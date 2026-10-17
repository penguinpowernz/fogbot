package chkrootkit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
)

const (
	SkillID   = 610
	SkillName = "chkrootkit"
)

const (
	defaultLogPath    = "/var/log/chkrootkit/log.today"
	defaultMaxScanAge = 48 * time.Hour

	// maxRead caps how much of the log is read
	maxRead = 16 << 20
)

var (
	// pollInterval is how often the log is checked for a new scan
	pollInterval = time.Minute

	// settle is how long the log must be unchanged before it is read
	settle = 30 * time.Second

	// procRoot is where running processes are listed; replaced in tests
	procRoot = "/proc"

	// scannerUID is who runs chkrootkit; replaced in tests
	scannerUID uint32 = 0
)

// settings are the parsed config
type settings struct {
	logPath        string
	alertInfected  bool
	alertWarning   bool
	repeatWarnings bool
	maxScanAge     time.Duration
}

func defaults() settings {
	return settings{
		logPath:       defaultLogPath,
		alertInfected: true,
		alertWarning:  true,
		maxScanAge:    defaultMaxScanAge,
	}
}

// Chkrootkit alerts on what chkrootkit's daily scans find, and on them
// stopping
type Chkrootkit struct {
	mu      sync.RWMutex
	enabled bool
	config  map[string]interface{}
	s       settings
}

// New creates a Chkrootkit with default config (used by daemon registry).
func New() *Chkrootkit {
	return &Chkrootkit{s: defaults()}
}

// NewFromConfig creates a Chkrootkit pre-populated from a SkillConfig (used by CLI enabler).
func NewFromConfig(cfg skills.SkillConfig) *Chkrootkit {
	c := New()
	if cfg.Config != nil {
		c.Configure(cfg.Config)
	}
	return c
}

func (c *Chkrootkit) ID() int      { return SkillID }
func (c *Chkrootkit) Name() string { return SkillName }
func (c *Chkrootkit) Description() string {
	return "Alert on chkrootkit's INFECTED and WARNING results, and on its daily scans stopping"
}
func (c *Chkrootkit) Why() string {
	return "chkrootkit looks for rootkits and malware with different checks from rkhunter. Its findings are only useful if someone reads them."
}
func (c *Chkrootkit) Requires() []string       { return []string{"chkrootkit"} }
func (c *Chkrootkit) Tags() []string           { return []string{"rootkit", "scanner"} }
func (c *Chkrootkit) DropIns() []skills.DropIn { return nil }
func (c *Chkrootkit) SetupHints() []string     { return nil }
func (c *Chkrootkit) DeduceCommands(cfg map[string]interface{}) ([]skills.SystemCommand, error) {
	return []skills.SystemCommand{}, nil
}
func (c *Chkrootkit) CheckSystemState() (bool, error) { return true, nil }

func (c *Chkrootkit) Enabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.enabled
}

func (c *Chkrootkit) SetEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = enabled
}

func (c *Chkrootkit) Config() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config
}

func (c *Chkrootkit) Configure(cfg map[string]interface{}) error {
	s := defaults()
	var errs []error
	get := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	var err error
	s.logPath, err = skills.ConfigString(cfg, "log_path", s.logPath)
	get(err)
	if !filepath.IsAbs(s.logPath) {
		errs = append(errs, fmt.Errorf("log_path %q must be absolute", s.logPath))
		s.logPath = defaultLogPath
	}
	s.alertInfected, err = skills.ConfigBool(cfg, "alert_on_infected", s.alertInfected)
	get(err)
	s.alertWarning, err = skills.ConfigBool(cfg, "alert_on_suspicious", s.alertWarning)
	get(err)
	s.repeatWarnings, err = skills.ConfigBool(cfg, "repeat_warnings", s.repeatWarnings)
	get(err)
	s.maxScanAge, err = skills.ConfigDuration(cfg, "max_scan_age", s.maxScanAge)
	get(err)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.config = cfg
	c.s = s
	return errors.Join(errs...)
}

// Watch checks chkrootkit's log every poll and reads it whenever a scan has
// rewritten it
func (c *Chkrootkit) Watch(ctx context.Context) (<-chan notifier.Alert, error) {
	c.mu.RLock()
	s := c.s
	c.mu.RUnlock()

	if _, err := os.Stat(filepath.Dir(s.logPath)); err != nil {
		return nil, fmt.Errorf("chkrootkit doesn't seem to be installed: %w", err)
	}

	now := time.Now()
	w := &watcher{s: s, report: &skills.ScanReport{
		SkillID:   SkillID,
		SkillName: SkillName,
		Scanner:   "chkrootkit",
		Location:  s.logPath,
		Options: skills.ReportOptions{
			Warnings:       s.alertWarning,
			Infections:     s.alertInfected,
			RepeatWarnings: s.repeatWarnings,
		},
		MaxAge:    s.maxScanAge,
		StaleHint: `check RUN_DAILY="true" in /etc/chkrootkit/chkrootkit.conf and that chkrootkit.timer is enabled`,
	}}
	w.report.Start(now)

	// The scan in the log already is the baseline: its warnings are known,
	// and only what the next scan adds to them is news
	seed := w.poll(now, true)
	if w.report.Scanned() {
		log.Printf("[chkrootkit] Read the last scan in %s; alerting on what later scans add", s.logPath)
	} else {
		log.Printf("[chkrootkit] No scan in %s yet; waiting for one", s.logPath)
	}

	alerts := make(chan notifier.Alert, 10)
	go w.loop(ctx, alerts, seed)
	return alerts, nil
}

// watcher holds the state of one Watch run
type watcher struct {
	s      settings
	report *skills.ScanReport
	// read identifies the log as last read
	read logID
	// readErr is the last error reading the log, logged once
	readErr string
}

// readFailed logs an error reading the log, unless it is the same as last
// poll's
func (w *watcher) readFailed(err error) {
	if errors.Is(err, os.ErrNotExist) || err.Error() == w.readErr {
		return
	}
	w.readErr = err.Error()
	log.Printf("[chkrootkit] Can't read %s: %v", w.s.logPath, err)
}

// logID tells one write of the log from another
type logID struct {
	ino   uint64
	size  int64
	mtime time.Time
}

func (w *watcher) loop(ctx context.Context, alerts chan<- notifier.Alert, pending []notifier.Alert) {
	defer close(alerts)

	tick := time.NewTicker(pollInterval)
	defer tick.Stop()

	for {
		for _, a := range pending {
			select {
			case alerts <- a:
			case <-ctx.Done():
				return
			}
		}

		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			pending = w.poll(now, false)
			if a, ok := w.report.CheckAge(now); ok {
				pending = append(pending, a)
			}
		}
	}
}

// poll reads the log if a scan has written it since it was last read, and
// returns the alerts for that scan. With seeding, the scan is only learnt,
// except for its infections.
func (w *watcher) poll(now time.Time, seeding bool) []notifier.Alert {
	info, err := os.Stat(w.s.logPath)
	if err != nil {
		w.readFailed(err)
		return nil
	}
	id := logID{size: info.Size(), mtime: info.ModTime()}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		id.ino = st.Ino
	}
	if id == w.read {
		return nil
	}

	// chkrootkit-daily writes the log as chkrootkit runs, and some checks
	// take minutes with nothing written: wait for chkrootkit to finish
	if now.Sub(id.mtime) < settle || running() {
		return nil
	}

	f, err := os.Open(w.s.logPath)
	if err != nil {
		w.readFailed(err)
		return nil
	}
	defer f.Close()
	w.readErr = ""
	data, _ := io.ReadAll(io.LimitReader(f, maxRead))
	w.read = id

	findings := parse(data)
	if seeding {
		return w.report.Seed(findings, id.mtime)
	}
	log.Printf("[chkrootkit] Scan finished with %d findings", len(findings))
	return w.report.Scan(findings, id.mtime)
}

// running reports whether chkrootkit, or Debian's chkrootkit-daily that runs
// it, is running as root. Anyone can start a process called chkrootkit, and
// fogbot would wait for it for ever.
func running() bool {
	dirs, err := os.ReadDir(procRoot)
	if err != nil {
		return false
	}
	for _, d := range dirs {
		if name := d.Name(); name[0] < '0' || name[0] > '9' {
			continue
		}
		info, err := d.Info()
		if err != nil {
			continue
		}
		if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != scannerUID {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join(procRoot, d.Name(), "cmdline"))
		if err != nil {
			continue
		}
		// Both are shell scripts, so may be the argument to a shell
		args := bytes.SplitN(cmdline, []byte{0}, 3)
		prog := filepath.Base(string(args[0]))
		switch prog {
		case "sh", "dash", "bash":
			if len(args) > 1 {
				prog = filepath.Base(string(args[1]))
			}
		}
		if prog == "chkrootkit" || prog == "chkrootkit-daily" {
			return true
		}
	}
	return false
}

var (
	// header starts a check's output: "Checking `sniffer'... WARNING" or
	// "Searching for Linux.Xor.DDoS... WARNING"
	header = regexp.MustCompile("^(?:Checking `([^']*)'|Searching for (.*?))(?:, it may take a while)?\\.\\.\\.\\s*(.*)$")

	// noise are lines that say nothing about the system: errors from the
	// tools chkrootkit runs, and interfaces the sniffer check found clean
	noise = []string{
		"RTNETLINK answers:",
		"not promisc and no packet sniffer sockets",
	}

	// clean are the endings of lines saying a check found nothing
	clean = []string{
		"not found", "not infected", "not tested", "nothing found",
		"nothing detected", "nothing deleted",
	}
)

// parse returns chkrootkit's findings. A check is a finding if anything it
// printed says INFECTED (an infection) or WARNING, Vulnerable, Possible,
// suspicious or hidden, or if it printed lines it doesn't print when it finds
// nothing; its lines are what it printed after its name.
//
// The output quotes file names, and chkrootkit prints them with printf %b,
// so anyone who can create a file in /tmp can put any line in it, including
// a check's name. The lines that follow then look like that check's output,
// but they are file names, which a clean check doesn't print: so they are
// still reported.
func parse(data []byte) []skills.Finding {
	var findings []skills.Finding
	var check string
	var lines []string
	unexpected := false

	flush := func() {
		f := classify(check, lines, unexpected)
		if f != nil {
			findings = append(findings, *f)
		}
		check, lines, unexpected = "", nil, false
	}

	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if m := header.FindStringSubmatch(l); m != nil {
			flush()
			check = m[1] + m[2]
			if m[3] != "" {
				lines = append(lines, m[3])
			}
			continue
		}
		if l == "" || isNoise(l) || strings.HasPrefix(l, "ROOTDIR is ") {
			continue
		}
		unexpected = unexpected || !isClean(l)
		lines = append(lines, l)
	}
	flush()
	return findings
}

func isNoise(l string) bool {
	for _, n := range noise {
		if strings.Contains(l, n) {
			return true
		}
	}
	return false
}

func isClean(l string) bool {
	for _, c := range clean {
		if strings.HasSuffix(l, c) {
			return true
		}
	}
	return false
}

// classify returns the finding for a check's output, or nil if it found
// nothing. unexpected is whether it printed lines a clean check doesn't.
func classify(check string, lines []string, unexpected bool) *skills.Finding {
	if check == "" {
		check = "chkrootkit"
	}
	f := skills.Finding{Check: check}
	flagged := unexpected
	seen := make(map[string]bool, len(lines))
	for _, l := range lines {
		if strings.Contains(l, "INFECTED") {
			f.Infected = true
		}
		lower := strings.ToLower(l)
		if strings.Contains(l, "WARNING") || strings.Contains(lower, "warning:") ||
			strings.Contains(l, "Vulnerable") || strings.Contains(l, "Possible") ||
			strings.Contains(lower, "suspicious") || strings.Contains(lower, "hidden") {
			flagged = true
		}
		// The bare WARNING result says nothing the lines after it don't
		if l == "WARNING" || seen[l] || isNoise(l) {
			continue
		}
		seen[l] = true
		f.Lines = append(f.Lines, l)
	}
	if !f.Infected && !flagged {
		return nil
	}
	return &f
}
