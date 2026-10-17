package rkhunter

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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
)

const (
	SkillID   = 600
	SkillName = "rkhunter"
)

const (
	defaultLogPath    = "/var/log/rkhunter.log"
	defaultMaxScanAge = 48 * time.Hour

	// maxRead caps how much of the log is read in one poll
	maxRead = 16 << 20
)

var (
	// pollInterval is how often the log is read and the scan age checked
	pollInterval = time.Minute

	// binaryPath is where rkhunter is installed; replaced in tests
	binaryPath = "/usr/bin/rkhunter"
)

// settings are the parsed config
type settings struct {
	logPath        string
	alertWarning   bool
	alertInfection bool
	repeatWarnings bool
	maxScanAge     time.Duration
}

func defaults() settings {
	return settings{
		logPath:        defaultLogPath,
		alertWarning:   true,
		alertInfection: true,
		maxScanAge:     defaultMaxScanAge,
	}
}

// RKHunter alerts on what rkhunter's scans find, and on rkhunter not
// scanning
type RKHunter struct {
	mu      sync.RWMutex
	enabled bool
	config  map[string]interface{}
	s       settings
}

// New creates an RKHunter with default config (used by daemon registry).
func New() *RKHunter {
	return &RKHunter{s: defaults()}
}

// NewFromConfig creates an RKHunter pre-populated from a SkillConfig (used by CLI enabler).
func NewFromConfig(cfg skills.SkillConfig) *RKHunter {
	r := New()
	if cfg.Config != nil {
		r.Configure(cfg.Config)
	}
	return r
}

func (r *RKHunter) ID() int      { return SkillID }
func (r *RKHunter) Name() string { return SkillName }
func (r *RKHunter) Description() string {
	return "Alert on rkhunter's warnings and rootkit findings, and on its scans stopping"
}
func (r *RKHunter) Why() string {
	return "rkhunter checks system binaries against known-good hashes and looks for known rootkits. Its findings are only useful if someone reads them."
}
func (r *RKHunter) Requires() []string       { return []string{"rkhunter"} }
func (r *RKHunter) Tags() []string           { return []string{"rootkit", "scanner"} }
func (r *RKHunter) DropIns() []skills.DropIn { return nil }
func (r *RKHunter) SetupHints() []string     { return nil }
func (r *RKHunter) DeduceCommands(cfg map[string]interface{}) ([]skills.SystemCommand, error) {
	return []skills.SystemCommand{}, nil
}
func (r *RKHunter) CheckSystemState() (bool, error) { return true, nil }

func (r *RKHunter) Enabled() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.enabled
}

func (r *RKHunter) SetEnabled(enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = enabled
}

func (r *RKHunter) Config() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.config
}

func (r *RKHunter) Configure(cfg map[string]interface{}) error {
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
	s.alertWarning, err = skills.ConfigBool(cfg, "alert_on_warning", s.alertWarning)
	get(err)
	s.alertInfection, err = skills.ConfigBool(cfg, "alert_on_infection", s.alertInfection)
	get(err)
	s.repeatWarnings, err = skills.ConfigBool(cfg, "repeat_warnings", s.repeatWarnings)
	get(err)
	s.maxScanAge, err = skills.ConfigDuration(cfg, "max_scan_age", s.maxScanAge)
	get(err)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.config = cfg
	r.s = s
	return errors.Join(errs...)
}

// Watch reads rkhunter's log every poll, alerting on each scan that finishes
func (r *RKHunter) Watch(ctx context.Context) (<-chan notifier.Alert, error) {
	r.mu.RLock()
	s := r.s
	r.mu.RUnlock()

	_, logErr := os.Stat(s.logPath)
	_, binErr := os.Stat(binaryPath)
	if logErr != nil && binErr != nil {
		return nil, fmt.Errorf("rkhunter doesn't seem to be installed: neither %s nor %s exists", binaryPath, s.logPath)
	}

	now := time.Now()
	w := &watcher{s: s, report: newReport(s)}
	w.report.Start(now)

	// What is in the log already is the baseline: its last scan's warnings
	// are known, and only what the next scan adds to them is news
	seed := w.poll(now, true)
	if w.report.Scanned() {
		log.Printf("[rkhunter] Read the last scan in %s; alerting on what later scans add", s.logPath)
	} else {
		log.Printf("[rkhunter] No finished scan in %s yet; waiting for one", s.logPath)
	}

	alerts := make(chan notifier.Alert, 10)
	go w.loop(ctx, alerts, seed)
	return alerts, nil
}

func newReport(s settings) *skills.ScanReport {
	return &skills.ScanReport{
		SkillID:   SkillID,
		SkillName: SkillName,
		Scanner:   "rkhunter",
		Location:  s.logPath,
		Options: skills.ReportOptions{
			Warnings:       s.alertWarning,
			Infections:     s.alertInfection,
			RepeatWarnings: s.repeatWarnings,
		},
		MaxAge:    s.maxScanAge,
		StaleHint: `check CRON_DAILY_RUN="true" in /etc/default/rkhunter, and that the machine is on AC power at cron.daily time`,
	}
}

// watcher holds the state of one Watch run
type watcher struct {
	s settings

	// The log is read from offset in the file with inode ino, whose first
	// line was first: rkhunter rewrites its log on each run unless told to
	// append, and either way the log may be rotated
	ino    uint64
	offset int64
	first  string
	rest   []byte
	p      parser

	report *skills.ScanReport
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
	log.Printf("[rkhunter] Can't read %s: %v", w.s.logPath, err)
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

// poll reads what was added to the log since the last poll, and returns
// alerts for the scans that finished in it. With seeding, the scans are
// only learnt, except for infections in the last one.
func (w *watcher) poll(now time.Time, seeding bool) []notifier.Alert {
	f, err := os.Open(w.s.logPath)
	if err != nil {
		w.readFailed(err)
		return nil
	}
	defer f.Close()
	w.readErr = ""

	info, err := f.Stat()
	if err != nil {
		return nil
	}
	var ino uint64
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		ino = st.Ino
	}
	first := firstLine(f)
	if ino != w.ino || info.Size() < w.offset || first != w.first {
		// A new log: rewritten, truncated or rotated
		w.ino, w.offset, w.first, w.rest = ino, 0, first, nil
		w.p = parser{}
	}
	if _, err := f.Seek(w.offset, io.SeekStart); err != nil {
		return nil
	}

	// A log appended to for years is read whole when seeding; after that
	// a poll reads at most maxRead, and the next one carries on
	var done []*scan
	for {
		data, _ := io.ReadAll(io.LimitReader(f, maxRead))
		w.offset += int64(len(data))
		for _, s := range w.lines(data) {
			if seeding {
				done = []*scan{s}
			} else {
				done = append(done, s)
			}
		}
		if !seeding || len(data) < maxRead {
			break
		}
	}

	if seeding {
		if len(done) == 0 {
			return nil
		}
		return w.report.Seed(done[0].findings, info.ModTime())
	}

	var out []notifier.Alert
	for _, s := range done {
		log.Printf("[rkhunter] Scan finished with %d findings", len(s.findings))
		out = append(out, w.report.Scan(s.findings, now)...)
	}
	return out
}

// lines parses the complete lines in data, after what was left over from the
// last read, and returns the runs they finish
func (w *watcher) lines(data []byte) []*scan {
	buf := append(w.rest, data...)
	end := bytes.LastIndexByte(buf, '\n')
	if end < 0 {
		// No log line is this long: don't hold on to it
		if len(buf) > maxRead {
			buf = nil
		}
		w.rest = buf
		return nil
	}
	w.rest = append([]byte(nil), buf[end+1:]...)

	var done []*scan
	for _, line := range strings.Split(string(buf[:end]), "\n") {
		if s := w.p.line(line); s != nil {
			done = append(done, s)
		}
	}
	return done
}

// firstLine reads the start of the log, which says when its first run began
func firstLine(f *os.File) string {
	buf := make([]byte, 256)
	n, _ := f.ReadAt(buf, 0)
	line, _, _ := bytes.Cut(buf[:n], []byte("\n"))
	return string(line)
}

// logLine matches a line of rkhunter's log: "[03:17:02] message". The
// message keeps its indent, which marks a continuation line.
var logLine = regexp.MustCompile(`^\[\s*\d\d:\d\d:\d\d\s*\] ?(.*)$`)

// possibleRootkits is the summary line counting rootkit check failures
var possibleRootkits = regexp.MustCompile(`^Possible rootkits:\s*(\d+)`)

// scan is one rkhunter run read from the log
type scan struct {
	// checks is whether it ran the checks; --update and --versioncheck
	// runs log too, with nothing to report
	checks   bool
	findings []skills.Finding
	rootkits int
}

// parser turns log lines into runs
type parser struct {
	run *scan
	// open is the index of the warning taking continuation lines, or -1
	open int
}

// line takes one log line, returning the run it finishes, if any
func (p *parser) line(l string) *scan {
	m := logLine.FindStringSubmatch(strings.TrimRight(l, "\r"))
	if m == nil {
		return nil
	}
	msg := m[1]
	text := strings.TrimSpace(msg)

	// rkhunter logs some file names as they are, so a file named with a
	// newline and a timestamp can forge a log line. A forged start or end
	// mustn't lose the scan's findings: a scan interrupted by a start is
	// reported as it stands, and a warning outside any run starts one.
	if strings.Contains(text, "Running Rootkit Hunter version") {
		done := p.run
		p.run, p.open = &scan{}, -1
		if done != nil && done.checks {
			done.finish()
			return done
		}
		return nil
	}
	if p.run == nil {
		if !strings.HasPrefix(msg, "Warning: ") {
			return nil
		}
		p.run, p.open = &scan{checks: true}, -1
	}

	// A warning's details are indented by at least the width of "Warning: ";
	// check results are indented less, and end the warning
	indent := len(msg) - len(strings.TrimLeft(msg, " \t"))
	if indent >= len("Warning: ") && text != "" && p.open >= 0 {
		f := &p.run.findings[p.open]
		f.Lines = append(f.Lines, text)
		return nil
	}
	p.open = -1

	switch {
	case strings.HasPrefix(msg, "Warning: "):
		check := strings.TrimSpace(strings.TrimPrefix(msg, "Warning: "))
		p.run.findings = append(p.run.findings, skills.Finding{Check: check})
		p.open = len(p.run.findings) - 1
	case strings.Contains(text, "Starting test name"), strings.Contains(text, "System checks summary"):
		p.run.checks = true
	case strings.HasPrefix(text, "Info: End date is"):
		s := p.run
		p.run = nil
		if !s.checks {
			return nil
		}
		s.finish()
		return s
	default:
		if sm := possibleRootkits.FindStringSubmatch(text); sm != nil {
			p.run.rootkits, _ = strconv.Atoi(sm[1])
		}
	}
	return nil
}

// finish marks warnings that name a rootkit as infections, and makes sure a
// scan counting possible rootkits reports one
func (s *scan) finish() {
	infected := false
	for i := range s.findings {
		f := &s.findings[i]
		text := strings.ToLower(f.Check + "\n" + strings.Join(f.Lines, "\n"))
		f.Infected = strings.Contains(text, "rootkit")
		infected = infected || f.Infected
	}
	if s.rootkits > 0 && !infected {
		s.findings = append(s.findings, skills.Finding{
			Check:    fmt.Sprintf("rkhunter counted %d possible rootkits", s.rootkits),
			Infected: true,
		})
	}
}
