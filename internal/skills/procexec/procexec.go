package procexec

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
)

const (
	SkillID   = 210
	SkillName = "proc-exec"
)

// ProcExec watches for suspicious process execution patterns
type ProcExec struct {
	mu              sync.RWMutex
	enabled         bool
	config          map[string]interface{}
	suspiciousPaths []string
	pollInterval    time.Duration
	detectMemfd     bool
	seenProcs       map[int]bool // track PIDs we've already alerted on

	// procDir is where processes are looked up; execEvents subscribes to exec
	// notifications. Both are fields so tests can replace them.
	procDir    string
	execEvents func(ctx context.Context) (<-chan int, error)
}

// New creates a new ProcExec skill
func New() *ProcExec {
	return &ProcExec{
		enabled:         false,
		suspiciousPaths: []string{"/tmp", "/dev/shm", "/run/user"},
		pollInterval:    5 * time.Second,
		detectMemfd:     true,
		seenProcs:       make(map[int]bool),
		procDir:         "/proc",
		execEvents:      listenExecs,
	}
}

func (p *ProcExec) ID() int      { return SkillID }
func (p *ProcExec) Name() string { return SkillName }
func (p *ProcExec) Description() string {
	return "Watches /proc for executables in suspicious locations and process hiding"
}
func (p *ProcExec) Why() string {
	return "Executables in /tmp or /dev/shm are common malware droppers. Process hiding indicates rootkit activity."
}
func (p *ProcExec) Requires() []string { return []string{"/proc"} }
func (p *ProcExec) Tags() []string     { return []string{"process", "execution", "malware"} }
func (p *ProcExec) DropIns() []skills.DropIn    { return nil }
func (p *ProcExec) SetupHints() []string        { return nil }
func (p *ProcExec) Enabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.enabled
}

func (p *ProcExec) SetEnabled(enabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enabled = enabled
}

func (p *ProcExec) Config() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.config
}

func (p *ProcExec) Configure(cfg map[string]interface{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.config = cfg

	if paths, ok := cfg["suspicious_paths"].([]interface{}); ok {
		p.suspiciousPaths = make([]string, 0, len(paths))
		for _, path := range paths {
			if s, ok := path.(string); ok {
				p.suspiciousPaths = append(p.suspiciousPaths, s)
			}
		}
	}

	p.detectMemfd = true
	if v, ok := cfg["detect_memfd_exec"].(bool); ok {
		p.detectMemfd = v
	}

	if intervalStr, ok := cfg["poll_interval"].(string); ok {
		if d, err := time.ParseDuration(intervalStr); err == nil && d > 0 { // time.NewTicker panics on d <= 0
			p.pollInterval = d
		}
	}

	return nil
}

func (p *ProcExec) Watch(ctx context.Context) (<-chan notifier.Alert, error) {
	alertChan := make(chan notifier.Alert, 10)

	go p.watchLoop(ctx, alertChan)

	return alertChan, nil
}

func (p *ProcExec) watchLoop(ctx context.Context, alertChan chan<- notifier.Alert) {
	defer close(alertChan)

	// Exec events catch processes that would come and go between polls. The
	// polls still run: they see what was already running when fogbot started,
	// and anything whose events were missed.
	var execs <-chan int
	if ch, err := p.execEvents(ctx); err != nil {
		log.Printf("[proc-exec] Exec events unavailable, polling only: %v", err)
	} else {
		execs = ch
	}

	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	log.Printf("[proc-exec] Watching %s for suspicious executables (interval: %v, exec events: %v)", p.procDir, p.pollInterval, execs != nil)
	p.scanProc(alertChan)

	for {
		select {
		case <-ctx.Done():
			return

		case pid, ok := <-execs:
			if !ok {
				log.Printf("[proc-exec] Exec events stopped, polling only")
				execs = nil
				continue
			}
			// A new program in this process: judge it afresh
			p.mu.Lock()
			delete(p.seenProcs, pid)
			p.mu.Unlock()
			p.checkPID(pid, alertChan)

		case <-ticker.C:
			p.scanProc(alertChan)
			p.cleanupSeenProcs()
		}
	}
}

func (p *ProcExec) scanProc(alertChan chan<- notifier.Alert) {
	entries, err := os.ReadDir(p.procDir)
	if err != nil {
		log.Printf("[proc-exec] Failed to read %s: %v", p.procDir, err)
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if this is a PID directory
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		p.checkPID(pid, alertChan)
	}
}

// checkPID alerts if the process is running an executable from a suspicious
// place, unless it was already reported
func (p *ProcExec) checkPID(pid int, alertChan chan<- notifier.Alert) {
	p.mu.RLock()
	seen := p.seenProcs[pid]
	suspiciousPaths, detectMemfd := p.suspiciousPaths, p.detectMemfd
	p.mu.RUnlock()
	if seen {
		return
	}

	dir := filepath.Join(p.procDir, strconv.Itoa(pid))

	// Read the exe symlink to get the executable path
	exePath, err := os.Readlink(filepath.Join(dir, "exe"))
	if err != nil {
		return
	}

	var title, activity string
	if detectMemfd && strings.HasPrefix(exePath, "/memfd:") {
		// memfd_create gives an anonymous file that never touches the disk;
		// executing one is how fileless malware runs a payload
		title = "Fileless Process Execution"
		activity = "Executable running from an in-memory file (memfd)"
	} else {
		for _, suspPath := range suspiciousPaths {
			if underPath(exePath, suspPath) {
				title = "Suspicious Process Execution"
				activity = fmt.Sprintf("Executable running from %s", suspPath)
				break
			}
		}
	}
	if title == "" {
		return
	}

	// Mark as seen
	p.mu.Lock()
	p.seenProcs[pid] = true
	p.mu.Unlock()

	// Read cmdline for additional context
	cmdlineBytes, _ := os.ReadFile(filepath.Join(dir, "cmdline"))
	cmdline := strings.TrimSpace(strings.ReplaceAll(string(cmdlineBytes), "\x00", " "))

	// Read comm (process name)
	commBytes, _ := os.ReadFile(filepath.Join(dir, "comm"))
	comm := strings.TrimSpace(string(commBytes))

	alertChan <- notifier.Alert{
		Severity:    notifier.SeverityContact,
		SkillID:     SkillID,
		SkillName:   SkillName,
		Title:       title,
		Size:        "1 process",
		Activity:    activity,
		Location:    exePath,
		Unit:        fmt.Sprintf("pid=%d (%s)", pid, comm),
		Time:        time.Now(),
		Equipment:   cmdline,
		Acknowledge: true,
		Metadata: map[string]string{
			"pid":     strconv.Itoa(pid),
			"exe":     exePath,
			"cmdline": cmdline,
		},
	}
}

// underPath reports whether exe is dir or inside it. A plain prefix match
// would also flag /tmpfiles/x for /tmp.
func underPath(exe, dir string) bool {
	dir = strings.TrimSuffix(dir, "/")
	if dir == "" {
		return strings.HasPrefix(exe, "/")
	}
	return exe == dir || strings.HasPrefix(exe, dir+"/")
}

func (p *ProcExec) cleanupSeenProcs() {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Remove PIDs that no longer exist
	for pid := range p.seenProcs {
		if _, err := os.Stat(filepath.Join(p.procDir, strconv.Itoa(pid))); os.IsNotExist(err) {
			delete(p.seenProcs, pid)
		}
	}
}




// DeduceCommands - stub for legacy skill
func (s *ProcExec) DeduceCommands(cfg map[string]interface{}) ([]skills.SystemCommand, error) {
	return []skills.SystemCommand{}, nil
}

// CheckSystemState - stub for legacy skill
func (s *ProcExec) CheckSystemState() (bool, error) {
	return true, nil
}
