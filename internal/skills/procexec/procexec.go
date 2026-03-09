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
	seenProcs       map[int]bool // track PIDs we've already alerted on
}

// New creates a new ProcExec skill
func New() *ProcExec {
	return &ProcExec{
		enabled:         false,
		suspiciousPaths: []string{"/tmp", "/dev/shm", "/run/user"},
		pollInterval:    5 * time.Second,
		seenProcs:       make(map[int]bool),
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
func (p *ProcExec) DropIns() []skills.DropIn { return nil }
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

	if intervalStr, ok := cfg["poll_interval"].(string); ok {
		if d, err := time.ParseDuration(intervalStr); err == nil {
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

	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	log.Printf("[proc-exec] Watching /proc for suspicious executables (interval: %v)", p.pollInterval)

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			p.scanProc(alertChan)
			p.cleanupSeenProcs()
		}
	}
}

func (p *ProcExec) scanProc(alertChan chan<- notifier.Alert) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		log.Printf("[proc-exec] Failed to read /proc: %v", err)
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

		// Skip if we've already alerted on this PID
		p.mu.RLock()
		seen := p.seenProcs[pid]
		p.mu.RUnlock()

		if seen {
			continue
		}

		// Read the exe symlink to get the executable path
		exePath, err := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		if err != nil {
			continue
		}

		// Check if exe is in a suspicious location
		for _, suspPath := range p.suspiciousPaths {
			if strings.HasPrefix(exePath, suspPath) {
				// Mark as seen
				p.mu.Lock()
				p.seenProcs[pid] = true
				p.mu.Unlock()

				// Read cmdline for additional context
				cmdlineBytes, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
				cmdline := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")

				// Read comm (process name)
				commBytes, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
				comm := strings.TrimSpace(string(commBytes))

				alertChan <- notifier.Alert{
					Severity:    notifier.SeverityContact,
					SkillID:     SkillID,
					SkillName:   SkillName,
					Title:       "Suspicious Process Execution",
					Size:        "1 process",
					Activity:    fmt.Sprintf("Executable running from %s", suspPath),
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

				break
			}
		}
	}
}

func (p *ProcExec) cleanupSeenProcs() {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Remove PIDs that no longer exist
	for pid := range p.seenProcs {
		if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid))); os.IsNotExist(err) {
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
