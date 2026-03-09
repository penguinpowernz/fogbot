package pkgmonitor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
)

const (
	SkillID   = 300
	SkillName = "pkg-monitor"
)

var (
	// dpkg.log patterns
	installPattern = regexp.MustCompile(`status installed (\S+):(\S+) (\S+)`)
	upgradePattern = regexp.MustCompile(`upgrade (\S+):(\S+) (\S+) (\S+)`)
	removePattern  = regexp.MustCompile(`remove (\S+):(\S+) (\S+)`)
)

// PkgMonitor watches dpkg.log for package changes
type PkgMonitor struct {
	mu      sync.RWMutex
	enabled bool
	config  map[string]interface{}
	logPath string
}

// New creates a new PkgMonitor skill
func New() *PkgMonitor {
	return &PkgMonitor{
		enabled: false,
		logPath: "/var/log/dpkg.log",
	}
}

func (p *PkgMonitor) ID() int      { return SkillID }
func (p *PkgMonitor) Name() string { return SkillName }
func (p *PkgMonitor) Description() string {
	return "Monitors /var/log/dpkg.log for package installs, removals, and upgrades"
}
func (p *PkgMonitor) Why() string {
	return "Unauthorized package installations can introduce backdoors or malware. Monitoring dpkg provides visibility into system changes."
}
func (p *PkgMonitor) Requires() []string { return []string{"dpkg.log"} }
func (p *PkgMonitor) Tags() []string     { return []string{"packages", "dpkg", "system-changes"} }
func (p *PkgMonitor) DropIns() []skills.DropIn { return nil }
func (p *PkgMonitor) Enabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.enabled
}

func (p *PkgMonitor) SetEnabled(enabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enabled = enabled
}

func (p *PkgMonitor) Config() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.config
}

func (p *PkgMonitor) Configure(cfg map[string]interface{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.config = cfg

	if path, ok := cfg["dpkg_log_path"].(string); ok {
		p.logPath = path
	}

	return nil
}

func (p *PkgMonitor) Watch(ctx context.Context) (<-chan notifier.Alert, error) {
	alertChan := make(chan notifier.Alert, 10)

	go p.watchLoop(ctx, alertChan)

	return alertChan, nil
}

func (p *PkgMonitor) watchLoop(ctx context.Context, alertChan chan<- notifier.Alert) {
	defer close(alertChan)

	file, err := os.Open(p.logPath)
	if err != nil {
		log.Printf("[pkg-monitor] Failed to open %s: %v", p.logPath, err)
		return
	}
	defer file.Close()

	// Seek to end
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		log.Printf("[pkg-monitor] Failed to seek to end: %v", err)
		return
	}

	reader := bufio.NewReader(file)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Printf("[pkg-monitor] Watching %s", p.logPath)

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					if err == io.EOF {
						break
					}
					log.Printf("[pkg-monitor] Read error: %v", err)
					return
				}

				p.processLine(line, alertChan)
			}
		}
	}
}

func (p *PkgMonitor) processLine(line string, alertChan chan<- notifier.Alert) {
	now := time.Now()

	// Check for package install
	if matches := installPattern.FindStringSubmatch(line); matches != nil {
		pkg := matches[1]
		arch := matches[2]
		version := matches[3]

		alertChan <- notifier.Alert{
			Severity:  notifier.SeverityMovement,
			SkillID:   SkillID,
			SkillName: SkillName,
			Title:     "Package Installed",
			Size:      "1 package",
			Activity:  fmt.Sprintf("Installed %s", pkg),
			Location:  "dpkg",
			Unit:      fmt.Sprintf("arch=%s version=%s", arch, version),
			Time:      now,
			Equipment: "dpkg",
		}
		return
	}

	// Check for package upgrade
	if matches := upgradePattern.FindStringSubmatch(line); matches != nil {
		pkg := matches[1]
		arch := matches[2]
		oldVer := matches[3]
		newVer := matches[4]

		alertChan <- notifier.Alert{
			Severity:  notifier.SeverityMovement,
			SkillID:   SkillID,
			SkillName: SkillName,
			Title:     "Package Upgraded",
			Size:      "1 package",
			Activity:  fmt.Sprintf("Upgraded %s", pkg),
			Location:  "dpkg",
			Unit:      fmt.Sprintf("arch=%s %s → %s", arch, oldVer, newVer),
			Time:      now,
			Equipment: "dpkg",
		}
		return
	}

	// Check for package removal
	if matches := removePattern.FindStringSubmatch(line); matches != nil {
		pkg := matches[1]
		arch := matches[2]
		version := matches[3]

		alertChan <- notifier.Alert{
			Severity:  notifier.SeverityMovement,
			SkillID:   SkillID,
			SkillName: SkillName,
			Title:     "Package Removed",
			Size:      "1 package",
			Activity:  fmt.Sprintf("Removed %s", pkg),
			Location:  "dpkg",
			Unit:      fmt.Sprintf("arch=%s version=%s", arch, version),
			Time:      now,
			Equipment: "dpkg",
		}
		return
	}
}




// DeduceCommands - stub for legacy skill
func (s *PkgMonitor) DeduceCommands(cfg map[string]interface{}) ([]skills.SystemCommand, error) {
	return []skills.SystemCommand{}, nil
}

// CheckSystemState - stub for legacy skill
func (s *PkgMonitor) CheckSystemState() (bool, error) {
	return true, nil
}
