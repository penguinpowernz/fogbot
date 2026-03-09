package logfreshness

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
)

const (
	SkillID   = 400
	SkillName = "log-freshness"
)

// LogFreshness monitors log files for staleness (DEADMAN check)
type LogFreshness struct {
	mu            sync.RWMutex
	enabled       bool
	config        map[string]interface{}
	watchedLogs   map[string]time.Duration // path -> max age before alert
	checkInterval time.Duration
}

// New creates a new LogFreshness skill
func New() *LogFreshness {
	return &LogFreshness{
		enabled: false,
		watchedLogs: map[string]time.Duration{
			"/var/log/syslog":   10 * time.Minute,
			"/var/log/auth.log": 30 * time.Minute,
		},
		checkInterval: 1 * time.Minute,
	}
}

func (l *LogFreshness) ID() int      { return SkillID }
func (l *LogFreshness) Name() string { return SkillName }
func (l *LogFreshness) Description() string {
	return "[DEADMAN] Alerts if configured log files not written within N minutes"
}
func (l *LogFreshness) Why() string {
	return "Stale logs may indicate logging infrastructure failure, which could mask attacker activity."
}
func (l *LogFreshness) Requires() []string { return []string{"inotify"} }
func (l *LogFreshness) Tags() []string     { return []string{"deadman", "logging", "health"} }
func (l *LogFreshness) DropIns() []skills.DropIn { return nil }
func (l *LogFreshness) Enabled() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.enabled
}

func (l *LogFreshness) SetEnabled(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enabled = enabled
}

func (l *LogFreshness) Config() map[string]interface{} {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.config
}

func (l *LogFreshness) Configure(cfg map[string]interface{}) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.config = cfg

	if logs, ok := cfg["watched_logs"].(map[string]interface{}); ok {
		l.watchedLogs = make(map[string]time.Duration)
		for path, maxAgeStr := range logs {
			if ageStr, ok := maxAgeStr.(string); ok {
				if d, err := time.ParseDuration(ageStr); err == nil {
					l.watchedLogs[path] = d
				}
			}
		}
	}

	if intervalStr, ok := cfg["check_interval"].(string); ok {
		if d, err := time.ParseDuration(intervalStr); err == nil {
			l.checkInterval = d
		}
	}

	return nil
}

func (l *LogFreshness) Watch(ctx context.Context) (<-chan notifier.Alert, error) {
	alertChan := make(chan notifier.Alert, 10)

	go l.watchLoop(ctx, alertChan)

	return alertChan, nil
}

func (l *LogFreshness) watchLoop(ctx context.Context, alertChan chan<- notifier.Alert) {
	defer close(alertChan)

	ticker := time.NewTicker(l.checkInterval)
	defer ticker.Stop()

	log.Printf("[log-freshness] Monitoring %d log files for staleness", len(l.watchedLogs))

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			l.checkLogs(alertChan)
		}
	}
}

func (l *LogFreshness) checkLogs(alertChan chan<- notifier.Alert) {
	now := time.Now()

	l.mu.RLock()
	defer l.mu.RUnlock()

	for logPath, maxAge := range l.watchedLogs {
		info, err := os.Stat(logPath)
		if err != nil {
			if os.IsNotExist(err) {
				alertChan <- notifier.Alert{
					Severity:    notifier.SeverityContact,
					SkillID:     SkillID,
					SkillName:   SkillName,
					Title:       "[DEADMAN] Log File Missing",
					Size:        "1 file",
					Activity:    "Expected log file does not exist",
					Location:    logPath,
					Unit:        "filesystem",
					Time:        now,
					Equipment:   "stat",
					Acknowledge: true,
				}
			}
			continue
		}

		age := now.Sub(info.ModTime())
		if age > maxAge {
			alertChan <- notifier.Alert{
				Severity:    notifier.SeverityContact,
				SkillID:     SkillID,
				SkillName:   SkillName,
				Title:       "[DEADMAN] Stale Log File",
				Size:        "1 file",
				Activity:    fmt.Sprintf("Log not written for %v (max: %v)", age.Round(time.Second), maxAge),
				Location:    logPath,
				Unit:        fmt.Sprintf("last modified: %s", info.ModTime().Format(time.RFC3339)),
				Time:        now,
				Equipment:   "mtime",
				Acknowledge: true,
			}
		}
	}
}




// DeduceCommands - stub for legacy skill
func (s *LogFreshness) DeduceCommands(cfg map[string]interface{}) ([]skills.SystemCommand, error) {
	return []skills.SystemCommand{}, nil
}

// CheckSystemState - stub for legacy skill
func (s *LogFreshness) CheckSystemState() (bool, error) {
	return true, nil
}
