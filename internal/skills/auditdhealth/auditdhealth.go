package auditdhealth

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
)

const (
	SkillID   = 420
	SkillName = "auditd-health"
)

// AuditdHealth monitors auditd process and log freshness (DEADMAN check)
type AuditdHealth struct {
	mu              sync.RWMutex
	enabled         bool
	config          map[string]interface{}
	checkInterval   time.Duration
	auditLogPath    string
	maxLogAge       time.Duration
}

// New creates a new AuditdHealth skill
func New() *AuditdHealth {
	return &AuditdHealth{
		enabled:       false,
		checkInterval: 1 * time.Minute,
		auditLogPath:  "/var/log/audit/audit.log",
		maxLogAge:     5 * time.Minute,
	}
}

func (a *AuditdHealth) ID() int      { return SkillID }
func (a *AuditdHealth) Name() string { return SkillName }
func (a *AuditdHealth) Description() string {
	return "[DEADMAN] Verifies auditd process is running and logs are being written"
}
func (a *AuditdHealth) Why() string {
	return "auditd provides critical security logging. If it stops, we lose visibility into system activity."
}
func (a *AuditdHealth) Requires() []string { return []string{"auditd"} }
func (a *AuditdHealth) Tags() []string     { return []string{"deadman", "auditd", "health"} }
func (a *AuditdHealth) DropIns() []skills.DropIn { return nil }
func (a *AuditdHealth) Enabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *AuditdHealth) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *AuditdHealth) Config() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.config
}

func (a *AuditdHealth) Configure(cfg map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.config = cfg

	if intervalStr, ok := cfg["check_interval"].(string); ok {
		if d, err := time.ParseDuration(intervalStr); err == nil {
			a.checkInterval = d
		}
	}

	if path, ok := cfg["audit_log_path"].(string); ok {
		a.auditLogPath = path
	}

	if maxAgeStr, ok := cfg["max_log_age"].(string); ok {
		if d, err := time.ParseDuration(maxAgeStr); err == nil {
			a.maxLogAge = d
		}
	}

	return nil
}

func (a *AuditdHealth) Watch(ctx context.Context) (<-chan notifier.Alert, error) {
	alertChan := make(chan notifier.Alert, 10)

	go a.watchLoop(ctx, alertChan)

	return alertChan, nil
}

func (a *AuditdHealth) watchLoop(ctx context.Context, alertChan chan<- notifier.Alert) {
	defer close(alertChan)

	ticker := time.NewTicker(a.checkInterval)
	defer ticker.Stop()

	log.Printf("[auditd-health] Monitoring auditd health")

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			a.checkHealth(alertChan)
		}
	}
}

func (a *AuditdHealth) checkHealth(alertChan chan<- notifier.Alert) {
	now := time.Now()

	// Check if auditd service is running
	cmd := exec.Command("systemctl", "is-active", "auditd")
	output, err := cmd.Output()
	status := strings.TrimSpace(string(output))

	if err != nil || status != "active" {
		alertChan <- notifier.Alert{
			Severity:    notifier.SeverityContact,
			SkillID:     SkillID,
			SkillName:   SkillName,
			Title:       "[DEADMAN] auditd Stopped",
			Size:        "1 service",
			Activity:    "auditd service is not active",
			Location:    "systemd",
			Unit:        fmt.Sprintf("status=%s", status),
			Time:        now,
			Equipment:   "systemctl",
			Acknowledge: true,
		}
		return
	}

	// Check if audit log is being written
	a.mu.RLock()
	logPath := a.auditLogPath
	maxAge := a.maxLogAge
	a.mu.RUnlock()

	info, err := os.Stat(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			alertChan <- notifier.Alert{
				Severity:    notifier.SeverityContact,
				SkillID:     SkillID,
				SkillName:   SkillName,
				Title:       "[DEADMAN] audit.log Missing",
				Size:        "1 file",
				Activity:    "audit.log file does not exist",
				Location:    logPath,
				Unit:        "filesystem",
				Time:        now,
				Equipment:   "stat",
				Acknowledge: true,
			}
		}
		return
	}

	age := now.Sub(info.ModTime())
	if age > maxAge {
		alertChan <- notifier.Alert{
			Severity:    notifier.SeverityContact,
			SkillID:     SkillID,
			SkillName:   SkillName,
			Title:       "[DEADMAN] Stale audit.log",
			Size:        "1 file",
			Activity:    fmt.Sprintf("audit.log not written for %v (max: %v)", age.Round(time.Second), maxAge),
			Location:    logPath,
			Unit:        fmt.Sprintf("last modified: %s", info.ModTime().Format(time.RFC3339)),
			Time:        now,
			Equipment:   "mtime",
			Acknowledge: true,
		}
	}
}




// DeduceCommands - stub for legacy skill
func (s *AuditdHealth) DeduceCommands(cfg map[string]interface{}) ([]skills.SystemCommand, error) {
	return []skills.SystemCommand{}, nil
}

// CheckSystemState - stub for legacy skill
func (s *AuditdHealth) CheckSystemState() (bool, error) {
	return true, nil
}
