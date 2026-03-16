package dirwatch

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/penguinpowernz/fogbot/internal/auditlog"
	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
)

const (
	SkillID   = 540
	SkillName = "dir-watch"
)

// DirWatch monitors configured directories using auditd
type DirWatch struct {
	mu         sync.RWMutex
	enabled    bool
	config     map[string]interface{}
	watchPaths []string
	recursive  bool
	globFilter string
	whitelist  map[string]bool
}

// New creates a DirWatch with default config (used by daemon registry).
func New() *DirWatch {
	return &DirWatch{
		enabled:    false,
		watchPaths: []string{"/usr/local/bin/", "/etc/cron.d/", "/root/"},
		whitelist:  make(map[string]bool),
	}
}

// NewFromConfig creates a DirWatch pre-populated from a SkillConfig (used by CLI enabler).
func NewFromConfig(cfg skills.SkillConfig) *DirWatch {
	d := New()
	if cfg.Config != nil {
		d.applyConfig(cfg.Config)
	}
	return d
}

func (d *DirWatch) applyConfig(cfg map[string]interface{}) {
	if paths, ok := cfg["watch_paths"].([]interface{}); ok {
		d.watchPaths = make([]string, 0, len(paths))
		for _, p := range paths {
			if s, ok := p.(string); ok {
				d.watchPaths = append(d.watchPaths, s)
			}
		}
	}

	if recursive, ok := cfg["recursive"].(bool); ok {
		d.recursive = recursive
	}

	if glob, ok := cfg["glob_filter"].(string); ok {
		d.globFilter = glob
	}

	if wl, ok := cfg["whitelist"].([]interface{}); ok {
		d.whitelist = make(map[string]bool, len(wl))
		for _, entry := range wl {
			if s, ok := entry.(string); ok {
				d.whitelist[s] = true
			}
		}
	}
}

func (d *DirWatch) ID() int      { return SkillID }
func (d *DirWatch) Name() string { return SkillName }
func (d *DirWatch) Description() string {
	return "Alert on new files/directories added to watched folders using auditd"
}
func (d *DirWatch) Why() string {
	return "New files in sensitive directories outside maintenance windows indicate delivery or persistence activity. Using auditd provides user/process context that inotify cannot."
}
func (d *DirWatch) Requires() []string        { return []string{"auditd", "root"} }
func (d *DirWatch) Tags() []string            { return []string{"filesystem", "persistence", "delivery", "auditd"} }
func (d *DirWatch) DropIns() []skills.DropIn  { return nil }

func (d *DirWatch) Enabled() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.enabled
}

func (d *DirWatch) SetEnabled(enabled bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.enabled = enabled
}

func (d *DirWatch) Config() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.config
}

func (d *DirWatch) Configure(cfg map[string]interface{}) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	log.Printf("[dir-watch] Configure called with config: %+v", cfg)
	d.config = cfg
	d.applyConfig(cfg)
	log.Printf("[dir-watch] After applyConfig: watch_paths=%v, recursive=%v, glob_filter=%s, whitelist=%v",
		d.watchPaths, d.recursive, d.globFilter, d.whitelist)
	return nil
}

// generateRuleKey creates an audit rule key based on skill ID
func (d *DirWatch) generateRuleKey() string {
	// Use fb-dir-<skillID> format (e.g., fb-dir-540)
	return fmt.Sprintf("fb-dir-%d", SkillID)
}

// DeduceCommands generates auditctl commands from the declarative config
func (d *DirWatch) DeduceCommands(cfg map[string]interface{}) ([]skills.SystemCommand, error) {
	commands := []skills.SystemCommand{}

	// Extract watch paths from config
	var watchPaths []string
	if paths, ok := cfg["watch_paths"].([]interface{}); ok {
		for _, p := range paths {
			if s, ok := p.(string); ok {
				watchPaths = append(watchPaths, s)
			}
		}
	}

	if len(watchPaths) == 0 {
		return nil, fmt.Errorf("no watch_paths configured")
	}

	// Generate non-obvious rule key
	ruleKey := d.generateRuleKey()

	// Build auditctl commands for each path
	// Use -p wa to watch for write and attribute changes (create, rename, chmod, etc.)
	for _, path := range watchPaths {
		cmd := fmt.Sprintf("auditctl -w %s -p wa -k %s", path, ruleKey)

		commands = append(commands, skills.SystemCommand{
			Command:     cmd,
			Description: fmt.Sprintf("Monitor %s for file creation/modification", path),
			Metadata: map[string]string{
				"rule_key": ruleKey,
				"path":     path,
				"perms":    "wa",
			},
		})
	}

	return commands, nil
}

// CheckSystemState verifies if auditd rules are already configured
func (d *DirWatch) CheckSystemState() (bool, error) {
	// Get current audit rules
	cmd := exec.Command("auditctl", "-l")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to check auditd rules: %w (output: %s)", err, string(output))
	}

	rulesOutput := string(output)

	// Generate the rule key we expect to find
	ruleKey := d.generateRuleKey()

	// Get watch paths from config
	d.mu.RLock()
	watchPaths := make([]string, len(d.watchPaths))
	copy(watchPaths, d.watchPaths)
	d.mu.RUnlock()

	// Check if all expected paths are monitored with our rule key
	// Each rule should be on its own line
	for _, path := range watchPaths {
		// Look for lines like: -w /usr/local/bin/ -p wa -k fb-dir-540
		// Match the exact rule pattern to avoid false positives
		rulePattern := fmt.Sprintf("-w %s -p wa -k %s", path, ruleKey)
		if !strings.Contains(rulesOutput, rulePattern) {
			return false, nil
		}
	}

	return true, nil
}

// Watch monitors audit logs for file creation/modification events
func (d *DirWatch) Watch(ctx context.Context) (<-chan notifier.Alert, error) {
	log.Printf("[dir-watch] Watch() called - starting auditd watcher")

	alerts := make(chan notifier.Alert, 10)

	// Get the shared global audit tailer
	tailer, err := auditlog.GetGlobalTailer()
	if err != nil {
		return nil, fmt.Errorf("failed to get audit tailer: %w", err)
	}

	// Start the tailer (safe to call multiple times)
	if err := auditlog.StartGlobalTailer(); err != nil {
		return nil, fmt.Errorf("failed to start audit tailer: %w", err)
	}

	ruleKey := d.generateRuleKey()
	auditEvents := make(chan auditlog.Event, 100)

	// Subscribe to our rule key
	tailer.Subscribe(ruleKey, auditEvents)

	log.Printf("[dir-watch] Subscribed to audit events with key: %s", ruleKey)

	go func() {
		defer close(alerts)
		defer tailer.Unsubscribe(ruleKey, auditEvents)

		// Track recently seen events to avoid duplicates (audit logs are verbose)
		seen := make(map[string]time.Time)
		cleanupTicker := time.NewTicker(1 * time.Minute)
		defer cleanupTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return

			case <-cleanupTicker.C:
				// Clean up old entries from seen map
				cutoff := time.Now().Add(-2 * time.Minute)
				for k, t := range seen {
					if t.Before(cutoff) {
						delete(seen, k)
					}
				}

			case event, ok := <-auditEvents:
				if !ok {
					return
				}

				log.Printf("[dir-watch] Received audit event: type=%s, name=%s, uid=%s, comm=%s, exe=%s",
					event.RecordType, event.Name, event.UID, event.Comm, event.Exe)

				// Process the event
				d.handleAuditEvent(event, alerts, seen)
			}
		}
	}()

	return alerts, nil
}

func (d *DirWatch) handleAuditEvent(event auditlog.Event, alerts chan<- notifier.Alert, seen map[string]time.Time) {
	// Extract the file path and name
	path := event.Path
	if path == "" && event.Name != "" {
		path = event.Name
	}

	if path == "" {
		log.Printf("[dir-watch] Skipping event with no path/name")
		return
	}

	name := filepath.Base(path)

	// Check whitelist
	d.mu.RLock()
	whitelisted := d.whitelist[name]
	globFilter := d.globFilter
	d.mu.RUnlock()

	if whitelisted {
		log.Printf("[dir-watch] Ignoring whitelisted file: %s", name)
		return
	}

	// Apply glob filter if set
	if globFilter != "" {
		matched, err := filepath.Match(globFilter, name)
		if err != nil || !matched {
			log.Printf("[dir-watch] File %s doesn't match glob filter %s", name, globFilter)
			return
		}
	}

	// Deduplicate: use path+uid+comm as key to avoid duplicate alerts
	// Audit logs can have multiple records for the same operation
	dedupeKey := fmt.Sprintf("%s:%s:%s", path, event.UID, event.Comm)
	if lastSeen, ok := seen[dedupeKey]; ok {
		if time.Since(lastSeen) < 5*time.Second {
			log.Printf("[dir-watch] Deduplicating recent event for %s", path)
			return
		}
	}
	seen[dedupeKey] = time.Now()

	// Determine file type from syscall or metadata
	kind := "file"
	if event.Metadata["mode"] != "" {
		// Parse mode to determine if directory
		// This is simplified - in reality we'd parse the octal mode
		if strings.Contains(event.Metadata["mode"], "040") {
			kind = "directory"
		}
	}

	// Build activity description with process context
	activity := fmt.Sprintf("New %s: %s", kind, name)
	if event.Comm != "" {
		activity = fmt.Sprintf("%s (by: %s)", activity, event.Comm)
	}
	if event.UID != "" {
		activity = fmt.Sprintf("%s [uid=%s]", activity, event.UID)
	}

	// Determine severity
	severity := notifier.SeverityContact
	if kind == "directory" {
		severity = notifier.SeverityMovement
	}

	// Build equipment description with process info
	equip := kind
	if event.Exe != "" {
		equip = fmt.Sprintf("%s (exe: %s)", kind, event.Exe)
	}

	// Build location from path
	location := filepath.Dir(path)

	alert := notifier.Alert{
		Severity:  severity,
		SkillID:   SkillID,
		SkillName: SkillName,
		Title:     "New Entry in Watched Directory",
		Size:      "1 " + kind,
		Activity:  activity,
		Location:  location,
		Unit:      fmt.Sprintf("uid=%s pid=%s", event.UID, event.PID),
		Time:      event.Timestamp,
		Equipment: equip,
		Metadata: map[string]string{
			"path":    path,
			"kind":    kind,
			"uid":     event.UID,
			"auid":    event.AUID,
			"pid":     event.PID,
			"ppid":    event.PPID,
			"comm":    event.Comm,
			"exe":     event.Exe,
			"syscall": event.Syscall,
		},
	}

	log.Printf("[dir-watch] Sending alert: %s - %s", alert.Title, alert.Activity)
	alerts <- alert
}
