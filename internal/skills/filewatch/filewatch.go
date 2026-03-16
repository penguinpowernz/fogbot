package filewatch

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/penguinpowernz/fogbot/internal/auditlog"
	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
)

// FileWatch monitors critical system files using auditd
type FileWatch struct {
	id              int
	name            string
	description     string
	why             string
	requires        []string
	tags            []string
	enabled         bool
	config          map[string]interface{}
	severityDefault string
}

// New creates a new FileWatch skill from config
func New(cfg skills.SkillConfig) *FileWatch {
	return &FileWatch{
		id:              cfg.ID,
		name:            cfg.Name,
		description:     cfg.Description,
		why:             cfg.Why,
		requires:        cfg.Requires,
		tags:            cfg.Tags,
		config:          cfg.Config,
		severityDefault: cfg.SeverityDefault,
		enabled:         false,
	}
}

func (f *FileWatch) ID() int                        { return f.id }
func (f *FileWatch) Name() string                   { return f.name }
func (f *FileWatch) Description() string            { return f.description }
func (f *FileWatch) Why() string                    { return f.why }
func (f *FileWatch) Requires() []string             { return f.requires }
func (f *FileWatch) Tags() []string                 { return f.tags }
func (f *FileWatch) Enabled() bool                  { return f.enabled }
func (f *FileWatch) SetEnabled(enabled bool)        { f.enabled = enabled }
func (f *FileWatch) Config() map[string]interface{} { return f.config }
func (f *FileWatch) DropIns() []skills.DropIn       { return nil }

func (f *FileWatch) Configure(cfg map[string]interface{}) error {
	f.config = cfg
	return nil
}

// generateRuleKey creates an audit rule key based on skill ID
func (f *FileWatch) generateRuleKey() string {
	// Use fb-file-<skillID> format (e.g., fb-file-500)
	return fmt.Sprintf("fb-file-%d", f.id)
}

// DeduceCommands generates auditctl commands from the declarative config
func (f *FileWatch) DeduceCommands(cfg map[string]interface{}) ([]skills.SystemCommand, error) {
	commands := []skills.SystemCommand{}

	// Extract watch paths from config
	watchPaths, err := extractStringList(cfg, "watch_paths")
	if err != nil {
		return nil, fmt.Errorf("invalid watch_paths config: %w", err)
	}

	if len(watchPaths) == 0 {
		return nil, fmt.Errorf("no watch_paths configured")
	}

	// Extract permission flags
	alertOnRead := getBool(cfg, "alert_on_read", false)
	alertOnWrite := getBool(cfg, "alert_on_write", true)
	alertOnExecute := getBool(cfg, "alert_on_execute", true)
	alertOnAttribute := getBool(cfg, "alert_on_attribute", true)

	// Build permission string (wa = write+attribute, r = read, x = execute)
	perms := ""
	if alertOnWrite {
		perms += "w"
	}
	if alertOnAttribute {
		perms += "a"
	}
	if alertOnRead {
		perms += "r"
	}
	if alertOnExecute {
		perms += "x"
	}

	if perms == "" {
		return nil, fmt.Errorf("no permissions enabled for monitoring")
	}

	// Generate non-obvious rule key
	ruleKey := f.generateRuleKey()

	// Build auditctl commands for each path
	for _, path := range watchPaths {
		cmd := fmt.Sprintf("auditctl -w %s -p %s -k %s", path, perms, ruleKey)

		// Create human-readable description of what's monitored
		var permDesc []string
		if alertOnRead {
			permDesc = append(permDesc, "reads")
		}
		if alertOnWrite {
			permDesc = append(permDesc, "writes")
		}
		if alertOnAttribute {
			permDesc = append(permDesc, "attribute changes")
		}
		if alertOnExecute {
			permDesc = append(permDesc, "executions")
		}

		commands = append(commands, skills.SystemCommand{
			Command:     cmd,
			Description: fmt.Sprintf("Monitor %s for %s", path, strings.Join(permDesc, ", ")),
			Metadata: map[string]string{
				"rule_key": ruleKey,
				"path":     path,
				"perms":    perms,
			},
		})
	}

	return commands, nil
}

// CheckSystemState verifies if auditd rules are already configured
func (f *FileWatch) CheckSystemState() (bool, error) {
	// Get current audit rules
	cmd := exec.Command("auditctl", "-l")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to check auditd rules: %w (output: %s)", err, string(output))
	}

	rulesOutput := string(output)

	// Generate the rule key we expect to find
	ruleKey := f.generateRuleKey()

	// Extract watch paths from config
	watchPaths, err := extractStringList(f.config, "watch_paths")
	if err != nil {
		return false, fmt.Errorf("invalid watch_paths config: %w", err)
	}

	// Build permission string to match what we generate in DeduceCommands
	alertOnRead := getBool(f.config, "alert_on_read", false)
	alertOnWrite := getBool(f.config, "alert_on_write", true)
	alertOnExecute := getBool(f.config, "alert_on_execute", true)
	alertOnAttribute := getBool(f.config, "alert_on_attribute", true)

	perms := ""
	if alertOnWrite {
		perms += "w"
	}
	if alertOnAttribute {
		perms += "a"
	}
	if alertOnRead {
		perms += "r"
	}
	if alertOnExecute {
		perms += "x"
	}

	// Check if all expected paths are monitored with our rule key
	for _, path := range watchPaths {
		// Look for exact match: -w /etc/passwd -p warx -k fb-file-500
		// This avoids false positives from substring matches
		rulePattern := fmt.Sprintf("-w %s -p %s -k %s", path, perms, ruleKey)
		if !strings.Contains(rulesOutput, rulePattern) {
			return false, nil
		}
	}

	return true, nil
}

// Watch monitors audit logs for file access events
func (f *FileWatch) Watch(ctx context.Context) (<-chan notifier.Alert, error) {
	log.Printf("[file-watch] Watch() called - starting auditd watcher")

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

	ruleKey := f.generateRuleKey()
	auditEvents := make(chan auditlog.Event, 100)

	// Subscribe to our rule key
	tailer.Subscribe(ruleKey, auditEvents)

	log.Printf("[file-watch] Subscribed to audit events with key: %s", ruleKey)

	go func() {
		defer close(alerts)
		defer tailer.Unsubscribe(ruleKey, auditEvents)

		// Track recently seen events to avoid duplicates
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

				log.Printf("[file-watch] Received audit event: type=%s, name=%s, uid=%s, comm=%s, exe=%s",
					event.RecordType, event.Name, event.UID, event.Comm, event.Exe)

				// Process the event
				f.handleAuditEvent(event, alerts, seen)
			}
		}
	}()

	return alerts, nil
}

func (f *FileWatch) handleAuditEvent(event auditlog.Event, alerts chan<- notifier.Alert, seen map[string]time.Time) {
	// Extract the file path
	path := event.Path
	if path == "" && event.Name != "" {
		path = event.Name
	}

	if path == "" {
		log.Printf("[file-watch] Skipping event with no path/name")
		return
	}

	// Deduplicate: use path+uid+syscall as key
	// Audit logs generate multiple records per operation
	dedupeKey := fmt.Sprintf("%s:%s:%s", path, event.UID, event.Syscall)
	if lastSeen, ok := seen[dedupeKey]; ok {
		if time.Since(lastSeen) < 5*time.Second {
			log.Printf("[file-watch] Deduplicating recent event for %s", path)
			return
		}
	}
	seen[dedupeKey] = time.Now()

	// Determine operation type from syscall or metadata
	operation := "accessed"
	if event.Syscall != "" {
		switch event.Syscall {
		case "open", "openat":
			operation = "opened"
		case "unlink", "unlinkat":
			operation = "deleted"
		case "rename", "renameat":
			operation = "renamed"
		case "chmod", "fchmod":
			operation = "permissions changed"
		case "chown", "fchown":
			operation = "ownership changed"
		}
	}

	// Build activity description with process context
	name := filepath.Base(path)
	activity := fmt.Sprintf("File %s: %s", operation, name)
	if event.Comm != "" {
		activity = fmt.Sprintf("%s (by: %s)", activity, event.Comm)
	}
	if event.UID != "" {
		activity = fmt.Sprintf("%s [uid=%s]", activity, event.UID)
	}

	// Determine severity based on file and operation
	severity := f.severityDefault
	if severity == "" {
		severity = notifier.SeverityContact
		// Critical files get elevated severity
		if strings.Contains(path, "/etc/shadow") || strings.Contains(path, "/etc/sudoers") {
			severity = notifier.SeverityMovement
		}
	}

	// Build equipment description with process info
	equip := "file"
	if event.Exe != "" {
		equip = fmt.Sprintf("file (exe: %s)", event.Exe)
	}

	alert := notifier.Alert{
		Severity:  severity,
		SkillID:   f.id,
		SkillName: f.name,
		Title:     "Critical File Access",
		Size:      "1 file",
		Activity:  activity,
		Location:  filepath.Dir(path),
		Unit:      fmt.Sprintf("uid=%s pid=%s", event.UID, event.PID),
		Time:      event.Timestamp,
		Equipment: equip,
		Metadata: map[string]string{
			"path":      path,
			"operation": operation,
			"uid":       event.UID,
			"auid":      event.AUID,
			"pid":       event.PID,
			"ppid":      event.PPID,
			"comm":      event.Comm,
			"exe":       event.Exe,
			"syscall":   event.Syscall,
		},
	}

	log.Printf("[file-watch] Sending alert: %s - %s", alert.Title, alert.Activity)
	alerts <- alert
}

// extractStringList safely extracts a list of strings from config
func extractStringList(cfg map[string]interface{}, key string) ([]string, error) {
	val, ok := cfg[key]
	if !ok {
		return []string{}, nil
	}

	// Handle []interface{} from YAML parsing
	if listInterface, ok := val.([]interface{}); ok {
		result := make([]string, 0, len(listInterface))
		for _, item := range listInterface {
			if str, ok := item.(string); ok {
				result = append(result, str)
			} else {
				return nil, fmt.Errorf("invalid string in %s: %v", key, item)
			}
		}
		return result, nil
	}

	return nil, fmt.Errorf("invalid format for %s", key)
}

// getBool safely extracts a boolean from config with a default value
func getBool(cfg map[string]interface{}, key string, defaultValue bool) bool {
	val, ok := cfg[key]
	if !ok {
		return defaultValue
	}

	if b, ok := val.(bool); ok {
		return b
	}

	return defaultValue
}
