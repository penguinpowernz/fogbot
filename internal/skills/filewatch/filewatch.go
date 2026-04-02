package filewatch

import (
	"context"
	"fmt"
	"log"
	"os"
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

// SetupHints checks which configured watch paths don't exist and returns
// suggested touch commands the user can run to create canary files.
// Paths owned by a specific user get a `sudo -iu <user> touch ...` form;
// root-owned paths use `sudo touch ...`.
func (f *FileWatch) SetupHints() []string {
	watchPaths, err := extractPathPermsMap(f.config, "watch_paths")
	if err != nil {
		return nil
	}

	// Collect missing paths, grouped by owner prefix
	var rootMissing []string
	homeMissing := map[string][]string{} // username -> paths

	for path := range watchPaths {
		if _, err := os.Stat(path); err == nil {
			continue // exists, skip
		}

		// Heuristic: paths under /home/<user> or /root suggest an owner
		if strings.HasPrefix(path, "/root/") {
			rootMissing = append(rootMissing, path)
		} else if strings.HasPrefix(path, "/home/") {
			parts := strings.SplitN(path, "/", 4) // ["", "home", "user", ...]
			if len(parts) >= 3 {
				user := parts[2]
				homeMissing[user] = append(homeMissing[user], path)
			} else {
				rootMissing = append(rootMissing, path)
			}
		} else {
			rootMissing = append(rootMissing, path)
		}
	}

	if len(rootMissing) == 0 && len(homeMissing) == 0 {
		return nil
	}

	var hints []string

	if len(rootMissing) > 0 {
		hints = append(hints, fmt.Sprintf("sudo touch %s", strings.Join(rootMissing, " ")))
	}

	for user, paths := range homeMissing {
		hints = append(hints, fmt.Sprintf("sudo -iu %s touch %s", user, strings.Join(paths, " ")))
	}

	return hints
}

func (f *FileWatch) Configure(cfg map[string]interface{}) error {
	f.config = cfg
	return nil
}

// generateRuleKey creates an audit rule key based on skill ID
func (f *FileWatch) generateRuleKey() string {
	// Use fb-file-<skillID> format (e.g., fb-file-500)
	return fmt.Sprintf("fb-file-%d", f.id)
}

// DeduceCommands generates auditctl commands from the declarative config.
// Each path in watch_paths maps to a permission string (any combo of r/w/a/x):
//
//	r = reads, w = writes, a = attribute changes, x = executions
//
// One auditctl command is generated per path:
//
//	auditctl -w <path> -p <perms> -k fb-file-<skillID>
func (f *FileWatch) DeduceCommands(cfg map[string]interface{}) ([]skills.SystemCommand, error) {
	watchPaths, err := extractPathPermsMap(cfg, "watch_paths")
	if err != nil {
		return nil, fmt.Errorf("invalid watch_paths config: %w", err)
	}

	if len(watchPaths) == 0 {
		return nil, fmt.Errorf("no watch_paths configured")
	}

	ruleKey := f.generateRuleKey()
	commands := []skills.SystemCommand{}

	for path, perms := range watchPaths {
		if perms == "" {
			return nil, fmt.Errorf("no permissions set for path %s", path)
		}

		commands = append(commands, skills.SystemCommand{
			Command:     fmt.Sprintf("auditctl -w %s -p %s -k %s", path, perms, ruleKey),
			Description: fmt.Sprintf("Monitor %s for %s", path, expandPerms(perms)),
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
	cmd := exec.Command("auditctl", "-l")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to check auditd rules: %w (output: %s)", err, string(output))
	}

	rulesOutput := string(output)
	ruleKey := f.generateRuleKey()

	watchPaths, err := extractPathPermsMap(f.config, "watch_paths")
	if err != nil {
		return false, fmt.Errorf("invalid watch_paths config: %w", err)
	}

	for path, perms := range watchPaths {
		// Look for exact match: -w /etc/passwd -p rwa -k fb-file-500
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

// extractPathPermsMap extracts the watch_paths map from config.
// YAML parses map[string]interface{} so values will be strings like "rwa".
func extractPathPermsMap(cfg map[string]interface{}, key string) (map[string]string, error) {
	val, ok := cfg[key]
	if !ok {
		return map[string]string{}, nil
	}

	raw, ok := val.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("watch_paths must be a map of path: perms")
	}

	result := make(map[string]string, len(raw))
	for path, permsVal := range raw {
		perms, ok := permsVal.(string)
		if !ok {
			return nil, fmt.Errorf("perms for %s must be a string (e.g. \"rwa\"), got %T", path, permsVal)
		}
		result[path] = perms
	}

	return result, nil
}

// expandPerms converts a compact permission string into a human-readable description.
func expandPerms(perms string) string {
	var parts []string
	if strings.Contains(perms, "r") {
		parts = append(parts, "reads")
	}
	if strings.Contains(perms, "w") {
		parts = append(parts, "writes")
	}
	if strings.Contains(perms, "a") {
		parts = append(parts, "attribute changes")
	}
	if strings.Contains(perms, "x") {
		parts = append(parts, "executions")
	}
	return strings.Join(parts, ", ")
}
