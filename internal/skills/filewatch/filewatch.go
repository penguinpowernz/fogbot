package filewatch

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

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

	// Check if all expected paths are monitored with our rule key
	for _, path := range watchPaths {
		// Look for lines like: -w /etc/passwd -p wa -k fogbot-file-500
		if !strings.Contains(rulesOutput, path) || !strings.Contains(rulesOutput, ruleKey) {
			return false, nil
		}
	}

	return true, nil
}

// Watch monitors audit logs for file access events
func (f *FileWatch) Watch(ctx context.Context) (<-chan notifier.Alert, error) {
	alerts := make(chan notifier.Alert)

	go func() {
		defer close(alerts)
		// TODO: Implement audit log watching
		// This will monitor ausearch or journalctl for events matching our rule key
		// Parse audit events and generate SALUTE-formatted alerts
		<-ctx.Done()
	}()

	return alerts, nil
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
