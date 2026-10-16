package skills

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/kballard/go-shellquote"
)

// AuditWatchListed reports whether rules, the output of auditctl -l, holds the
// watch rule for path with perms and key.
//
// auditctl lists a rule normalised rather than as it was added: trailing
// slashes are trimmed from the path and the permissions are printed in rwxa
// order, so "-w /etc/cron.d/ -p aw" is listed as "-w /etc/cron.d -p wa". Both
// sides are normalised before comparing, so a rule that is present is never
// reported missing.
func AuditWatchListed(rules, path, perms, key string) bool {
	wantPath, wantPerms := auditWatchPath(path), auditWatchPerms(perms)
	suffix := " -k " + key
	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "-w ")
		if !ok {
			continue
		}
		rest, ok = strings.CutSuffix(rest, suffix)
		if !ok {
			continue
		}
		// The path may contain spaces; the permissions never do
		i := strings.LastIndex(rest, " -p ")
		if i < 0 {
			continue
		}
		if auditWatchPath(rest[:i]) == wantPath && auditWatchPerms(rest[i+len(" -p "):]) == wantPerms {
			return true
		}
	}
	return false
}

// auditWatchPath trims trailing slashes, as auditctl does
func auditWatchPath(path string) string {
	for len(path) > 1 && strings.HasSuffix(path, "/") {
		path = path[:len(path)-1]
	}
	return path
}

// auditWatchPerms puts permission letters in the order auditctl lists them
func auditWatchPerms(perms string) string {
	var b strings.Builder
	for _, c := range "rwxa" {
		if strings.ContainsRune(perms, c) {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// ListAuditRules returns the output of auditctl -l
func ListAuditRules() (string, error) {
	output, err := exec.Command("auditctl", "-l").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to list auditd rules: %w (output: %s)", err, string(output))
	}
	return string(output), nil
}

// AuditWatch is a watch rule as auditctl -l lists it
type AuditWatch struct {
	Path  string
	Perms string
}

// AuditWatchesWithKey returns the watch rules in rules, the output of
// auditctl -l, that carry key
func AuditWatchesWithKey(rules, key string) []AuditWatch {
	var watches []AuditWatch
	suffix := " -k " + key
	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "-w ")
		if !ok {
			continue
		}
		rest, ok = strings.CutSuffix(rest, suffix)
		if !ok {
			continue
		}
		i := strings.LastIndex(rest, " -p ")
		if i < 0 {
			continue
		}
		watches = append(watches, AuditWatch{Path: rest[:i], Perms: rest[i+len(" -p "):]})
	}
	return watches
}

// AuditRemoveCommands returns the commands deleting every watch rule
// carrying key, whether or not the current config still lists its path
func AuditRemoveCommands(key string) ([]SystemCommand, error) {
	rules, err := ListAuditRules()
	if err != nil {
		return nil, err
	}
	var commands []SystemCommand
	for _, w := range AuditWatchesWithKey(rules, key) {
		commands = append(commands, SystemCommand{
			Command:     fmt.Sprintf("auditctl -W %s -p %s -k %s", shellquote.Join(w.Path), w.Perms, key),
			Description: fmt.Sprintf("Stop monitoring %s", w.Path),
			Metadata: map[string]string{
				"rule_key": key,
				"path":     w.Path,
				"perms":    w.Perms,
				"action":   "remove",
			},
		})
	}
	return commands, nil
}
