package skills

import (
	"strings"
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
