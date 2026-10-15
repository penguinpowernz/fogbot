package filewatch

import (
	"testing"
	"time"

	"github.com/penguinpowernz/fogbot/internal/auditlog"
	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
)

func severityFor(t *testing.T, f *FileWatch, path string) string {
	t.Helper()
	alerts := make(chan notifier.Alert, 1)
	f.handleAuditEvent(auditlog.Event{Path: path, Syscall: "openat", Timestamp: time.Now()}, alerts, map[string]time.Time{})
	select {
	case a := <-alerts:
		return a.Severity
	default:
		t.Fatalf("no alert for %s", path)
		return ""
	}
}

func TestSeverity_DaemonDefaultIsContactForAllPaths(t *testing.T) {
	f := NewDefault()
	for _, path := range []string{"/etc/shadow", "/etc/sudoers.d/90-admin", "/etc/passwd", "/root/.aws/credentials"} {
		if got := severityFor(t, f, path); got != notifier.SeverityContact {
			t.Errorf("%s: expected %q, got %q", path, notifier.SeverityContact, got)
		}
	}
}

func TestSeverity_YAMLColorDefault(t *testing.T) {
	f := New(skills.SkillConfig{ID: 500, Name: "file-watch", SeverityDefault: "yellow"})
	if got := severityFor(t, f, "/etc/passwd"); got != notifier.SeverityMovement {
		t.Errorf("expected yellow to map to %q, got %q", notifier.SeverityMovement, got)
	}
	// Auth files are never downgraded below CONTACT
	if got := severityFor(t, f, "/etc/shadow"); got != notifier.SeverityContact {
		t.Errorf("expected /etc/shadow to stay %q, got %q", notifier.SeverityContact, got)
	}
}
