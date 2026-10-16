package filewatch

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/penguinpowernz/fogbot/internal/auditlog"
	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
)

func alertFor(t *testing.T, f *FileWatch, e auditlog.Event) notifier.Alert {
	t.Helper()
	alerts := make(chan notifier.Alert, 1)
	e.Timestamp = time.Now()
	f.handleAuditEvent(e, alerts, map[string]time.Time{})
	select {
	case a := <-alerts:
		return a
	default:
		t.Fatal("no alert")
		return notifier.Alert{}
	}
}

func inodeOf(t *testing.T, path string) string {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return strconv.FormatUint(info.Sys().(*syscall.Stat_t).Ino, 10)
}

// openat(fd of the watched file's directory, "shadow") whose fd couldn't be
// looked up: the inode identifies the watched file
func TestUnresolvedPathMatchedByInode(t *testing.T) {
	shadow := filepath.Join(t.TempDir(), "shadow")
	os.WriteFile(shadow, nil, 0600)
	f := New(skills.SkillConfig{ID: 500, Name: "file-watch", SeverityDefault: "yellow",
		Config: map[string]interface{}{"watch_paths": map[string]interface{}{shadow: "rwa"}}})

	a := alertFor(t, f, auditlog.Event{Path: "shadow", Name: "shadow", PathUnresolved: true, Inode: inodeOf(t, shadow), Syscall: "openat"})
	if a.Metadata["path"] != shadow || a.Location != filepath.Dir(shadow) {
		t.Fatalf("expected the watched path, got path=%q location=%q", a.Metadata["path"], a.Location)
	}
}

// Without a match the alert must not name a made-up path, and can't be
// downgraded: the file might be /etc/shadow
func TestUnresolvedPathIsContactWithUnknownLocation(t *testing.T) {
	f := New(skills.SkillConfig{ID: 500, Name: "file-watch", SeverityDefault: "yellow"})

	a := alertFor(t, f, auditlog.Event{Path: "shadow", Name: "shadow", PathUnresolved: true, Inode: "1", Syscall: "openat"})
	if a.Severity != notifier.SeverityContact || a.Location != unresolvedLocation || a.Metadata["resolved"] != "false" {
		t.Fatalf("unexpected alert: severity=%q location=%q resolved=%q", a.Severity, a.Location, a.Metadata["resolved"])
	}
}
