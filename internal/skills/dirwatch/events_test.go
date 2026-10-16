package dirwatch

import (
	"testing"
	"time"

	"github.com/penguinpowernz/fogbot/internal/auditlog"
	"github.com/penguinpowernz/fogbot/internal/notifier"
)

func newWatch(recursive bool) *DirWatch {
	d := New()
	d.Configure(map[string]interface{}{
		"watch_paths": []interface{}{"/usr/local/bin/", "/root/"},
		"recursive":   recursive,
	})
	return d
}

// handle returns the alert for e, or ok=false if there was none
func handle(d *DirWatch, e auditlog.Event) (notifier.Alert, bool) {
	alerts := make(chan notifier.Alert, 1)
	e.Timestamp = time.Now()
	d.handleAuditEvent(e, alerts, map[string]time.Time{})
	select {
	case a := <-alerts:
		return a, true
	default:
		return notifier.Alert{}, false
	}
}

func TestEventKindsHaveTheirOwnTitles(t *testing.T) {
	d := newWatch(false)
	for _, tc := range []struct {
		nametype, title, severity string
	}{
		{"CREATE", "New Entry in Watched Directory", notifier.SeverityContact},
		{"NORMAL", "Entry Changed in Watched Directory", notifier.SeverityContact},
		{"DELETE", "Entry Removed from Watched Directory", notifier.SeverityMovement},
	} {
		a, ok := handle(d, auditlog.Event{Path: "/usr/local/bin/tool", NameType: tc.nametype, UID: "0", Syscall: tc.nametype})
		if !ok || a.Title != tc.title || a.Severity != tc.severity {
			t.Errorf("%s: got %q/%q, want %q/%q", tc.nametype, a.Title, a.Severity, tc.title, tc.severity)
		}
	}
}

// auditd watches the whole tree; recursive: false used to be ignored, so
// every write under /root/.cache raised an alert
func TestNonRecursiveIgnoresSubdirectories(t *testing.T) {
	d := newWatch(false)
	if _, ok := handle(d, auditlog.Event{Path: "/root/.cache/x/y", NameType: "CREATE"}); ok {
		t.Fatal("alerted on a subdirectory with recursive off")
	}
	if _, ok := handle(d, auditlog.Event{Path: "/root/.bashrc", NameType: "NORMAL"}); !ok {
		t.Fatal("no alert for an entry directly in a watched directory")
	}

	if _, ok := handle(newWatch(true), auditlog.Event{Path: "/root/.cache/x/y", NameType: "CREATE"}); !ok {
		t.Fatal("no alert for a subdirectory with recursive on")
	}
}

func TestMovedOutIsReportedNotDropped(t *testing.T) {
	a, ok := handle(newWatch(false), auditlog.Event{Path: "/tmp/tool", NameType: "CREATE", Syscall: "rename"})
	if !ok || a.Title != "Entry Moved Out of Watched Directory" {
		t.Fatalf("unexpected alert %+v (ok=%v)", a, ok)
	}
}

// A name relative to an unidentified directory may be directly in a watched
// one, so it is reported even with recursive off
func TestUnresolvedIsReported(t *testing.T) {
	a, ok := handle(newWatch(false), auditlog.Event{Path: "payload", PathUnresolved: true, NameType: "CREATE", Inode: "1"})
	if !ok || a.Metadata["resolved"] != "false" {
		t.Fatalf("unexpected alert %+v (ok=%v)", a, ok)
	}
}
