package suidsweep

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/penguinpowernz/fogbot/internal/baseline"
	"github.com/penguinpowernz/fogbot/internal/notifier"
)

func writeSuid(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
}

func takeAlerts(ch chan notifier.Alert) []notifier.Alert {
	var out []notifier.Alert
	for {
		select {
		case a := <-ch:
			out = append(out, a)
		default:
			return out
		}
	}
}

func TestCheck_BaselineLifecycle(t *testing.T) {
	bin := t.TempDir()
	mgr := baseline.NewManager(t.TempDir())
	s := New(mgr)
	s.searchPaths = []string{bin}
	alerts := make(chan notifier.Alert, 10)
	reported := map[string]string{}

	writeSuid(t, filepath.Join(bin, "sudo"), "original")

	// No approved baseline: pending is saved and approval requested
	s.check(alerts, reported, true)
	got := takeAlerts(alerts)
	if len(got) != 1 || got[0].Title != "SUID Baseline Pending Approval" {
		t.Fatalf("expected pending approval alert, got %+v", got)
	}
	if err := mgr.ApproveSuid("cli:test"); err != nil {
		t.Fatal(err)
	}

	// Approved and unchanged: nothing to report
	s.check(alerts, reported, true)
	if got := takeAlerts(alerts); len(got) != 0 {
		t.Fatalf("expected no alerts, got %+v", got)
	}

	// A new SUID binary is reported once, and offered as pending
	writeSuid(t, filepath.Join(bin, "evil"), "backdoor")
	s.check(alerts, reported, false)
	got = takeAlerts(alerts)
	if len(got) != 1 || got[0].Title != "New SUID/SGID Binary Detected" {
		t.Fatalf("expected new binary alert, got %+v", got)
	}
	s.check(alerts, reported, false)
	if got := takeAlerts(alerts); len(got) != 0 {
		t.Fatalf("expected the same change not to re-alert, got %+v", got)
	}
	if pending, _ := mgr.LoadPendingSuid(); pending == nil || len(pending.Entries) != 2 {
		t.Fatalf("expected pending baseline with 2 entries, got %+v", pending)
	}

	// A binary replaced in place is reported as modified
	writeSuid(t, filepath.Join(bin, "sudo"), "trojaned")
	s.check(alerts, reported, false)
	got = takeAlerts(alerts)
	if len(got) != 1 || got[0].Title != "SUID/SGID Binary Modified" {
		t.Fatalf("expected modified alert, got %+v", got)
	}

	// Approving the pending state clears the alerts
	if err := mgr.ApproveSuid("cli:test"); err != nil {
		t.Fatal(err)
	}
	s.check(alerts, reported, false)
	if got := takeAlerts(alerts); len(got) != 0 {
		t.Fatalf("expected no alerts after approval, got %+v", got)
	}
}
