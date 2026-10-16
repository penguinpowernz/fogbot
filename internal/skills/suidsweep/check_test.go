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

	// Removing the binary and planting it again reports it again
	if err := os.Remove(filepath.Join(bin, "evil")); err != nil {
		t.Fatal(err)
	}
	s.check(alerts, reported, false)
	if got := takeAlerts(alerts); len(got) != 0 {
		t.Fatalf("expected no alerts once the binary is removed, got %+v", got)
	}
	writeSuid(t, filepath.Join(bin, "evil"), "backdoor")
	s.check(alerts, reported, false)
	got = takeAlerts(alerts)
	if len(got) != 1 || got[0].Title != "New SUID/SGID Binary Detected" {
		t.Fatalf("expected re-planted binary to alert again, got %+v", got)
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

func TestCheck_NoSuidPaths(t *testing.T) {
	bin := t.TempDir()
	home := t.TempDir()
	mgr := baseline.NewManager(t.TempDir())
	s := New(mgr)
	s.Configure(map[string]interface{}{"no_suid_paths": []interface{}{home}})
	s.searchPaths = []string{bin, home} // overlap: home must not enter the baseline
	alerts := make(chan notifier.Alert, 10)
	reported := map[string]string{}

	writeSuid(t, filepath.Join(bin, "sudo"), "original")
	if err := os.MkdirAll(filepath.Join(home, "alice"), 0755); err != nil {
		t.Fatal(err)
	}
	writeSuid(t, filepath.Join(home, "alice", "sh"), "rootshell")

	// Reported even with no approved baseline, and kept out of the pending one
	s.check(alerts, reported, true)
	got := takeAlerts(alerts)
	if len(got) != 2 || got[0].Title != "SUID/SGID File in No-SUID Path" || got[1].Title != "SUID Baseline Pending Approval" {
		t.Fatalf("expected no-SUID alert then pending approval, got %+v", got)
	}
	if got[0].Location != filepath.Join(home, "alice", "sh") {
		t.Errorf("expected alert for the planted file, got %q", got[0].Location)
	}
	if pending, _ := mgr.LoadPendingSuid(); pending == nil || len(pending.Entries) != 1 {
		t.Fatalf("expected only the watch_paths binary in the pending baseline, got %+v", pending)
	}

	// Approving the baseline doesn't clear it, but it is only reported once
	if err := mgr.ApproveSuid("cli:test"); err != nil {
		t.Fatal(err)
	}
	s.check(alerts, reported, false)
	if got := takeAlerts(alerts); len(got) != 0 {
		t.Fatalf("expected the same file not to re-alert, got %+v", got)
	}

	// Changed contents are reported again
	writeSuid(t, filepath.Join(home, "alice", "sh"), "rootshell v2")
	s.check(alerts, reported, false)
	if got := takeAlerts(alerts); len(got) != 1 || got[0].Title != "SUID/SGID File in No-SUID Path" {
		t.Fatalf("expected changed file to alert again, got %+v", got)
	}

	// Dropping the bit clears it, and setting it again reports it again
	path := filepath.Join(home, "alice", "sh")
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	s.check(alerts, reported, false)
	if got := takeAlerts(alerts); len(got) != 0 {
		t.Fatalf("expected no alerts once the bit is gone, got %+v", got)
	}
	if err := os.Chmod(path, 0755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	s.check(alerts, reported, false)
	if got := takeAlerts(alerts); len(got) != 1 {
		t.Fatalf("expected the file to alert again once the bit is back, got %+v", got)
	}
}

func TestSweepNoSuid_NestedPathsWalkedOnce(t *testing.T) {
	root := t.TempDir()
	inner := filepath.Join(root, "inner")
	if err := os.Mkdir(inner, 0755); err != nil {
		t.Fatal(err)
	}
	writeSuid(t, filepath.Join(inner, "x"), "x")

	s := New(nil)
	s.Configure(map[string]interface{}{"no_suid_paths": []interface{}{inner, root + "/"}})
	if got := s.sweepNoSuid(); len(got) != 1 {
		t.Fatalf("expected 1 file, got %v", got)
	}

	// A path listed twice is still walked
	s.Configure(map[string]interface{}{"no_suid_paths": []interface{}{inner, inner}})
	if got := s.sweepNoSuid(); len(got) != 1 {
		t.Fatalf("expected 1 file with a duplicated path, got %v", got)
	}
}

func TestConfigure_NoSuidPaths(t *testing.T) {
	s := New(nil)
	if len(s.noSuidPaths) != 0 {
		t.Fatalf("expected no no-SUID paths by default, got %v", s.noSuidPaths)
	}
	s.Configure(map[string]interface{}{"no_suid_paths": []interface{}{"/tmp", "/home/"}})
	if len(s.noSuidPaths) != 2 || s.noSuidPaths[1] != "/home" {
		t.Fatalf("expected cleaned paths, got %v", s.noSuidPaths)
	}
	s.Configure(map[string]interface{}{"no_suid_paths": []interface{}{}})
	if len(s.noSuidPaths) != 0 {
		t.Fatalf("expected an empty list to switch the check off, got %v", s.noSuidPaths)
	}
}

func TestUnder(t *testing.T) {
	cases := []struct {
		path, root string
		want       bool
	}{
		{"/home", "/home", true},
		{"/home/alice/x", "/home", true},
		{"/homework", "/home", false},
		{"/usr/bin", "/home", false},
		{"/anything", "/", true},
	}
	for _, c := range cases {
		if got := under(c.path, c.root); got != c.want {
			t.Errorf("under(%q, %q) = %v, want %v", c.path, c.root, got, c.want)
		}
	}
}

// A SUID file over max_hash_mb isn't read; alert_on_too_large reports it once
func TestCheck_TooLargeFileNotHashedAndOptionallyAlerted(t *testing.T) {
	bin := t.TempDir()
	mgr := baseline.NewManager(t.TempDir())
	s := New(mgr)
	if err := s.Configure(map[string]interface{}{
		"watch_paths":        []interface{}{bin},
		"max_hash_mb":        1,
		"alert_on_too_large": true,
	}); err != nil {
		t.Fatal(err)
	}
	alerts := make(chan notifier.Alert, 10)
	reported := map[string]string{}

	big := filepath.Join(bin, "big")
	writeSuid(t, big, "")
	os.Truncate(big, 2<<20) // clears the SUID bit
	os.Chmod(big, 0755|os.ModeSetuid)

	s.check(alerts, reported, true)
	var titles []string
	for _, a := range takeAlerts(alerts) {
		titles = append(titles, a.Title)
	}
	if len(titles) != 2 || titles[0] != "SUID/SGID File Too Large to Hash" {
		t.Fatalf("expected a too-large alert then the pending baseline, got %q", titles)
	}
	pending, _ := mgr.LoadPendingSuid()
	if e := pending.Entries[big]; !e.TooLarge || e.Hash != "" {
		t.Fatalf("expected an unhashed too-large entry, got %+v", e)
	}

	// Reported once, not on every sweep
	s.check(alerts, reported, false)
	if got := takeAlerts(alerts); len(got) != 0 {
		t.Fatalf("expected no repeat alert, got %+v", got)
	}
}

func TestCheck_TooLargeIsQuietByDefault(t *testing.T) {
	bin := t.TempDir()
	s := New(baseline.NewManager(t.TempDir()))
	s.Configure(map[string]interface{}{"watch_paths": []interface{}{bin}, "max_hash_mb": 1})
	alerts := make(chan notifier.Alert, 10)

	big := filepath.Join(bin, "big")
	writeSuid(t, big, "")
	os.Truncate(big, 2<<20) // clears the SUID bit
	os.Chmod(big, 0755|os.ModeSetuid)

	s.check(alerts, map[string]string{}, true)
	for _, a := range takeAlerts(alerts) {
		if a.Title == "SUID/SGID File Too Large to Hash" {
			t.Fatal("too-large alert without alert_on_too_large")
		}
	}
}
