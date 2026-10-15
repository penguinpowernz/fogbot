package main

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/penguinpowernz/fogbot/internal/baseline"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, _ := os.Pipe()
	orig := os.Stdout
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = orig
	out, _ := io.ReadAll(r)
	return string(out)
}

func TestLoadBaselineChanges_ShowsAddedChangedRemoved(t *testing.T) {
	stateDir = t.TempDir()
	defer func() { stateDir = "" }()
	mgr := baseline.NewManager(stateDir)

	entry := func(path, hash string) baseline.SuidEntry {
		return baseline.SuidEntry{Path: path, Hash: hash, Mode: uint32(0755 | os.ModeSetuid)}
	}
	mgr.SavePendingSuid(&baseline.Baseline{Type: "suid", CreatedAt: time.Now(), Entries: map[string]baseline.SuidEntry{
		"/usr/bin/sudo":   entry("/usr/bin/sudo", "aaa"),
		"/usr/bin/passwd": entry("/usr/bin/passwd", "bbb"),
	}})
	if err := mgr.ApproveSuid("cli:test"); err != nil {
		t.Fatal(err)
	}
	mgr.SavePendingSuid(&baseline.Baseline{Type: "suid", CreatedAt: time.Now(), Entries: map[string]baseline.SuidEntry{
		"/usr/bin/sudo": entry("/usr/bin/sudo", "changed"),
		"/tmp/evil":     entry("/tmp/evil", "ccc"),
	}})

	var pending *baseline.Baseline
	out := captureStdout(t, func() {
		var err error
		if _, pending, err = loadBaselineChanges(); err != nil {
			t.Fatal(err)
		}
	})

	if pending == nil {
		t.Fatal("expected the pending baseline to be returned")
	}
	for _, want := range []string{"+ /tmp/evil", "~ /usr/bin/sudo", "- /usr/bin/passwd", "urwxr-xr-x"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestLoadBaselineChanges_NothingPending(t *testing.T) {
	stateDir = t.TempDir()
	defer func() { stateDir = "" }()

	var pending *baseline.Baseline
	out := captureStdout(t, func() { _, pending, _ = loadBaselineChanges() })
	if pending != nil || !strings.Contains(out, "No pending") {
		t.Fatalf("expected nothing pending, got %v / %q", pending, out)
	}
}
