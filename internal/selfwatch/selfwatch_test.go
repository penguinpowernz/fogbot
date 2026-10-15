package selfwatch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
)

func start(t *testing.T) (string, string, <-chan notifier.Alert) {
	t.Helper()
	stateDir := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(configPath, []byte("x: 1\n"), 0600)
	for _, f := range []string{"state.json", "suid_baseline.json"} {
		os.WriteFile(filepath.Join(stateDir, f), []byte("{}"), 0600)
	}

	sw, err := New("", configPath, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ch, err := sw.Watch(ctx, "host")
	if err != nil {
		t.Fatal(err)
	}
	return stateDir, configPath, ch
}

func next(t *testing.T, ch <-chan notifier.Alert) notifier.Alert {
	t.Helper()
	select {
	case a := <-ch:
		return a
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for alert")
	}
	return notifier.Alert{}
}

func none(t *testing.T, ch <-chan notifier.Alert) {
	t.Helper()
	select {
	case a := <-ch:
		t.Fatalf("unexpected alert: %+v", a)
	case <-time.After(500 * time.Millisecond):
	}
}

func TestOwnWritesAreNotReported(t *testing.T) {
	stateDir, _, ch := start(t)
	path := filepath.Join(stateDir, "state.json")

	ExpectWrite(path)
	os.WriteFile(path, []byte(`{"authorized_chat":"1"}`), 0600)
	none(t, ch)
}

func TestForeignStateWriteIsContactWhenOnlyDaemonWritesIt(t *testing.T) {
	stateDir, _, ch := start(t)
	os.WriteFile(filepath.Join(stateDir, "state.json"), []byte(`{"authorized_chat":"666"}`), 0600)

	a := next(t, ch)
	if a.Severity != notifier.SeverityContact || a.Title != "fogbot State Changed" {
		t.Fatalf("expected CONTACT state change, got %+v", a)
	}
	none(t, ch) // the write's other events are collapsed into one alert
}

func TestBaselineChangeOutsideDaemonIsMovementWithHint(t *testing.T) {
	stateDir, _, ch := start(t)
	os.WriteFile(filepath.Join(stateDir, "suid_baseline.json"), []byte(`{"approved":true}`), 0600)

	a := next(t, ch)
	if a.Severity != notifier.SeverityMovement || a.Unit != "expected only after running: fogbot baseline approve" {
		t.Fatalf("expected MOVEMENT with approve hint, got %+v", a)
	}
}

func TestConfigChangeIsContact(t *testing.T) {
	_, configPath, ch := start(t)
	os.WriteFile(configPath, []byte("x: 2\n"), 0600)

	a := next(t, ch)
	if a.Severity != notifier.SeverityContact || a.Title != "fogbot File Tamper Detected" {
		t.Fatalf("expected CONTACT tamper alert, got %+v", a)
	}
}

func TestExpectWriteExpires(t *testing.T) {
	ExpectWrite("/x/y")
	if !isOwnWrite("/x/y") || !isOwnWrite("/x/y") {
		t.Fatal("an expected write should match repeatedly within the grace period")
	}
	ownWrites.Lock()
	ownWrites.until["/x/y"] = time.Now().Add(-time.Second)
	ownWrites.Unlock()
	if isOwnWrite("/x/y") {
		t.Fatal("expected write should expire")
	}
}
