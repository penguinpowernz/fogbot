package selfwatch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/penguinpowernz/fogbot/internal/atomicfile"
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

func TestOwnAtomicWritesAreNotReported(t *testing.T) {
	stateDir, _, ch := start(t)
	path := filepath.Join(stateDir, "state.json")

	ExpectWrite(path)
	if err := atomicfile.WriteFile(path, []byte(`{"authorized_chat":"1"}`), 0600); err != nil {
		t.Fatal(err)
	}
	none(t, ch)
}

func TestForeignAtomicWriteIsOneAlertAboutTheRealFile(t *testing.T) {
	stateDir, _, ch := start(t)
	path := filepath.Join(stateDir, "approved-commands.json")

	if err := atomicfile.WriteFile(path, []byte(`[]`), 0600); err != nil {
		t.Fatal(err)
	}

	a := next(t, ch)
	if a.Location != path || a.Severity != notifier.SeverityMovement ||
		a.Unit != "expected only after running: fogbot skill enable/disable" {
		t.Fatalf("expected MOVEMENT about approved-commands.json, got %+v", a)
	}
	none(t, ch) // the temporary file's events are collapsed into the same alert
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

func TestConfigReplacedByRenameIsContact(t *testing.T) {
	_, configPath, ch := start(t)
	replacement := configPath + ".new"
	os.WriteFile(replacement, []byte("x: 3\n"), 0600)
	os.Rename(replacement, configPath)

	a := next(t, ch)
	if a.Severity != notifier.SeverityContact || a.Title != "fogbot File Tamper Detected" {
		t.Fatalf("expected CONTACT tamper alert, got %+v", a)
	}

	// The new file at the path is watched too
	time.Sleep(ownWriteGrace)
	for len(ch) > 0 {
		<-ch
	}
	os.WriteFile(configPath, []byte("x: 4\n"), 0600)
	if a := next(t, ch); a.Severity != notifier.SeverityContact {
		t.Fatalf("expected CONTACT for write to replaced config, got %+v", a)
	}
}

func TestConfigChmodIsReported(t *testing.T) {
	_, configPath, ch := start(t)
	os.Chmod(configPath, 0666)

	if a := next(t, ch); a.Severity != notifier.SeverityContact {
		t.Fatalf("expected CONTACT tamper alert, got %+v", a)
	}
}

func TestSkillDirChangesAreReported(t *testing.T) {
	available, enabled := t.TempDir(), t.TempDir()
	skillFile := filepath.Join(available, "510-port-tripwires.yaml")
	os.WriteFile(skillFile, []byte("id: 510\n"), 0600)

	sw, err := New("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	sw.WatchSkillDirs(available, enabled)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ch, err := sw.Watch(ctx, "host")
	if err != nil {
		t.Fatal(err)
	}

	// Editor droppings aren't skill files
	os.WriteFile(filepath.Join(available, ".510-port-tripwires.yaml.swp"), []byte("x"), 0600)
	none(t, ch)

	os.WriteFile(skillFile, []byte("id: 510\nconfig: {}\n"), 0600)
	if a := next(t, ch); a.Title != "fogbot Skill Config Changed" || a.Severity != notifier.SeverityMovement {
		t.Fatalf("unexpected alert for edited skill: %+v", a)
	}

	link := filepath.Join(enabled, "510-port-tripwires.yaml")
	os.Symlink(skillFile, link)
	if a := next(t, ch); a.Location != link {
		t.Fatalf("unexpected alert for enabled skill: %+v", a)
	}
}
