package pkgmonitor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
)

func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
}

func waitAlert(t *testing.T, ch <-chan notifier.Alert, want string) {
	t.Helper()
	select {
	case a := <-ch:
		if a.Activity != "Installed "+want {
			t.Fatalf("expected alert for %s, got %q", want, a.Activity)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for alert about %s", want)
	}
}

func startWatch(t *testing.T, logPath string) <-chan notifier.Alert {
	t.Helper()
	p := New()
	p.Configure(map[string]interface{}{"log_path": logPath})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ch, err := p.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // let the tailer open and seek to the end
	return ch
}

func TestWatch_SurvivesRotation(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "dpkg.log")
	appendLine(t, logPath, "2024-03-15 12:00:00 install old:amd64 <none> 1.0")
	ch := startWatch(t, logPath)

	appendLine(t, logPath, "2024-03-15 12:00:01 install before:amd64 <none> 1.0")
	waitAlert(t, ch, "before")

	// logrotate-style rotation: move the file away, then a new file appears
	if err := os.Rename(logPath, logPath+".1"); err != nil {
		t.Fatal(err)
	}
	appendLine(t, logPath, "2024-03-15 12:00:02 install after:amd64 <none> 1.0")
	waitAlert(t, ch, "after")
}

func TestWatch_WaitsForMissingFile(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "dpkg.log")
	ch := startWatch(t, logPath)

	appendLine(t, logPath, "2024-03-15 12:00:00 install late:amd64 <none> 1.0")
	waitAlert(t, ch, "late")
}
