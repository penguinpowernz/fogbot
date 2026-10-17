package systemdwatch

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
	"golang.org/x/sys/unix"
)

// holdLock takes a write lock on path the way dpkg does. It is an OFD lock
// because F_GETLK never reports a process's own POSIX locks back to it.
func holdLock(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0640)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	lk := unix.Flock_t{Type: unix.F_WRLCK}
	if err := unix.FcntlFlock(f.Fd(), unix.F_OFD_SETLK, &lk); err != nil {
		t.Fatal(err)
	}
}

func TestDpkgRunning(t *testing.T) {
	dir := t.TempDir()
	frontend := filepath.Join(dir, "lock-frontend")
	lock := filepath.Join(dir, "lock")
	locks := []string{frontend, lock}

	if skills.DpkgRunning(locks) {
		t.Fatal("expected false when the lock files don't exist")
	}
	if err := os.WriteFile(lock, nil, 0640); err != nil {
		t.Fatal(err)
	}
	if skills.DpkgRunning(locks) {
		t.Fatal("expected false when the lock file exists but is unlocked")
	}
	holdLock(t, lock)
	if !skills.DpkgRunning(locks) {
		t.Fatal("expected true while the lock is held")
	}
}

func reloading() *dbus.Signal {
	return &dbus.Signal{Name: "org.freedesktop.systemd1.Manager.Reloading", Body: []interface{}{true}}
}

func TestHandleSignal_QuietDuringDpkg(t *testing.T) {
	lock := filepath.Join(t.TempDir(), "lock")
	holdLock(t, lock)

	s := New()
	s.dpkgLocks = []string{lock}
	alerts := make(chan notifier.Alert, 1)

	s.handleSignal(reloading(), alerts)
	if len(alerts) != 0 {
		t.Fatalf("expected no alert while dpkg is running, got %+v", <-alerts)
	}

	s.Configure(map[string]interface{}{"quiet_during_dpkg": false})
	s.handleSignal(reloading(), alerts)
	if len(alerts) != 1 {
		t.Fatal("expected an alert with quiet_during_dpkg off")
	}
}

func TestHandleSignal_AlertsWithoutDpkg(t *testing.T) {
	s := New()
	s.dpkgLocks = []string{filepath.Join(t.TempDir(), "lock")}
	alerts := make(chan notifier.Alert, 1)

	s.handleSignal(reloading(), alerts)
	if len(alerts) != 1 {
		t.Fatal("expected an alert when dpkg isn't running")
	}
}
