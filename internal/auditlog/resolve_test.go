package auditlog

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// ids returns path's inode and dev the way a PATH record writes them
func ids(t *testing.T, path string) (string, string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	return strconv.FormatUint(st.Ino, 10), formatDev(uint64(st.Dev))
}

// fakeProc points procRoot at a directory where pid's fd links to dir
func fakeProc(t *testing.T, pid string, fd int, dir string) {
	t.Helper()
	root := t.TempDir()
	fdDir := filepath.Join(root, pid, "fd")
	os.MkdirAll(fdDir, 0755)
	if dir != "" {
		os.Symlink(dir, filepath.Join(fdDir, strconv.Itoa(fd)))
	}
	old := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = old })
}

// openatEvent feeds the records for openat(fd, name) run from cwd /tmp
func openatEvent(t *testing.T, fd, name, inode, dev string) *Event {
	t.Helper()
	tl := newTestTailer("fb-file-500")
	events := feed(tl, time.Now(),
		fmt.Sprintf(`type=SYSCALL msg=audit(1.0:20): arch=c000003e syscall=257 success=yes a0=%s pid=5678 uid=1000 comm="x" key="fb-file-500"`, fd),
		`type=CWD msg=audit(1.0:20): cwd="/tmp"`,
		fmt.Sprintf(`type=PATH msg=audit(1.0:20): item=0 name="%s" inode=%s dev=%s nametype=NORMAL mode=0100640`, name, inode, dev),
		`type=EOE msg=audit(1.0:20):`,
	)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	return events[0]
}

// openat(fd of /etc, "shadow") from /tmp used to be reported as /tmp/shadow
func TestDirfdRelativeNameResolvedFromProc(t *testing.T) {
	etc := t.TempDir()
	shadow := filepath.Join(etc, "shadow")
	os.WriteFile(shadow, nil, 0600)
	inode, dev := ids(t, shadow)
	fakeProc(t, "5678", 3, etc)

	e := openatEvent(t, "3", "shadow", inode, dev)
	if e.PathUnresolved || e.Path != shadow {
		t.Fatalf("expected %s, got path=%q unresolved=%v", shadow, e.Path, e.PathUnresolved)
	}
}

func TestDirfdRelativeNameUnresolvedWhenProcessGone(t *testing.T) {
	fakeProc(t, "5678", 3, "")
	e := openatEvent(t, "3", "shadow", "1", "")
	if !e.PathUnresolved || e.Path != "shadow" {
		t.Fatalf("expected an unresolved relative name, got path=%q unresolved=%v", e.Path, e.PathUnresolved)
	}
}

// The fd may since point somewhere else: a reused PID, or a reused fd number
func TestDirfdRelativeNameNotTrustedWhenInodeDiffers(t *testing.T) {
	other := t.TempDir()
	os.WriteFile(filepath.Join(other, "shadow"), nil, 0600)
	fakeProc(t, "5678", 3, other)

	e := openatEvent(t, "3", "shadow", "999999999", "")
	if !e.PathUnresolved {
		t.Fatalf("trusted a directory whose entry is a different file: %q", e.Path)
	}
}

func TestATFdcwdStillUsesCwd(t *testing.T) {
	e := openatEvent(t, "ffffff9c", "shadow", "1", "")
	if e.PathUnresolved || e.Path != "/tmp/shadow" {
		t.Fatalf("expected /tmp/shadow, got path=%q unresolved=%v", e.Path, e.PathUnresolved)
	}
}

func TestResolvePath(t *testing.T) {
	dir := t.TempDir()
	watchedFile := filepath.Join(dir, "passwd")
	watchedDir := filepath.Join(dir, "cron.d")
	os.WriteFile(watchedFile, nil, 0644)
	os.Mkdir(watchedDir, 0755)
	job := filepath.Join(watchedDir, "job")
	os.WriteFile(job, nil, 0644)
	roots := []string{watchedFile, watchedDir + "/"}

	fileIno, fileDev := ids(t, watchedFile)
	dirIno, dirDev := ids(t, watchedDir)
	jobIno, jobDev := ids(t, job)
	parentIno, parentDev := ids(t, dir)

	for _, tc := range []struct {
		name string
		e    Event
		want string
	}{
		{"watched file itself", Event{Path: "passwd", Inode: fileIno, Dev: fileDev}, watchedFile},
		{"entry created in watched dir", Event{Path: "job", Inode: "1", ParentInode: dirIno, ParentDev: dirDev}, job},
		{"existing entry in watched dir", Event{Path: "job", Inode: jobIno, Dev: jobDev}, job},
		{"watched file deleted", Event{Path: "passwd", Inode: "1", ParentInode: parentIno, ParentDev: parentDev}, watchedFile},
		{"nothing matches", Event{Path: "job", Inode: "1", ParentInode: "2"}, ""},
	} {
		got, ok := ResolvePath(tc.e, roots)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("%s: got %q, %v; want %q", tc.name, got, ok, tc.want)
		}
	}
}
