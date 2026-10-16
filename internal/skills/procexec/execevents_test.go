package procexec

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/penguinpowernz/fogbot/internal/notifier"
)

// execEvent builds a connector message as the kernel sends it
func execEvent(what uint32, tgid uint32) []byte {
	msg := make([]byte, procEventDataOff+8)
	le := binary.LittleEndian
	le.PutUint32(msg[nlmsgHdrLen:], cnIdxProc)
	le.PutUint32(msg[nlmsgHdrLen+4:], cnValProc)
	le.PutUint32(msg[nlmsgHdrLen+cnMsgLen:], what)
	le.PutUint32(msg[procEventDataOff:], tgid+1) // a thread
	le.PutUint32(msg[procEventDataOff+4:], tgid)
	return msg
}

func TestParseExecEvent(t *testing.T) {
	if pid, ok := parseExecEvent(execEvent(procEventExec, 4242)); !ok || pid != 4242 {
		t.Fatalf("got %d, %v; want the thread group 4242", pid, ok)
	}
	if _, ok := parseExecEvent(execEvent(0x80000000, 4242)); ok {
		t.Error("an exit event was taken for an exec")
	}
	other := execEvent(procEventExec, 4242)
	binary.LittleEndian.PutUint32(other[nlmsgHdrLen:], 7)
	if _, ok := parseExecEvent(other); ok {
		t.Error("another connector's message was taken for an exec")
	}
	if _, ok := parseExecEvent(execEvent(procEventExec, 4242)[:40]); ok {
		t.Error("a truncated message was parsed")
	}
}

// watch starts the skill with a poll interval so long that only exec events
// can catch anything started after the first scan
func watch(t *testing.T, p *ProcExec) <-chan notifier.Alert {
	t.Helper()
	p.pollInterval = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ch, _ := p.Watch(ctx)
	time.Sleep(200 * time.Millisecond) // past the first scan
	return ch
}

func expectAlert(t *testing.T, ch <-chan notifier.Alert, title, exe string) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case a := <-ch:
			if a.Title == title && strings.Contains(a.Location, exe) {
				return
			}
		case <-deadline:
			t.Fatalf("no %q alert for %s", title, exe)
		}
	}
}

// The bug: /proc was only polled, so a payload that ran and exited between
// polls (30s as shipped) was never seen
func TestExecEventsCatchShortLivedProcess(t *testing.T) {
	if _, err := listenExecs(context.Background()); err != nil {
		t.Skipf("process events connector unavailable: %v", err)
	}
	dir := t.TempDir()
	payload := filepath.Join(dir, "payload")
	copyFile(t, "/bin/sleep", payload, 0755)

	p := New()
	p.suspiciousPaths = []string{dir}
	ch := watch(t, p)

	if err := exec.Command(payload, "0.3").Run(); err != nil {
		t.Fatal(err)
	}
	expectAlert(t, ch, "Suspicious Process Execution", payload)
}

func TestMemfdExecDetected(t *testing.T) {
	fd, err := unix.MemfdCreate("fogbot-test", 0)
	if err != nil {
		t.Skipf("memfd_create: %v", err)
	}
	memfd := os.NewFile(uintptr(fd), "memfd")
	defer memfd.Close()
	src, err := os.Open("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(memfd, src)
	src.Close()

	p := New()
	ch := make(chan notifier.Alert, 1)
	cmd := exec.Command("/proc/self/fd/3", "5")
	cmd.ExtraFiles = []*os.File{memfd}
	if err := cmd.Start(); err != nil {
		t.Skipf("can't exec a memfd here: %v", err)
	}
	defer cmd.Process.Kill()
	time.Sleep(100 * time.Millisecond)

	p.checkPID(cmd.Process.Pid, ch)
	select {
	case a := <-ch:
		if a.Title != "Fileless Process Execution" || !strings.HasPrefix(a.Location, "/memfd:fogbot-test") {
			t.Fatalf("unexpected alert %+v", a)
		}
	default:
		t.Fatal("memfd execution not detected")
	}

	p = New()
	p.Configure(map[string]interface{}{"detect_memfd_exec": false})
	p.checkPID(cmd.Process.Pid, ch)
	if len(ch) != 0 {
		t.Fatal("alerted with detect_memfd_exec off")
	}
}

func copyFile(t *testing.T, from, to string, mode os.FileMode) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, mode); err != nil {
		t.Fatal(err)
	}
}
