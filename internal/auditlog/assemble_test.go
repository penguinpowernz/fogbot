package auditlog

import (
	"testing"
	"time"
)

func newTestTailer(keys ...string) *Tailer {
	t := &Tailer{subscribers: make(map[string][]chan<- Event)}
	for _, k := range keys {
		t.Subscribe(k, make(chan Event, 1))
	}
	return t
}

func feed(t *Tailer, now time.Time, lines ...string) []*Event {
	var out []*Event
	for _, l := range lines {
		out = append(out, t.handleLine(l, now)...)
	}
	return out
}

// Real auditd output (ENRICHED format) for `cd /etc && cat shadow` with
// `auditctl -w /etc/shadow -p rwa -k fb-file-500`. Only the SYSCALL record has the key.
func TestHandleLine_FileReadAssemblesPathFromPathRecord(t *testing.T) {
	tl := newTestTailer("fb-file-500")
	now := time.Now()
	events := feed(tl, now,
		`type=SYSCALL msg=audit(1710547200.123:456): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffc a2=0 a3=0 items=1 ppid=1234 pid=5678 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="cat" exe="/usr/bin/cat" subj=unconfined key="fb-file-500"`+"\x1d"+`ARCH=x86_64 SYSCALL=openat AUID="robert" UID="root"`,
		`type=CWD msg=audit(1710547200.123:456): cwd="/etc"`,
		`type=PATH msg=audit(1710547200.123:456): item=0 name="shadow" inode=1234 dev=08:01 mode=0100640 ouid=0 ogid=42 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0`,
		`type=PROCTITLE msg=audit(1710547200.123:456): proctitle=63617400736861646F77`,
	)
	if len(events) != 0 {
		t.Fatalf("event emitted before EOE: %+v", events)
	}

	events = feed(tl, now, `type=EOE msg=audit(1710547200.123:456):`)
	if len(events) != 1 {
		t.Fatalf("expected 1 event after EOE, got %d", len(events))
	}
	e := events[0]
	if e.Path != "/etc/shadow" || e.Name != "shadow" {
		t.Errorf("expected path /etc/shadow, got path=%q name=%q", e.Path, e.Name)
	}
	if e.Syscall != "openat" {
		t.Errorf("expected syscall openat, got %q", e.Syscall)
	}
	if e.UID != "0" || e.Comm != "cat" || e.Exe != "/usr/bin/cat" || e.Cwd != "/etc" {
		t.Errorf("unexpected process fields: %+v", e)
	}
	if e.Metadata["mode"] != "0100640" {
		t.Errorf("expected mode from PATH record, got %q", e.Metadata["mode"])
	}
}

// RAW format logs have only the syscall number
func TestHandleLine_RawFormatSyscallNumberTranslated(t *testing.T) {
	tl := newTestTailer("fb-file-500")
	events := feed(tl, time.Now(),
		`type=SYSCALL msg=audit(1.0:7): arch=c000003e syscall=263 success=yes exit=0 uid=0 comm="rm" exe="/usr/bin/rm" key="fb-file-500"`,
		`type=PATH msg=audit(1.0:7): item=0 name="/etc/" nametype=PARENT mode=040755`,
		`type=PATH msg=audit(1.0:7): item=1 name="/etc/passwd" nametype=DELETE mode=0100644`,
		`type=EOE msg=audit(1.0:7):`,
	)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Syscall != "unlinkat" {
		t.Errorf("expected unlinkat, got %q", events[0].Syscall)
	}
	if events[0].Path != "/etc/passwd" {
		t.Errorf("expected the DELETE item rather than its parent, got %q", events[0].Path)
	}
}

// A file created in a watched directory: PARENT then CREATE items
func TestHandleLine_DirWatchPicksCreatedEntry(t *testing.T) {
	tl := newTestTailer("fb-dir-540")
	events := feed(tl, time.Now(),
		`type=SYSCALL msg=audit(1.0:8): arch=c000003e syscall=257 success=yes uid=0 comm="touch" exe="/usr/bin/touch" key="fb-dir-540"`,
		`type=CWD msg=audit(1.0:8): cwd="/root"`,
		`type=PATH msg=audit(1.0:8): item=0 name="/usr/local/bin/" nametype=PARENT mode=040755`,
		`type=PATH msg=audit(1.0:8): item=1 name="/usr/local/bin/evil" nametype=CREATE mode=0100644`,
		`type=EOE msg=audit(1.0:8):`,
	)
	if len(events) != 1 || events[0].Path != "/usr/local/bin/evil" {
		t.Fatalf("expected /usr/local/bin/evil, got %+v", events)
	}
}

// auditd writes names containing spaces as unquoted hex
func TestHandleLine_HexEncodedNameDecoded(t *testing.T) {
	tl := newTestTailer("fb-dir-540")
	events := feed(tl, time.Now(),
		`type=SYSCALL msg=audit(1.0:9): arch=c000003e syscall=257 success=yes uid=0 comm="touch" key="fb-dir-540"`,
		`type=CWD msg=audit(1.0:9): cwd="/tmp"`,
		`type=PATH msg=audit(1.0:9): item=1 name=6120622E7368 nametype=CREATE mode=0100644`,
		`type=EOE msg=audit(1.0:9):`,
	)
	if len(events) != 1 || events[0].Path != "/tmp/a b.sh" {
		t.Fatalf("expected /tmp/a b.sh, got %+v", events)
	}
}

func TestHandleLine_IgnoresUnsubscribedAndUnkeyed(t *testing.T) {
	tl := newTestTailer("fb-file-500")
	events := feed(tl, time.Now(),
		`type=SYSCALL msg=audit(1.0:10): arch=c000003e syscall=257 uid=0 key="someone-else"`,
		`type=PATH msg=audit(1.0:10): item=0 name="/etc/shadow" nametype=NORMAL`,
		`type=EOE msg=audit(1.0:10):`,
		`type=SYSCALL msg=audit(1.0:11): arch=c000003e syscall=257 uid=0 key=(null)`,
		`type=EOE msg=audit(1.0:11):`,
	)
	if len(events) != 0 {
		t.Fatalf("expected no events, got %+v", events)
	}
}

// Without an EOE the event is still emitted after the timeout
func TestHandleLine_FlushesWithoutEOE(t *testing.T) {
	tl := newTestTailer("fb-file-500")
	start := time.Now()
	feed(tl, start,
		`type=SYSCALL msg=audit(1.0:12): arch=c000003e syscall=257 uid=0 key="fb-file-500"`,
		`type=PATH msg=audit(1.0:12): item=0 name="/etc/shadow" nametype=NORMAL`,
	)
	if got := tl.flushStale(start.Add(pendingTimeout / 2)); len(got) != 0 {
		t.Fatalf("flushed too early: %+v", got)
	}
	got := tl.flushStale(start.Add(pendingTimeout))
	if len(got) != 1 || got[0].Path != "/etc/shadow" {
		t.Fatalf("expected stale event for /etc/shadow, got %+v", got)
	}
}

// comm and exe are chosen by the process, so one named `xkey=` must not hide
// the real rule key from the parser
func TestHandleLine_KeyInCommDoesNotHideRuleKey(t *testing.T) {
	tl := newTestTailer("fb-file-500")
	now := time.Now()
	events := feed(tl, now,
		`type=SYSCALL msg=audit(1710547200.123:457): arch=c000003e syscall=257 success=yes exit=3 items=1 ppid=1 pid=2 auid=1000 uid=0 comm="xkey=" exe="/tmp/key=" subj=unconfined key="fb-file-500"`,
		`type=PATH msg=audit(1710547200.123:457): item=0 name="/etc/shadow" nametype=NORMAL`,
		`type=EOE msg=audit(1710547200.123:457):`,
	)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].RuleKey != "fb-file-500" || events[0].Comm != "xkey=" {
		t.Errorf("unexpected event: key=%q comm=%q", events[0].RuleKey, events[0].Comm)
	}
}
