package porttripwires

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
)

const (
	inboundRec  = "4,1201,5678901,-;fw-510-in: IN=eth0 OUT= MAC=52:54:00:12:34:56 SRC=203.0.113.9 DST=192.0.2.1 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=0 DF PROTO=TCP SPT=51234 DPT=445 WINDOW=64240 RES=0x00 SYN URGP=0 \n SUBSYSTEM=net\n"
	outboundRec = "4,1202,5678902,-;fw-510-out: IN= OUT=eth0 SRC=192.0.2.1 DST=198.51.100.7 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=1 DF PROTO=TCP SPT=40000 DPT=4444 WINDOW=64240 RES=0x00 SYN URGP=0 UID=0 GID=0 \n"
)

func TestParseRecord(t *testing.T) {
	p := NewDefault()

	h, ok := p.parseRecord(inboundRec)
	if !ok {
		t.Fatal("inbound record not recognised")
	}
	if h.tripwire.direction != "in" || h.src != "203.0.113.9" || h.dpt != "445" || h.proto != "tcp" || h.iface != "eth0" || h.remote() != "203.0.113.9" {
		t.Errorf("bad inbound hit: %+v", h)
	}

	h, ok = p.parseRecord(outboundRec)
	if !ok {
		t.Fatal("outbound record not recognised")
	}
	if h.tripwire.direction != "out" || h.dst != "198.51.100.7" || h.dpt != "4444" || h.iface != "eth0" || h.remote() != "198.51.100.7" {
		t.Errorf("bad outbound hit: %+v", h)
	}
}

func TestParseRecord_RejectsForgeriesAndNoise(t *testing.T) {
	p := NewDefault()
	for name, rec := range map[string]string{
		// Written to /dev/kmsg from userspace: the kernel tags it LOG_USER (1)
		"user facility": "12,1203,5678903,-;fw-510-out: IN= OUT=eth0 SRC=192.0.2.1 DST=198.51.100.7 PROTO=TCP SPT=1 DPT=4444",
		// A kernel message quoting text a process chose, e.g. its name
		"prefix not at start": "6,1204,5678904,-;audit: comm=\"fw-510-out: SRC=1.2.3.4\" DST=1.2.3.4 DPT=4444",
		"other skill's rule":  "4,1205,5678905,-;fw-511-in: IN=eth0 OUT= SRC=203.0.113.9 DST=192.0.2.1 PROTO=TCP SPT=1 DPT=445",
		"bad address":         "4,1206,5678906,-;fw-510-in: IN=eth0 OUT= SRC=evil DST=192.0.2.1 PROTO=TCP SPT=1 DPT=445",
		"bad port":            "4,1207,5678907,-;fw-510-in: IN=eth0 OUT= SRC=203.0.113.9 DST=192.0.2.1 PROTO=TCP SPT=1 DPT=99999",
		"no header":           "fw-510-in: IN=eth0 OUT= SRC=203.0.113.9 DST=192.0.2.1 PROTO=TCP SPT=1 DPT=445",
		"unrelated":           "6,1208,5678908,-;usb 1-1: new high-speed USB device number 2",
	} {
		if h, ok := p.parseRecord(rec); ok {
			t.Errorf("%s: accepted as a hit: %+v", name, h)
		}
	}
}

func TestParseRecord_IPv6(t *testing.T) {
	p := NewDefault()
	rec := "4,1209,5678909,-;fw-510-in: IN=eth0 OUT= SRC=2001:0db8:0000:0000:0000:0000:0000:0009 DST=2001:0db8:0000:0000:0000:0000:0000:0001 LEN=80 PROTO=TCP SPT=51234 DPT=445 SYN URGP=0"
	if _, ok := p.parseRecord(rec); !ok {
		t.Fatal("IPv6 record not recognised")
	}
}

func runRecords(t *testing.T, p *PortTripwires, recs ...string) []notifier.Alert {
	t.Helper()
	records := make(chan string, len(recs))
	for _, r := range recs {
		records <- r
	}
	close(records)

	alerts := make(chan notifier.Alert, len(recs))
	p.watchRecords(context.Background(), records, alerts)
	close(alerts)

	var out []notifier.Alert
	for a := range alerts {
		out = append(out, a)
	}
	return out
}

func TestRun_AlertsAndSeverity(t *testing.T) {
	got := runRecords(t, NewDefault(), inboundRec, outboundRec)
	if len(got) != 2 {
		t.Fatalf("expected 2 alerts, got %d: %+v", len(got), got)
	}
	in, out := got[0], got[1]
	// Nothing should connect to a workstation on these ports
	if in.Severity != notifier.SeverityContact || !in.Acknowledge || in.Location != "port 445/tcp" || in.SkillID != 510 {
		t.Errorf("bad inbound alert: %+v", in)
	}
	if out.Severity != notifier.SeverityContact || !out.Acknowledge || out.Location != "port 4444/tcp" {
		t.Errorf("bad outbound alert: %+v", out)
	}
	// --log-uid names the user whose process connected out
	if !strings.Contains(out.Activity, "by root (uid=0)") || out.Metadata["uid"] != "0" {
		t.Errorf("outbound alert doesn't name the user: %+v", out)
	}
}

func TestUserName_UnknownUID(t *testing.T) {
	if got := userName("4294967294"); got != "uid=4294967294" {
		t.Errorf("got %q", got)
	}
}

// Every packet of a connection is logged; only the first should alert
func TestRun_CooldownPerRemoteAndPort(t *testing.T) {
	other := "4,1210,5678910,-;fw-510-in: IN=eth0 OUT= SRC=203.0.113.10 DST=192.0.2.1 PROTO=TCP SPT=51234 DPT=445 SYN"
	got := runRecords(t, NewDefault(), inboundRec, inboundRec, inboundRec, other)
	if len(got) != 2 {
		t.Fatalf("expected one alert per remote address, got %d", len(got))
	}

	p := NewDefault()
	if err := p.Configure(map[string]interface{}{"alert_cooldown": "0s"}); err != nil {
		t.Fatal(err)
	}
	if got := runRecords(t, p, inboundRec, inboundRec); len(got) != 2 {
		t.Fatalf("expected no cooldown with alert_cooldown 0s, got %d alerts", len(got))
	}
}

func TestConfigure_InvalidCooldown(t *testing.T) {
	if err := NewDefault().Configure(map[string]interface{}{"alert_cooldown": "soon"}); err == nil {
		t.Fatal("expected an error for an invalid alert_cooldown")
	}
}

func TestWatch_MissingKernelLog(t *testing.T) {
	p := NewDefault()
	p.kmsgPath = filepath.Join(t.TempDir(), "kmsg")
	if _, err := p.Watch(context.Background()); err == nil {
		t.Fatal("expected an error when the kernel log can't be opened")
	}
}

// Closing the device must unblock a pending read, or a stopped watcher would
// leak its reader. A FIFO stands in for /dev/kmsg: both are pollable.
func TestReadKmsg_CloseUnblocksRead(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "kmsg")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	w, err := os.OpenFile(fifo, os.O_RDWR, 0) // doesn't block, unlike O_WRONLY
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	r, err := os.Open(fifo)
	if err != nil {
		t.Fatal(err)
	}

	records := make(chan string, 1)
	done := make(chan struct{})
	go readKmsg(r, records, done)

	if _, err := w.WriteString(inboundRec); err != nil {
		t.Fatal(err)
	}
	select {
	case rec := <-records:
		if rec != inboundRec {
			t.Fatalf("got record %q", rec)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("record not read")
	}

	// Now blocked reading; stop it the way Watch does
	close(done)
	r.Close()
	select {
	case _, ok := <-records:
		if ok {
			t.Fatal("unexpected record")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reader still blocked after close")
	}
}
