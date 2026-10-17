package chkrootkit

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
)

// logToday is chkrootkit 0.58 output as Debian's chkrootkit-daily writes it,
// after its default FILTER, with lines from extra added to the sniffer check
func logToday(extra ...string) string {
	return `ROOTDIR is ` + "`/'" + `
Checking ` + "`amd'" + `...                                           not found
Checking ` + "`basename'" + `...                                      not infected
Checking ` + "`tcpdump'" + `...                                       RTNETLINK answers: Invalid argument
Checking ` + "`aliens'" + `...                                        started
Searching for suspicious files and dirs...                  WARNING

WARNING: The following suspicious files and directories were found:
/usr/lib/debug/.dwz
/usr/lib/ruby/vendor_ruby/rubygems/ssl_certs/.document

Searching for OBSD rootkit v1...                            not tested
Searching for Linux.Xor.DDoS...                             WARNING

WARNING: Possible Linux.Xor.DDoS installed:
/tmp/go-build360080069/b001/exe/a.out

Searching for Kovid LKM rootkit...                          not tested
Checking ` + "`aliens'" + `...                                        finished
Checking ` + "`bindshell'" + `...                                     RTNETLINK answers: Invalid argument
RTNETLINK answers: Invalid argument
Checking ` + "`lkm'" + `...                                           chkproc: nothing detected
Checking ` + "`sniffer'" + `...                                       WARNING

WARNING: Output from ifpromisc:
lo: not promisc and no packet sniffer sockets
<interface>: PACKET SNIFFER([systemd-networkd|dhclient|dhcpd|dhcpcd|wpa_supplicant|NetworkManager]{PID})
<interface>: PACKET SNIFFER([systemd-networkd|dhclient|dhcpd|dhcpcd|wpa_supplicant|NetworkManager]{PID})
docker0: not promisc and no packet sniffer sockets
` + strings.Join(extra, "") + `
Checking ` + "`scalper'" + `...                                       RTNETLINK answers: Invalid argument
Checking ` + "`OSX_RSPLUG'" + `...                                    not tested
`
}

func TestParse(t *testing.T) {
	want := []skills.Finding{
		{Check: "suspicious files and dirs", Lines: []string{
			"WARNING: The following suspicious files and directories were found:",
			"/usr/lib/debug/.dwz",
			"/usr/lib/ruby/vendor_ruby/rubygems/ssl_certs/.document",
		}},
		{Check: "Linux.Xor.DDoS", Lines: []string{
			"WARNING: Possible Linux.Xor.DDoS installed:",
			"/tmp/go-build360080069/b001/exe/a.out",
		}},
		{Check: "sniffer", Lines: []string{
			"WARNING: Output from ifpromisc:",
			"<interface>: PACKET SNIFFER([systemd-networkd|dhclient|dhcpd|dhcpcd|wpa_supplicant|NetworkManager]{PID})",
		}},
	}
	got := parse([]byte(logToday()))
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings:\n got %+v\nwant %+v", got, want)
	}
}

func TestParseInfected(t *testing.T) {
	text := `Checking ` + "`ls'" + `...                                            INFECTED
Checking ` + "`bindshell'" + `...                                     WARNING

WARNING: Potential bindshell installed: infected ports: 465

Checking ` + "`lkm'" + `...                                           You have     1 process hidden for readdir command
chkproc: Warning: Possible LKM Trojan installed
Searching for Linux.Proxy.1.0...                            INFECTED: Possible Malicious Linux.Proxy.10 installed in /etc/passwd
Checking ` + "`chkutmp'" + `...                                       The tty of the following user process(es) were not found
 in /var/run/utmp !
! RUID          PID TTY    CMD
! robert       {PID} pts/3  tmux
chkutmp: nothing deleted
`
	want := []skills.Finding{
		{Check: "ls", Lines: []string{"INFECTED"}, Infected: true},
		{Check: "bindshell", Lines: []string{"WARNING: Potential bindshell installed: infected ports: 465"}},
		{Check: "lkm", Lines: []string{
			"You have     1 process hidden for readdir command",
			"chkproc: Warning: Possible LKM Trojan installed",
		}},
		{Check: "Linux.Proxy.1.0", Lines: []string{"INFECTED: Possible Malicious Linux.Proxy.10 installed in /etc/passwd"}, Infected: true},
		{Check: "chkutmp", Lines: []string{
			"The tty of the following user process(es) were not found",
			"in /var/run/utmp !",
			"! RUID          PID TTY    CMD",
			"! robert       {PID} pts/3  tmux",
			"chkutmp: nothing deleted",
		}},
	}
	got := parse([]byte(text))
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings:\n got %+v\nwant %+v", got, want)
	}
}

func TestParseForgedHeader(t *testing.T) {
	// A file in /tmp named "x\nChecking `ls'... not infected" puts a fake
	// clean check in front of the files listed after it
	text := `Searching for Linux.Xor.DDoS...                             WARNING

WARNING: Possible Linux.Xor.DDoS installed:
/tmp/x
Checking ` + "`ls'" + `...                                            not infected
/tmp/.hidden/implant

Searching for Kovid LKM rootkit...                          not tested
`
	got := parse([]byte(text))
	if len(got) != 2 || got[1].Check != "ls" || len(got[1].Lines) != 2 || got[1].Lines[1] != "/tmp/.hidden/implant" {
		t.Fatalf("expected the implant to be reported under the forged check, got %+v", got)
	}
}

func TestParseQuiet(t *testing.T) {
	// With -q chkrootkit prints only what it found, with no check names
	got := parse([]byte("WARNING: Output from ifpromisc:\neth0: PACKET SNIFFER(/usr/sbin/tcpdump[123])\n"))
	if len(got) != 1 || got[0].Check != "chkrootkit" || len(got[0].Lines) != 2 {
		t.Errorf("expected one finding for the whole output, got %+v", got)
	}
}

type harness struct {
	t   *testing.T
	dir string
	log string
	w   *watcher
}

func newHarness(t *testing.T, cfg map[string]interface{}) *harness {
	t.Helper()
	oldSettle, oldProc, oldUID := settle, procRoot, scannerUID
	settle = 0
	procRoot = filepath.Join(t.TempDir(), "proc")
	scannerUID = uint32(os.Getuid())
	os.MkdirAll(procRoot, 0755)
	t.Cleanup(func() { settle, procRoot, scannerUID = oldSettle, oldProc, oldUID })

	dir := t.TempDir()
	h := &harness{t: t, dir: dir, log: filepath.Join(dir, "log.today")}
	if cfg == nil {
		cfg = map[string]interface{}{}
	}
	cfg["log_path"] = h.log
	c := New()
	if err := c.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	h.w = &watcher{s: c.s, report: &skills.ScanReport{
		SkillID: SkillID, SkillName: SkillName, Scanner: "chkrootkit", Location: h.log,
		Options: skills.ReportOptions{Warnings: c.s.alertWarning, Infections: c.s.alertInfected},
		MaxAge:  c.s.maxScanAge,
	}}
	h.w.report.Start(time.Now())
	return h
}

// write writes a scan's output as chkrootkit-daily does, as a new file
// whose time differs from the last
func (h *harness) write(text string, at time.Time) {
	h.t.Helper()
	tmp := h.log + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0644); err != nil {
		h.t.Fatal(err)
	}
	os.Chtimes(tmp, at, at)
	os.Rename(tmp, h.log)
}

func (h *harness) proc(pid, cmdline string) {
	h.t.Helper()
	dir := filepath.Join(procRoot, pid)
	os.MkdirAll(dir, 0755)
	os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0644)
}

func titles(alerts []notifier.Alert) []string {
	var out []string
	for _, a := range alerts {
		out = append(out, a.Title+": "+a.Activity+" / "+a.Equipment)
	}
	return out
}

func TestSeedThenNewLines(t *testing.T) {
	h := newHarness(t, nil)
	day := time.Now().Add(-time.Hour)
	h.write(logToday(), day)
	if got := h.w.poll(time.Now(), true); len(got) != 0 {
		t.Fatalf("seeding alerted: %v", titles(got))
	}
	if got := h.w.poll(time.Now(), false); len(got) != 0 {
		t.Fatalf("an unchanged log alerted: %v", titles(got))
	}

	// The next day's identical scan is quiet
	h.write(logToday(), day.Add(time.Minute))
	if got := h.w.poll(time.Now(), false); len(got) != 0 {
		t.Fatalf("an identical scan alerted: %v", titles(got))
	}

	// A new sniffer is reported, without what was already known
	h.write(logToday("eth0: PACKET SNIFFER(/tmp/.x/sniff[4242])\n"), day.Add(2*time.Minute))
	got := h.w.poll(time.Now(), false)
	if len(got) != 1 || got[0].Activity != "sniffer" || got[0].Equipment != "eth0: PACKET SNIFFER(/tmp/.x/sniff[4242])" {
		t.Fatalf("expected the new sniffer line only, got %v", titles(got))
	}
}

func TestWaitsForChkrootkit(t *testing.T) {
	h := newHarness(t, nil)
	h.w.poll(time.Now(), true)

	h.proc("1", "/sbin/init\x00")
	h.proc("4242", "/bin/sh\x00/usr/sbin/chkrootkit-daily\x00")
	h.write(logToday(), time.Now().Add(-time.Hour))
	if got := h.w.poll(time.Now(), false); len(got) != 0 || h.w.report.Scanned() {
		t.Fatalf("read the log while chkrootkit-daily ran: %v", titles(got))
	}

	os.RemoveAll(filepath.Join(procRoot, "4242"))
	h.proc("4243", "/usr/sbin/chkrootkit\x00-q\x00")
	if got := h.w.poll(time.Now(), false); len(got) != 0 || h.w.report.Scanned() {
		t.Fatalf("read the log while chkrootkit ran: %v", titles(got))
	}

	os.RemoveAll(filepath.Join(procRoot, "4243"))
	got := h.w.poll(time.Now(), false)
	if len(got) != 3 || got[0].Unit != "first scan fogbot has read" {
		t.Fatalf("expected the first scan's 3 findings, got %v", titles(got))
	}
}

func TestWaitsToSettle(t *testing.T) {
	h := newHarness(t, nil)
	settle = time.Minute
	h.write(logToday(), time.Now())
	h.w.poll(time.Now(), false)
	if h.w.report.Scanned() {
		t.Fatal("read a log still being written")
	}
	if got := h.w.poll(time.Now().Add(2*time.Minute), false); len(got) != 3 {
		t.Fatalf("expected the scan once settled, got %v", titles(got))
	}
}

func TestInfectionEveryScan(t *testing.T) {
	h := newHarness(t, nil)
	inf := "Checking `ps'...                                            INFECTED\n"
	h.write(logToday()+inf, time.Now().Add(-time.Hour))
	got := h.w.poll(time.Now(), true)
	if len(got) != 1 || got[0].Title != "Possible Rootkit (chkrootkit)" {
		t.Fatalf("expected the infection at startup, got %v", titles(got))
	}
	h.write(logToday()+inf, time.Now().Add(-time.Minute))
	got = h.w.poll(time.Now(), false)
	if len(got) != 1 || got[0].Unit != "also in the last scan" {
		t.Fatalf("expected the infection again, got %v", titles(got))
	}
}

func TestStaleFromLogTime(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"max_scan_age": "24h"})
	h.write(logToday(), time.Now().Add(-25*time.Hour))
	h.w.poll(time.Now(), true)
	if a, ok := h.w.report.CheckAge(time.Now()); !ok || !strings.HasPrefix(a.Unit, "last scan finished") {
		t.Fatalf("expected a stale alert from the log's time, got %+v", a)
	}
}

func TestRunning(t *testing.T) {
	h := newHarness(t, nil)
	h.proc("10", "/usr/bin/chkrootkit-ish\x00")
	h.proc("11", "vim\x00/usr/sbin/chkrootkit\x00")
	h.proc("self", "/usr/sbin/chkrootkit\x00")
	if running() {
		t.Error("matched an editor opening chkrootkit, or a non-pid directory")
	}
	h.proc("12", "/bin/sh\x00/usr/sbin/chkrootkit\x00")
	if !running() {
		t.Error("missed chkrootkit run by sh")
	}

	// Someone else's process called chkrootkit doesn't hold up reading
	scannerUID = uint32(os.Getuid()) + 1
	if running() {
		t.Error("counted a chkrootkit not run by the scanner's user")
	}
}

func TestConfigure(t *testing.T) {
	c := New()
	if err := c.Configure(map[string]interface{}{"alert_on_infected": "yes"}); err == nil {
		t.Error("expected an error for a non-boolean")
	}
	if err := c.Configure(map[string]interface{}{"max_scan_age": "off", "alert_on_suspicious": false}); err != nil {
		t.Fatal(err)
	}
	if c.s.maxScanAge != 0 || c.s.alertWarning {
		t.Errorf("unexpected settings: %+v", c.s)
	}
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
		c := New()
		if err := c.Configure(cfg.Config); err != nil {
			t.Fatal(err)
		}
		if c.s != defaults() {
			t.Errorf("shipped YAML differs from the code's defaults:\n yaml %+v\n code %+v", c.s, defaults())
		}
		return
	}
	t.Fatal("skill 610 not found in shipped YAML")
}

func TestWatchNotInstalled(t *testing.T) {
	c := New()
	c.Configure(map[string]interface{}{"log_path": filepath.Join(t.TempDir(), "missing", "log.today")})
	if _, err := c.Watch(context.Background()); err == nil {
		t.Error("expected an error when chkrootkit's log directory doesn't exist")
	}
}
