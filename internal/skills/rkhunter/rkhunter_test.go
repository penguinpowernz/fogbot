package rkhunter

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

// scanLog is an rkhunter --check run as it appears in the log, with warnings
// for each of extra
func scanLog(extra ...string) string {
	var b strings.Builder
	b.WriteString(`[03:17:02] Running Rootkit Hunter version 1.4.6 on host
[03:17:02]
[03:17:02] Info: Start date is Sat 17 Oct 2026 03:17:02 NZDT
[03:17:02]
[03:17:02] Checking configuration file and command-line options...
[03:17:03] Info: Starting test name 'strings'
[03:17:03] Checking for strings command                     [ Found ]
[03:17:10]   /usr/bin/lwp-request                             [ Warning ]
[03:17:10] Warning: The command '/usr/bin/lwp-request' has been replaced by a script: /usr/bin/lwp-request: Perl script text executable
[03:17:10]   /usr/bin/ls                                      [ OK ]
[03:18:00] Checking for hidden files and directories       [ Warning ]
[03:18:00] Warning: Hidden directory found: /etc/.java: directory
[03:18:01] Checking /dev for suspicious file types         [ Warning ]
[03:18:01] Warning: Suspicious file types found in /dev:
[03:18:01]          /dev/shm/.org.chromium.Chromium.abc: data
[03:18:01]          /dev/shm/pulse-shm-123: data
[03:18:01]   Checking for Xzibit Rootkit                      [ Not found ]
`)
	for _, e := range extra {
		b.WriteString(e)
	}
	b.WriteString(`[03:19:31]
[03:19:31] System checks summary
[03:19:31] =====================
[03:19:31]
[03:19:31] File properties checks...
[03:19:31]   Files checked: 142
[03:19:31]   Suspect files: 1
[03:19:31]
[03:19:31] Rootkit checks...
[03:19:31]   Rootkits checked : 498
[03:19:31]   Possible rootkits: 0
[03:19:31]
[03:19:31] Info: End date is Sat 17 Oct 2026 03:19:31 NZDT
`)
	return b.String()
}

const updateLog = `[04:00:00] Running Rootkit Hunter version 1.4.6 on host
[04:00:00] Info: Start date is Sat 17 Oct 2026 04:00:00 NZDT
[04:00:01] Checking rkhunter data files...
[04:00:01] Warning: Download of 'mirrors.dat' failed
[04:00:02] Info: End date is Sat 17 Oct 2026 04:00:02 NZDT
`

func parseAll(t *testing.T, text string) []*scan {
	t.Helper()
	var p parser
	var out []*scan
	for _, l := range strings.Split(text, "\n") {
		if s := p.line(l); s != nil {
			out = append(out, s)
		}
	}
	return out
}

func TestParseScan(t *testing.T) {
	scans := parseAll(t, scanLog()+updateLog)
	if len(scans) != 1 {
		t.Fatalf("expected the check run only, got %d runs", len(scans))
	}
	want := []skills.Finding{
		{Check: "The command '/usr/bin/lwp-request' has been replaced by a script: /usr/bin/lwp-request: Perl script text executable"},
		{Check: "Hidden directory found: /etc/.java: directory"},
		{Check: "Suspicious file types found in /dev:", Lines: []string{
			"/dev/shm/.org.chromium.Chromium.abc: data",
			"/dev/shm/pulse-shm-123: data",
		}},
	}
	if !reflect.DeepEqual(scans[0].findings, want) {
		t.Errorf("findings:\n got %+v\nwant %+v", scans[0].findings, want)
	}
}

func TestParseRootkit(t *testing.T) {
	scans := parseAll(t, scanLog(`[03:18:02]   Checking for Xzibit Rootkit                    [ Warning ]
[03:18:02] Warning: Xzibit Rootkit
[03:18:02]          File '/dev/dsx' found
`))
	if len(scans) != 1 {
		t.Fatalf("expected 1 scan, got %d", len(scans))
	}
	var got *skills.Finding
	for i, f := range scans[0].findings {
		if f.Infected {
			got = &scans[0].findings[i]
		}
	}
	if got == nil || got.Check != "Xzibit Rootkit" || len(got.Lines) != 1 || got.Lines[0] != "File '/dev/dsx' found" {
		t.Fatalf("expected the Xzibit infection, got %+v", scans[0].findings)
	}
}

func TestParseRootkitCountOnly(t *testing.T) {
	text := strings.Replace(scanLog(), "Possible rootkits: 0", "Possible rootkits: 2", 1)
	scans := parseAll(t, text)
	last := scans[0].findings[len(scans[0].findings)-1]
	if !last.Infected || last.Check != "rkhunter counted 2 possible rootkits" {
		t.Errorf("expected a finding for the count, got %+v", last)
	}
}

func TestParseForgedStart(t *testing.T) {
	// A forged start line mid-scan reports what the scan found so far
	forged := "[03:18:03] Warning: Hidden file found: /dev/shm/x\n[03:18:03] Running Rootkit Hunter version 1.4.6 on host\n"
	text := strings.Replace(scanLog(), "[03:18:01] Checking /dev", forged+"[03:18:01] Checking /dev", 1)
	scans := parseAll(t, text)
	if len(scans) != 2 {
		t.Fatalf("expected the interrupted scan and the rest, got %d", len(scans))
	}
	if n := len(scans[0].findings); n != 3 {
		t.Errorf("expected the 3 findings before the forged start, got %+v", scans[0].findings)
	}
}

func TestParseForgedEnd(t *testing.T) {
	// A forged end line mid-scan doesn't hide the warnings after it
	forged := "[03:18:00] Info: End date is Sat 17 Oct 2026 03:18:00 NZDT\n"
	text := strings.Replace(scanLog(), "[03:18:00] Checking for hidden", forged+"[03:18:00] Checking for hidden", 1)
	scans := parseAll(t, text)
	var all []string
	for _, s := range scans {
		for _, f := range s.findings {
			all = append(all, f.Check)
		}
	}
	if len(all) != 3 {
		t.Errorf("expected all 3 warnings across the split scan, got %q", all)
	}
}

func TestParseUnfinishedRun(t *testing.T) {
	text := scanLog()
	text = text[:strings.Index(text, "System checks summary")]
	var p parser
	for _, l := range strings.Split(text, "\n") {
		if p.line(l) != nil {
			t.Fatal("an unfinished run was returned")
		}
	}
	if p.run == nil || !p.run.checks {
		t.Error("expected a scan in progress")
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
	dir := t.TempDir()
	h := &harness{t: t, dir: dir, log: filepath.Join(dir, "rkhunter.log")}
	if cfg == nil {
		cfg = map[string]interface{}{}
	}
	cfg["log_path"] = h.log
	r := New()
	if err := r.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	h.w = &watcher{s: r.s, report: newReport(r.s)}
	h.w.report.Start(time.Now())
	return h
}

func (h *harness) write(text string) {
	h.t.Helper()
	if err := os.WriteFile(h.log, []byte(text), 0600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) appendLog(text string) {
	h.t.Helper()
	f, err := os.OpenFile(h.log, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		h.t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(text); err != nil {
		h.t.Fatal(err)
	}
}

func titles(alerts []notifier.Alert) []string {
	var out []string
	for _, a := range alerts {
		out = append(out, a.Title+": "+a.Activity)
	}
	return out
}

func TestSeedThenNewWarning(t *testing.T) {
	h := newHarness(t, nil)
	h.write(scanLog())
	if got := h.w.poll(time.Now(), true); len(got) != 0 {
		t.Fatalf("seeding alerted: %v", titles(got))
	}

	// The same scan again (appended, as Debian's cron job does) is quiet
	h.appendLog(scanLog())
	if got := h.w.poll(time.Now(), false); len(got) != 0 {
		t.Fatalf("repeat scan alerted: %v", titles(got))
	}

	h.appendLog(scanLog("[03:18:05] Warning: Hidden file found: /etc/.evil: data\n"))
	got := h.w.poll(time.Now(), false)
	if len(got) != 1 || got[0].Activity != "Hidden file found: /etc/.evil: data" {
		t.Fatalf("expected the new warning only, got %v", titles(got))
	}
}

func TestScanSpanningPolls(t *testing.T) {
	h := newHarness(t, nil)
	h.w.poll(time.Now(), true)

	full := scanLog("[03:18:05] Warning: Hidden file found: /etc/.evil: data\n")
	cut := strings.Index(full, "Possible rootkits") + 5
	h.write(full[:cut])
	if got := h.w.poll(time.Now(), false); len(got) != 0 {
		t.Fatalf("alerted before the scan ended: %v", titles(got))
	}
	h.appendLog(full[cut:])
	got := h.w.poll(time.Now(), false)
	if len(got) != 4 || got[0].Unit != "first scan fogbot has read" {
		t.Fatalf("expected the first scan's 4 warnings, got %v", titles(got))
	}
}

func TestRewrittenLog(t *testing.T) {
	h := newHarness(t, nil)
	h.write(scanLog() + scanLog())
	h.w.poll(time.Now(), true)

	// rkhunter without --appendlog starts the log afresh; the new run is
	// shorter than what was read
	h.write(strings.Replace(scanLog("[03:18:05] Warning: Hidden file found: /etc/.evil: data\n"),
		"[03:17:02] Running", "[05:00:00] Running", 1))
	got := h.w.poll(time.Now(), false)
	if len(got) != 1 || got[0].Activity != "Hidden file found: /etc/.evil: data" {
		t.Fatalf("expected the new warning from the rewritten log, got %v", titles(got))
	}
}

func TestSeedAlertsInfection(t *testing.T) {
	h := newHarness(t, nil)
	h.write(scanLog("[03:18:02] Warning: Xzibit Rootkit\n[03:18:02]          File '/dev/dsx' found\n"))
	got := h.w.poll(time.Now(), true)
	if len(got) != 1 || got[0].Title != "Possible Rootkit (rkhunter)" {
		t.Fatalf("expected the infection at startup, got %v", titles(got))
	}

	// And again in the next scan, while it is still there
	h.appendLog(scanLog("[03:18:02] Warning: Xzibit Rootkit\n[03:18:02]          File '/dev/dsx' found\n"))
	got = h.w.poll(time.Now(), false)
	if len(got) != 1 || got[0].Unit != "also in the last scan" {
		t.Fatalf("expected the repeated infection, got %v", titles(got))
	}
}

func TestSeedUsesLastScanOnly(t *testing.T) {
	h := newHarness(t, nil)
	h.write(scanLog("[03:18:05] Warning: Hidden file found: /etc/.old: data\n") + scanLog())
	h.w.poll(time.Now(), true)

	// .old was fixed before the last scan: its return is news
	h.appendLog(scanLog("[03:18:05] Warning: Hidden file found: /etc/.old: data\n"))
	if got := h.w.poll(time.Now(), false); len(got) != 1 {
		t.Fatalf("expected the returning warning, got %v", titles(got))
	}
}

func TestSeedLastScanSetsAge(t *testing.T) {
	h := newHarness(t, map[string]interface{}{"max_scan_age": "1h"})
	h.write(scanLog())
	old := time.Now().Add(-3 * time.Hour)
	os.Chtimes(h.log, old, old)
	h.w.poll(time.Now(), true)
	a, ok := h.w.report.CheckAge(time.Now())
	if !ok || !strings.HasPrefix(a.Unit, "last scan finished") {
		t.Fatalf("expected a stale alert from the log's age, got %+v", a)
	}
}

func TestConfigure(t *testing.T) {
	r := New()
	if err := r.Configure(map[string]interface{}{"max_scan_age": "soon"}); err == nil {
		t.Error("expected an error for a bad max_scan_age")
	}
	if err := r.Configure(map[string]interface{}{"max_scan_age": "off", "repeat_warnings": true}); err != nil {
		t.Fatal(err)
	}
	if r.s.maxScanAge != 0 || !r.s.repeatWarnings {
		t.Errorf("unexpected settings: %+v", r.s)
	}
}

func TestShippedYAML(t *testing.T) {
	cfgs, err := skills.LoadAvailable("../../../usr/share/fogbot/contrib/skills-available")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cfgs {
		if c.ID != SkillID {
			continue
		}
		r := New()
		if err := r.Configure(c.Config); err != nil {
			t.Fatal(err)
		}
		if r.s != defaults() {
			t.Errorf("shipped YAML differs from the code's defaults:\n yaml %+v\n code %+v", r.s, defaults())
		}
		return
	}
	t.Fatal("skill 600 not found in shipped YAML")
}

func TestWatchNotInstalled(t *testing.T) {
	dir := t.TempDir()
	old := binaryPath
	binaryPath = filepath.Join(dir, "rkhunter")
	t.Cleanup(func() { binaryPath = old })
	r := New()
	r.Configure(map[string]interface{}{"log_path": filepath.Join(dir, "rkhunter.log")})
	if _, err := r.Watch(context.Background()); err == nil {
		t.Error("expected an error when rkhunter isn't installed")
	}
}
