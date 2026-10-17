package skills

import (
	"strings"
	"testing"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
)

func TestReportableOnlyNewWarnings(t *testing.T) {
	prev := []Finding{
		{Check: "sniffer", Lines: []string{"eth0: PACKET SNIFFER(dhclient)"}},
		{Check: "Hidden directory found: /etc/.java"},
	}
	cur := []Finding{
		{Check: "sniffer", Lines: []string{"eth0: PACKET SNIFFER(dhclient)", "eth0: PACKET SNIFFER(/tmp/x)"}},
		{Check: "Hidden directory found: /etc/.java"},
		{Check: "Hidden directory found: /etc/.x"},
	}
	got := Reportable(prev, cur, ReportOptions{Warnings: true, Infections: true})
	if len(got) != 2 {
		t.Fatalf("expected 2 findings, got %+v", got)
	}
	if got[0].Check != "sniffer" || len(got[0].Lines) != 1 || got[0].Lines[0] != "eth0: PACKET SNIFFER(/tmp/x)" || !got[0].New {
		t.Errorf("expected only the new sniffer line, got %+v", got[0])
	}
	if got[1].Check != "Hidden directory found: /etc/.x" || !got[1].New {
		t.Errorf("expected the new check, got %+v", got[1])
	}
}

func TestReportableInfectionsEveryTime(t *testing.T) {
	inf := Finding{Check: "bindshell", Lines: []string{"INFECTED (PORTS: 465)"}, Infected: true}
	got := Reportable([]Finding{inf}, []Finding{inf}, ReportOptions{Warnings: true, Infections: true})
	if len(got) != 1 || got[0].New || len(got[0].Lines) != 1 {
		t.Fatalf("expected the repeated infection in full, got %+v", got)
	}
	if got := Reportable(nil, []Finding{inf}, ReportOptions{Warnings: true}); len(got) != 0 {
		t.Errorf("infections off: expected nothing, got %+v", got)
	}
}

func TestReportableRepeatWarnings(t *testing.T) {
	w := Finding{Check: "Hidden directory found: /etc/.java"}
	opts := ReportOptions{Warnings: true, RepeatWarnings: true}
	got := Reportable([]Finding{w}, []Finding{w}, opts)
	if len(got) != 1 || got[0].New {
		t.Fatalf("expected the repeated warning, not new, got %+v", got)
	}
	if got := Reportable(nil, []Finding{w}, ReportOptions{Infections: true}); len(got) != 0 {
		t.Errorf("warnings off: expected nothing, got %+v", got)
	}
}

func TestReportableNoPrevIsAllNew(t *testing.T) {
	cur := []Finding{{Check: "a"}, {Check: "b", Lines: []string{"x"}}}
	got := Reportable(nil, cur, ReportOptions{Warnings: true})
	if len(got) != 2 || !got[0].New || !got[1].New {
		t.Fatalf("expected everything new, got %+v", got)
	}
}

func TestConfigDuration(t *testing.T) {
	cases := []struct {
		raw     interface{}
		want    time.Duration
		wantErr bool
	}{
		{"48h", 48 * time.Hour, false},
		{"off", 0, false},
		{"0", 0, false},
		{0, 0, false},
		{"soon", time.Hour, true},
		{"-1h", time.Hour, true},
		{12, time.Hour, true},
	}
	for _, c := range cases {
		got, err := ConfigDuration(map[string]interface{}{"k": c.raw}, "k", time.Hour)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("%v: got %v, %v; want %v, error %v", c.raw, got, err, c.want, c.wantErr)
		}
	}
	if got, err := ConfigDuration(nil, "k", time.Hour); got != time.Hour || err != nil {
		t.Errorf("absent: got %v, %v", got, err)
	}
}

func TestShortDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		48 * time.Hour:   "48h",
		90 * time.Minute: "1h30m",
		30 * time.Second: "30s",
		5 * time.Minute:  "5m",
	} {
		if got := ShortDuration(d); got != want {
			t.Errorf("%v: got %q, want %q", d, got, want)
		}
	}
}

func newTestReport() *ScanReport {
	return &ScanReport{
		SkillID:   600,
		SkillName: "rkhunter",
		Scanner:   "rkhunter",
		Location:  "/var/log/rkhunter.log",
		Options:   ReportOptions{Warnings: true, Infections: true},
		MaxAge:    48 * time.Hour,
		StaleHint: "check cron",
	}
}

func TestScanReportSeedThenScan(t *testing.T) {
	r := newTestReport()
	start := time.Now()
	r.Start(start)

	known := Finding{Check: "Hidden directory found: /etc/.java"}
	inf := Finding{Check: "Xzibit Rootkit", Lines: []string{"File '/dev/dsx' found"}, Infected: true}

	alerts := r.Seed([]Finding{known, inf}, start)
	if len(alerts) != 1 || alerts[0].Title != "Possible Rootkit (rkhunter)" || alerts[0].Unit != "in the last scan before fogbot started" {
		t.Fatalf("seed: expected only the infection, got %+v", alerts)
	}

	fresh := Finding{Check: "The command '/usr/bin/x' has been replaced by a script"}
	alerts = r.Scan([]Finding{known, fresh}, start)
	if len(alerts) != 1 || alerts[0].Title != "rkhunter Warning" || alerts[0].Unit != "new since the last scan" {
		t.Fatalf("scan: expected only the new warning, got %+v", alerts)
	}
	if alerts[0].Severity != notifier.SeverityContact || alerts[0].Activity != fresh.Check {
		t.Errorf("unexpected alert: %+v", alerts[0])
	}
}

func TestScanReportFirstScan(t *testing.T) {
	r := newTestReport()
	r.Start(time.Now())
	alerts := r.Scan([]Finding{{Check: "a"}}, time.Now())
	if len(alerts) != 1 || alerts[0].Unit != "first scan fogbot has read" {
		t.Fatalf("expected the first scan's warning, got %+v", alerts)
	}
}

func TestScanReportCapsAlerts(t *testing.T) {
	r := newTestReport()
	r.Start(time.Now())
	var cur []Finding
	for _, c := range "abcdefgh" {
		cur = append(cur, Finding{Check: string(c)})
	}
	alerts := r.Scan(cur, time.Now())
	if len(alerts) != maxScanAlerts+1 {
		t.Fatalf("expected %d alerts, got %d", maxScanAlerts+1, len(alerts))
	}
	last := alerts[len(alerts)-1]
	if last.Title != "More rkhunter Findings" || last.Metadata["count"] != "3" || last.Equipment != "f | g | h" {
		t.Errorf("unexpected summary: %+v", last)
	}
}

func TestScanReportCheckAge(t *testing.T) {
	r := newTestReport()
	start := time.Now()
	r.Start(start)

	if _, ok := r.CheckAge(start.Add(47 * time.Hour)); ok {
		t.Fatal("alerted before max age")
	}
	a, ok := r.CheckAge(start.Add(49 * time.Hour))
	if !ok || a.Title != "[DEADMAN] rkhunter Not Scanning" || !a.Acknowledge || a.Equipment != "check cron" {
		t.Fatalf("expected stale alert, got %+v", a)
	}
	if !strings.Contains(a.Activity, "48h") || !strings.HasPrefix(a.Unit, "no scan seen since fogbot started") {
		t.Errorf("unexpected stale alert text: %+v", a)
	}
	if _, ok := r.CheckAge(start.Add(50 * time.Hour)); ok {
		t.Error("alerted twice for the same stale spell")
	}

	r.Scan(nil, start.Add(51*time.Hour))
	a, ok = r.CheckAge(start.Add(51 * time.Hour))
	if !ok || a.Severity != notifier.SeverityNominal || a.Title != "[DEADMAN] Recovered: rkhunter Not Scanning" {
		t.Fatalf("expected recovery, got %+v", a)
	}

	r.MaxAge = 0
	if _, ok := r.CheckAge(start.Add(1000 * time.Hour)); ok {
		t.Error("alerted with max age off")
	}
}

func TestCleanText(t *testing.T) {
	if got := CleanText("a\nb‮c"); got != "a?b?c" {
		t.Errorf("got %q", got)
	}
}
