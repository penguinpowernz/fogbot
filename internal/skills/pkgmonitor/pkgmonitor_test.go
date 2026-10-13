package pkgmonitor

import (
	"strings"
	"testing"

	"github.com/penguinpowernz/fogbot/internal/notifier"
)

func drainAlerts(ch chan notifier.Alert) []notifier.Alert {
	var alerts []notifier.Alert
	for {
		select {
		case a := <-ch:
			alerts = append(alerts, a)
		default:
			return alerts
		}
	}
}

// ---------------------------------------------------------------------------
// processLine: install
// ---------------------------------------------------------------------------

func TestProcessLine_PackageInstall(t *testing.T) {
	p := New()
	ch := make(chan notifier.Alert, 10)

	// Real dpkg.log install status line format:
	// "2024-03-15 12:00:00 status installed curl:amd64 7.88.1-10"
	line := "2024-03-15 12:00:00 status installed curl:amd64 7.88.1-10\n"
	p.processLine(line, ch)

	alerts := drainAlerts(ch)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for package install, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Title != "Package Installed" {
		t.Errorf("unexpected title: %q", a.Title)
	}
	if a.Severity != notifier.SeverityMovement {
		t.Errorf("expected severity %q, got %q", notifier.SeverityMovement, a.Severity)
	}
	if a.SkillID != SkillID {
		t.Errorf("expected SkillID %d, got %d", SkillID, a.SkillID)
	}
	if a.SkillName != SkillName {
		t.Errorf("expected SkillName %q, got %q", SkillName, a.SkillName)
	}
}

func TestProcessLine_PackageInstall_FieldsPopulated(t *testing.T) {
	p := New()
	ch := make(chan notifier.Alert, 10)

	line := "2024-03-15 12:00:00 status installed nginx:amd64 1.22.1-1\n"
	p.processLine(line, ch)

	alerts := drainAlerts(ch)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Activity == "" {
		t.Error("Activity should not be empty")
	}
	if a.Unit == "" {
		t.Error("Unit should not be empty")
	}
	if a.Equipment != "dpkg" {
		t.Errorf("expected Equipment=dpkg, got %q", a.Equipment)
	}
	if a.Location != "dpkg" {
		t.Errorf("expected Location=dpkg, got %q", a.Location)
	}
	if !strings.Contains(a.Activity, "nginx") {
		t.Errorf("expected Activity to contain package name 'nginx', got %q", a.Activity)
	}
}

// ---------------------------------------------------------------------------
// processLine: upgrade
// ---------------------------------------------------------------------------

func TestProcessLine_PackageUpgrade(t *testing.T) {
	p := New()
	ch := make(chan notifier.Alert, 10)

	// dpkg.log upgrade line:
	// "2024-03-15 12:00:00 upgrade curl:amd64 7.88.1-9 7.88.1-10"
	line := "2024-03-15 12:00:00 upgrade curl:amd64 7.88.1-9 7.88.1-10\n"
	p.processLine(line, ch)

	alerts := drainAlerts(ch)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for package upgrade, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Title != "Package Upgraded" {
		t.Errorf("unexpected title: %q", a.Title)
	}
	if a.Severity != notifier.SeverityMovement {
		t.Errorf("expected severity %q, got %q", notifier.SeverityMovement, a.Severity)
	}
	if a.SkillID != SkillID {
		t.Errorf("expected SkillID %d, got %d", SkillID, a.SkillID)
	}
}

func TestProcessLine_PackageUpgrade_BothVersionsInUnit(t *testing.T) {
	p := New()
	ch := make(chan notifier.Alert, 10)

	line := "2024-03-15 12:00:00 upgrade bash:amd64 5.1.16-1 5.2.0-1\n"
	p.processLine(line, ch)

	alerts := drainAlerts(ch)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	a := alerts[0]
	// Unit must contain both old and new version
	for _, v := range []string{"5.1.16-1", "5.2.0-1"} {
		if !strings.Contains(a.Unit, v) {
			t.Errorf("expected version %q to appear in Unit field %q", v, a.Unit)
		}
	}
}

// ---------------------------------------------------------------------------
// processLine: remove
// ---------------------------------------------------------------------------

func TestProcessLine_PackageRemove(t *testing.T) {
	p := New()
	ch := make(chan notifier.Alert, 10)

	// dpkg.log remove line:
	// "2024-03-15 12:00:00 remove curl:amd64 7.88.1-10 <none>"
	line := "2024-03-15 12:00:00 remove curl:amd64 7.88.1-10 <none>\n"
	p.processLine(line, ch)

	alerts := drainAlerts(ch)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for package remove, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Title != "Package Removed" {
		t.Errorf("unexpected title: %q", a.Title)
	}
	if a.Severity != notifier.SeverityMovement {
		t.Errorf("expected severity %q, got %q", notifier.SeverityMovement, a.Severity)
	}
	if a.SkillID != SkillID {
		t.Errorf("expected SkillID %d, got %d", SkillID, a.SkillID)
	}
}

func TestProcessLine_PackageRemove_FieldsPopulated(t *testing.T) {
	p := New()
	ch := make(chan notifier.Alert, 10)

	line := "2024-03-15 12:00:00 remove vim:amd64 2:8.2.3995-1 <none>\n"
	p.processLine(line, ch)

	alerts := drainAlerts(ch)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	a := alerts[0]
	if !strings.Contains(a.Activity, "vim") {
		t.Errorf("expected Activity to contain package name 'vim', got %q", a.Activity)
	}
	if !strings.Contains(a.Unit, "amd64") {
		t.Errorf("expected Unit to contain arch 'amd64', got %q", a.Unit)
	}
}

// ---------------------------------------------------------------------------
// processLine: irrelevant lines produce no alerts
// ---------------------------------------------------------------------------

func TestProcessLine_NonMatchingStatusLine_NoAlert(t *testing.T) {
	p := New()
	ch := make(chan notifier.Alert, 10)

	// A dpkg.log status line that is not "installed" (e.g. half-configured)
	line := "2024-03-15 12:00:00 status half-configured curl:amd64 7.88.1-10\n"
	p.processLine(line, ch)

	if len(drainAlerts(ch)) != 0 {
		t.Error("expected no alert for non-matching dpkg log line")
	}
}

func TestProcessLine_EmptyLine_NoAlert(t *testing.T) {
	p := New()
	ch := make(chan notifier.Alert, 10)

	p.processLine("", ch)
	p.processLine("\n", ch)

	if len(drainAlerts(ch)) != 0 {
		t.Error("expected no alert for empty log line")
	}
}

func TestProcessLine_UnrelatedLogLine_NoAlert(t *testing.T) {
	p := New()
	ch := make(chan notifier.Alert, 10)

	line := "Apr 26 10:00:01 host kernel: [12345.678] eth0: renamed from veth1234\n"
	p.processLine(line, ch)

	if len(drainAlerts(ch)) != 0 {
		t.Error("expected no alert for unrelated log line")
	}
}

// ---------------------------------------------------------------------------
// One line produces at most one alert
// ---------------------------------------------------------------------------

func TestProcessLine_OneLineOneAlert(t *testing.T) {
	p := New()
	ch := make(chan notifier.Alert, 10)

	line := "2024-03-15 12:00:00 status installed openssh-server:amd64 1:9.2p1-2\n"
	p.processLine(line, ch)

	alerts := drainAlerts(ch)
	if len(alerts) > 1 {
		t.Errorf("a single log line should produce at most 1 alert, got %d", len(alerts))
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestConfigure_CustomLogPath(t *testing.T) {
	p := New()
	cfg := map[string]interface{}{
		"dpkg_log_path": "/tmp/test_dpkg.log",
	}
	if err := p.Configure(cfg); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	if p.logPath != "/tmp/test_dpkg.log" {
		t.Errorf("expected custom log path, got %q", p.logPath)
	}
}

func TestConfigure_DefaultLogPath(t *testing.T) {
	p := New()
	if p.logPath != "/var/log/dpkg.log" {
		t.Errorf("expected default log path /var/log/dpkg.log, got %q", p.logPath)
	}
}

func TestConfigure_EmptyConfig_PreservesDefaults(t *testing.T) {
	p := New()
	original := p.logPath
	if err := p.Configure(map[string]interface{}{}); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	if p.logPath != original {
		t.Error("empty config should not change logPath")
	}
}

// ---------------------------------------------------------------------------
// Skill interface metadata
// ---------------------------------------------------------------------------

func TestMetadata(t *testing.T) {
	p := New()
	if p.ID() != SkillID {
		t.Errorf("ID() = %d, want %d", p.ID(), SkillID)
	}
	if p.Name() != SkillName {
		t.Errorf("Name() = %q, want %q", p.Name(), SkillName)
	}
	if p.Description() == "" {
		t.Error("Description() should not be empty")
	}
	if p.Why() == "" {
		t.Error("Why() should not be empty")
	}
	if len(p.Requires()) == 0 {
		t.Error("Requires() should list at least one requirement")
	}
	if len(p.Tags()) == 0 {
		t.Error("Tags() should list at least one tag")
	}
}

func TestEnabledState(t *testing.T) {
	p := New()
	if p.Enabled() {
		t.Error("skill should start disabled")
	}
	p.SetEnabled(true)
	if !p.Enabled() {
		t.Error("skill should be enabled after SetEnabled(true)")
	}
	p.SetEnabled(false)
	if p.Enabled() {
		t.Error("skill should be disabled after SetEnabled(false)")
	}
}

func TestDeduceCommandsAndCheckSystemState(t *testing.T) {
	p := New()
	cmds, err := p.DeduceCommands(nil)
	if err != nil {
		t.Fatalf("DeduceCommands error: %v", err)
	}
	if len(cmds) != 0 {
		t.Errorf("expected no system commands for pkg-monitor, got %d", len(cmds))
	}
	ok, err := p.CheckSystemState()
	if err != nil {
		t.Fatalf("CheckSystemState error: %v", err)
	}
	if !ok {
		t.Error("CheckSystemState should always return true for pkg-monitor")
	}
}
