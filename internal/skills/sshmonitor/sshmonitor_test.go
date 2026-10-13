package sshmonitor

import (
	"testing"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
)

// drainAlerts reads all alerts already buffered in the channel without blocking.
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

func newTestMonitor() *SSHMonitor {
	m := New()
	// Fast brute-force window so tests don't need to manipulate real time
	m.bruteForceThreshold = 3
	m.bruteForceWindow = 10 * time.Second
	return m
}

// ---------------------------------------------------------------------------
// processLine: successful logins
// ---------------------------------------------------------------------------

func TestProcessLine_SuccessfulLogin_NewIP_ProducesAlert(t *testing.T) {
	m := newTestMonitor()
	ch := make(chan notifier.Alert, 10)

	line := `Apr 26 10:00:01 host sshd[1234]: Accepted publickey for alice from 1.2.3.4 port 54321 ssh2`
	m.processLine(line, ch)

	alerts := drainAlerts(ch)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for new-IP login, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Title != "SSH Login from New IP" {
		t.Errorf("unexpected title: %q", a.Title)
	}
	if a.Severity != notifier.SeverityContact {
		t.Errorf("expected severity %q, got %q", notifier.SeverityContact, a.Severity)
	}
	if a.SkillID != SkillID {
		t.Errorf("expected SkillID %d, got %d", SkillID, a.SkillID)
	}
	if a.SkillName != SkillName {
		t.Errorf("expected SkillName %q, got %q", SkillName, a.SkillName)
	}
	if !a.Acknowledge {
		t.Error("expected Acknowledge=true for new-IP login alert")
	}
}

func TestProcessLine_SuccessfulLogin_KnownIP_NoAlert(t *testing.T) {
	m := newTestMonitor()
	ch := make(chan notifier.Alert, 10)

	// Pre-seed the IP as known
	m.knownIPs["1.2.3.4"] = true

	line := `Apr 26 10:00:01 host sshd[1234]: Accepted publickey for alice from 1.2.3.4 port 54321 ssh2`
	m.processLine(line, ch)

	alerts := drainAlerts(ch)
	if len(alerts) != 0 {
		t.Errorf("expected no alert for known-IP login, got %d", len(alerts))
	}
}

func TestProcessLine_SuccessfulLogin_AlertNewIPDisabled_NoAlert(t *testing.T) {
	m := newTestMonitor()
	m.alertNewIPLogin = false
	ch := make(chan notifier.Alert, 10)

	line := `Apr 26 10:00:01 host sshd[1234]: Accepted publickey for alice from 5.5.5.5 port 22 ssh2`
	m.processLine(line, ch)

	alerts := drainAlerts(ch)
	if len(alerts) != 0 {
		t.Errorf("expected no alert when alertNewIPLogin=false, got %d", len(alerts))
	}
}

func TestProcessLine_SuccessfulLogin_LearnIP(t *testing.T) {
	m := newTestMonitor()
	ch := make(chan notifier.Alert, 10)

	line := `Apr 26 10:00:01 host sshd[1234]: Accepted publickey for alice from 9.9.9.9 port 22 ssh2`

	// First login → new IP alert, IP recorded
	m.processLine(line, ch)
	if len(drainAlerts(ch)) != 1 {
		t.Fatal("expected alert on first login from new IP")
	}

	// Second login from the same IP → no alert
	m.processLine(line, ch)
	if len(drainAlerts(ch)) != 0 {
		t.Error("expected no alert on repeated login from already-seen IP")
	}
}

// ---------------------------------------------------------------------------
// processLine: root login
// ---------------------------------------------------------------------------

func TestProcessLine_RootLogin_ProducesAlert(t *testing.T) {
	m := newTestMonitor()
	ch := make(chan notifier.Alert, 10)

	line := `Apr 26 10:00:01 host sshd[1234]: Accepted publickey for root from 1.2.3.4 port 22 ssh2`
	m.processLine(line, ch)

	alerts := drainAlerts(ch)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for root login, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Title != "Direct Root Login" {
		t.Errorf("unexpected title: %q", a.Title)
	}
	if a.Severity != notifier.SeverityContact {
		t.Errorf("expected severity %q, got %q", notifier.SeverityContact, a.Severity)
	}
	if !a.Acknowledge {
		t.Error("expected Acknowledge=true for root login alert")
	}
}

// Root login must NOT additionally produce a "new IP" alert (it returns early).
func TestProcessLine_RootLogin_ExactlyOneAlert(t *testing.T) {
	m := newTestMonitor()
	ch := make(chan notifier.Alert, 10)

	line := `Apr 26 10:00:01 host sshd[1234]: Accepted publickey for root from 1.2.3.4 port 22 ssh2`
	m.processLine(line, ch)

	alerts := drainAlerts(ch)
	if len(alerts) != 1 {
		t.Errorf("root login should produce exactly 1 alert, got %d", len(alerts))
	}
}

// ---------------------------------------------------------------------------
// processLine: brute-force detection
// ---------------------------------------------------------------------------

func TestProcessLine_BruteForce_ThresholdTriggersAlert(t *testing.T) {
	m := newTestMonitor()
	// threshold = 3
	ch := make(chan notifier.Alert, 10)

	failLine := `Apr 26 10:00:01 host sshd[1234]: Failed password for bob from 6.6.6.6 port 22 ssh2`

	// Two failures → below threshold, no alert yet
	m.processLine(failLine, ch)
	m.processLine(failLine, ch)
	if len(drainAlerts(ch)) != 0 {
		t.Error("should not alert before threshold is reached")
	}

	// Third failure → at threshold, alert fires
	m.processLine(failLine, ch)
	alerts := drainAlerts(ch)
	if len(alerts) != 1 {
		t.Fatalf("expected brute-force alert at threshold, got %d alerts", len(alerts))
	}
	a := alerts[0]
	if a.Title != "SSH Brute Force" {
		t.Errorf("unexpected title: %q", a.Title)
	}
	if a.Severity != notifier.SeverityMovement {
		t.Errorf("expected severity %q, got %q", notifier.SeverityMovement, a.Severity)
	}
	if a.SkillID != SkillID {
		t.Errorf("expected SkillID %d, got %d", SkillID, a.SkillID)
	}
}

func TestProcessLine_BruteForce_ResetsAfterAlert(t *testing.T) {
	m := newTestMonitor()
	ch := make(chan notifier.Alert, 10)

	failLine := `Apr 26 10:00:01 host sshd[1234]: Failed password for bob from 7.7.7.7 port 22 ssh2`

	// Hit threshold
	for i := 0; i < m.bruteForceThreshold; i++ {
		m.processLine(failLine, ch)
	}
	drainAlerts(ch) // consume the alert

	// After reset, next batch of failures below threshold should not alert again
	for i := 0; i < m.bruteForceThreshold-1; i++ {
		m.processLine(failLine, ch)
	}
	if len(drainAlerts(ch)) != 0 {
		t.Error("expected no second alert after failure counter was reset")
	}
}

func TestProcessLine_BruteForce_InvalidUser(t *testing.T) {
	m := newTestMonitor()
	ch := make(chan notifier.Alert, 10)

	// "invalid user" variant of failed login
	line := `Apr 26 10:00:01 host sshd[1234]: Failed password for invalid user nobody from 8.8.8.8 port 22 ssh2`

	for i := 0; i < m.bruteForceThreshold; i++ {
		m.processLine(line, ch)
	}
	alerts := drainAlerts(ch)
	if len(alerts) != 1 {
		t.Fatalf("expected brute-force alert for invalid-user failures, got %d", len(alerts))
	}
}

// ---------------------------------------------------------------------------
// processLine: sudo/su failures
// ---------------------------------------------------------------------------

func TestProcessLine_FailedSudo_ProducesAlert(t *testing.T) {
	m := newTestMonitor()
	ch := make(chan notifier.Alert, 10)

	line := `Apr 26 10:00:01 host sudo: alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash`
	m.processLine(line, ch)

	alerts := drainAlerts(ch)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for failed sudo, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Title != "Failed Sudo Attempt" {
		t.Errorf("unexpected title: %q", a.Title)
	}
	if a.Severity != notifier.SeverityMovement {
		t.Errorf("expected severity %q, got %q", notifier.SeverityMovement, a.Severity)
	}
}

func TestProcessLine_FailedSu_ProducesAlert(t *testing.T) {
	m := newTestMonitor()
	ch := make(chan notifier.Alert, 10)

	// pam_unix su failure format
	line := `Apr 26 10:00:01 host su[9999]: pam_unix(su:auth): authentication failure; logname=alice uid=1000 euid=1000 tty=pts/0 ruser=alice rhost=  user=root`
	m.processLine(line, ch)

	alerts := drainAlerts(ch)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for failed su, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Title != "Failed su Attempt" {
		t.Errorf("unexpected title: %q", a.Title)
	}
	if a.Severity != notifier.SeverityMovement {
		t.Errorf("expected severity %q, got %q", notifier.SeverityMovement, a.Severity)
	}
}

// ---------------------------------------------------------------------------
// processLine: unrelated lines produce no alerts
// ---------------------------------------------------------------------------

func TestProcessLine_IrrelevantLine_NoAlert(t *testing.T) {
	m := newTestMonitor()
	ch := make(chan notifier.Alert, 10)

	line := `Apr 26 10:00:01 host kernel: [12345.678] eth0: renamed from veth1234`
	m.processLine(line, ch)

	if len(drainAlerts(ch)) != 0 {
		t.Error("expected no alerts for an irrelevant log line")
	}
}

// ---------------------------------------------------------------------------
// cleanupFailures
// ---------------------------------------------------------------------------

func TestCleanupFailures_RemovesExpiredEntries(t *testing.T) {
	m := newTestMonitor()

	// Insert a failure old enough to be outside 2x the window
	old := time.Now().Add(-(m.bruteForceWindow * 3))
	m.failuresByIP["10.0.0.1"] = []time.Time{old}

	m.cleanupFailures()

	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, exists := m.failuresByIP["10.0.0.1"]; exists {
		t.Error("expected expired IP entry to be removed by cleanupFailures")
	}
}

func TestCleanupFailures_RetainsRecentEntries(t *testing.T) {
	m := newTestMonitor()

	recent := time.Now()
	m.failuresByIP["10.0.0.2"] = []time.Time{recent}

	m.cleanupFailures()

	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, exists := m.failuresByIP["10.0.0.2"]; !exists {
		t.Error("expected recent IP entry to be retained by cleanupFailures")
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestConfigure_ParsesThresholdAndWindow(t *testing.T) {
	m := New()
	cfg := map[string]interface{}{
		"brute_force_threshold": 10,
		"brute_force_window":    "2m",
		"alert_new_ip_login":    false,
	}
	if err := m.Configure(cfg); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	if m.bruteForceThreshold != 10 {
		t.Errorf("expected threshold=10, got %d", m.bruteForceThreshold)
	}
	if m.bruteForceWindow != 2*time.Minute {
		t.Errorf("expected window=2m, got %v", m.bruteForceWindow)
	}
	if m.alertNewIPLogin {
		t.Error("expected alertNewIPLogin=false after Configure")
	}
}

func TestConfigure_InvalidDurationIgnored(t *testing.T) {
	m := New()
	original := m.bruteForceWindow
	cfg := map[string]interface{}{
		"brute_force_window": "not-a-duration",
	}
	if err := m.Configure(cfg); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	if m.bruteForceWindow != original {
		t.Error("invalid duration string should leave bruteForceWindow unchanged")
	}
}

func TestConfigure_CustomAuthLogPath(t *testing.T) {
	m := New()
	cfg := map[string]interface{}{
		"auth_log_path": "/tmp/test_auth.log",
	}
	if err := m.Configure(cfg); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	if m.authLogPath != "/tmp/test_auth.log" {
		t.Errorf("expected custom auth log path, got %q", m.authLogPath)
	}
}

// ---------------------------------------------------------------------------
// Skill interface metadata
// ---------------------------------------------------------------------------

func TestMetadata(t *testing.T) {
	m := New()
	if m.ID() != SkillID {
		t.Errorf("ID() = %d, want %d", m.ID(), SkillID)
	}
	if m.Name() != SkillName {
		t.Errorf("Name() = %q, want %q", m.Name(), SkillName)
	}
	if m.Description() == "" {
		t.Error("Description() should not be empty")
	}
	if m.Why() == "" {
		t.Error("Why() should not be empty")
	}
	if len(m.Requires()) == 0 {
		t.Error("Requires() should list at least one requirement")
	}
	if len(m.Tags()) == 0 {
		t.Error("Tags() should list at least one tag")
	}
}

func TestEnabledState(t *testing.T) {
	m := New()
	if m.Enabled() {
		t.Error("skill should start disabled")
	}
	m.SetEnabled(true)
	if !m.Enabled() {
		t.Error("skill should be enabled after SetEnabled(true)")
	}
	m.SetEnabled(false)
	if m.Enabled() {
		t.Error("skill should be disabled after SetEnabled(false)")
	}
}

func TestDeduceCommandsAndCheckSystemState(t *testing.T) {
	m := New()
	cmds, err := m.DeduceCommands(nil)
	if err != nil {
		t.Fatalf("DeduceCommands error: %v", err)
	}
	if len(cmds) != 0 {
		t.Errorf("expected no system commands for ssh-monitor, got %d", len(cmds))
	}
	ok, err := m.CheckSystemState()
	if err != nil {
		t.Fatalf("CheckSystemState error: %v", err)
	}
	if !ok {
		t.Error("CheckSystemState should always return true for ssh-monitor")
	}
}
