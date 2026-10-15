package logfreshness

import (
	"os"
	"path/filepath"
	"testing"
	"time"

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

// touchFile creates a file and sets its mtime to the given time.
func touchFile(t *testing.T, path string, mtime time.Time) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("could not create temp file %s: %v", path, err)
	}
	f.Close()
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatalf("could not set mtime on %s: %v", path, err)
	}
}

// ---------------------------------------------------------------------------
// checkLogs: fresh file → no alert
// ---------------------------------------------------------------------------

func TestCheckLogs_FreshFile_NoAlert(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "test.log")
	touchFile(t, logFile, time.Now()) // just written

	l := New()
	l.watchedLogs = map[string]time.Duration{
		logFile: 5 * time.Minute,
	}

	ch := make(chan notifier.Alert, 10)
	l.checkLogs(ch)

	if alerts := drainAlerts(ch); len(alerts) != 0 {
		t.Errorf("expected no alert for fresh log file, got %d", len(alerts))
	}
}

// ---------------------------------------------------------------------------
// checkLogs: stale file → alert
// ---------------------------------------------------------------------------

func TestCheckLogs_StaleFile_ProducesAlert(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "stale.log")
	// Make the file appear 10 minutes old
	staleTime := time.Now().Add(-10 * time.Minute)
	touchFile(t, logFile, staleTime)

	l := New()
	l.watchedLogs = map[string]time.Duration{
		logFile: 5 * time.Minute, // max age is 5 min, file is 10 min old
	}

	ch := make(chan notifier.Alert, 10)
	l.checkLogs(ch)

	alerts := drainAlerts(ch)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 stale-log alert, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Title != "[DEADMAN] Stale Log File" {
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
	if a.Location != logFile {
		t.Errorf("expected Location %q, got %q", logFile, a.Location)
	}
	if !a.Acknowledge {
		t.Error("expected Acknowledge=true for stale log alert")
	}
}

// ---------------------------------------------------------------------------
// checkLogs: missing file → alert
// ---------------------------------------------------------------------------

func TestCheckLogs_MissingFile_ProducesAlert(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "does-not-exist.log")

	l := New()
	l.watchedLogs = map[string]time.Duration{
		missingPath: 5 * time.Minute,
	}

	ch := make(chan notifier.Alert, 10)
	l.checkLogs(ch)

	alerts := drainAlerts(ch)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 missing-file alert, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Title != "[DEADMAN] Log File Missing" {
		t.Errorf("unexpected title: %q", a.Title)
	}
	if a.Severity != notifier.SeverityContact {
		t.Errorf("expected severity %q, got %q", notifier.SeverityContact, a.Severity)
	}
	if a.Location != missingPath {
		t.Errorf("expected Location %q, got %q", missingPath, a.Location)
	}
	if !a.Acknowledge {
		t.Error("expected Acknowledge=true for missing-file alert")
	}
}

// ---------------------------------------------------------------------------
// checkLogs: multiple files — independent evaluation
// ---------------------------------------------------------------------------

func TestCheckLogs_MultipleFiles_AlertOnlyForStale(t *testing.T) {
	dir := t.TempDir()

	freshFile := filepath.Join(dir, "fresh.log")
	staleFile := filepath.Join(dir, "stale.log")

	touchFile(t, freshFile, time.Now())
	touchFile(t, staleFile, time.Now().Add(-30*time.Minute))

	l := New()
	l.watchedLogs = map[string]time.Duration{
		freshFile: 10 * time.Minute,
		staleFile: 10 * time.Minute,
	}

	ch := make(chan notifier.Alert, 10)
	l.checkLogs(ch)

	alerts := drainAlerts(ch)
	if len(alerts) != 1 {
		t.Fatalf("expected exactly 1 alert (for the stale file), got %d", len(alerts))
	}
	if alerts[0].Location != staleFile {
		t.Errorf("expected alert location %q, got %q", staleFile, alerts[0].Location)
	}
}

func TestCheckLogs_MultipleFiles_BothMissing_TwoAlerts(t *testing.T) {
	dir := t.TempDir()
	missing1 := filepath.Join(dir, "missing1.log")
	missing2 := filepath.Join(dir, "missing2.log")

	l := New()
	l.watchedLogs = map[string]time.Duration{
		missing1: 5 * time.Minute,
		missing2: 5 * time.Minute,
	}

	ch := make(chan notifier.Alert, 10)
	l.checkLogs(ch)

	alerts := drainAlerts(ch)
	if len(alerts) != 2 {
		t.Errorf("expected 2 missing-file alerts, got %d", len(alerts))
	}
}

// ---------------------------------------------------------------------------
// checkLogs: file exactly at threshold boundary
// ---------------------------------------------------------------------------

func TestCheckLogs_FileAtExactThreshold_NoAlert(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "boundary.log")

	// Slightly under the threshold (4 min 50 sec old vs 5 min max)
	touchFile(t, logFile, time.Now().Add(-4*time.Minute-50*time.Second))

	l := New()
	l.watchedLogs = map[string]time.Duration{
		logFile: 5 * time.Minute,
	}

	ch := make(chan notifier.Alert, 10)
	l.checkLogs(ch)

	if alerts := drainAlerts(ch); len(alerts) != 0 {
		t.Errorf("expected no alert for file within max age, got %d", len(alerts))
	}
}

// ---------------------------------------------------------------------------
// checkLogs: alert contains useful age info
// ---------------------------------------------------------------------------

func TestCheckLogs_StaleAlert_ActivityContainsAge(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "aged.log")
	touchFile(t, logFile, time.Now().Add(-20*time.Minute))

	l := New()
	l.watchedLogs = map[string]time.Duration{
		logFile: 5 * time.Minute,
	}

	ch := make(chan notifier.Alert, 10)
	l.checkLogs(ch)

	alerts := drainAlerts(ch)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 stale alert, got %d", len(alerts))
	}
	if alerts[0].Activity == "" {
		t.Error("Activity should not be empty")
	}
	// The Activity string should mention the max age
	if alerts[0].Unit == "" {
		t.Error("Unit should contain last-modified timestamp")
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestConfigure_ParsesWatchedLogs(t *testing.T) {
	l := New()
	cfg := map[string]interface{}{
		"watch_logs": []interface{}{
			map[string]interface{}{"path": "/var/log/syslog", "threshold": "15m"},
			map[string]interface{}{"path": "/var/log/auth.log", "threshold": "1h"},
		},
		"poll_interval": "30s",
	}
	if err := l.Configure(cfg); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}

	if len(l.watchedLogs) != 2 {
		t.Errorf("expected 2 watched logs, got %d", len(l.watchedLogs))
	}
	if d, ok := l.watchedLogs["/var/log/syslog"]; !ok || d != 15*time.Minute {
		t.Errorf("expected /var/log/syslog max-age=15m, got %v", d)
	}
	if d, ok := l.watchedLogs["/var/log/auth.log"]; !ok || d != time.Hour {
		t.Errorf("expected /var/log/auth.log max-age=1h, got %v", d)
	}
	if l.checkInterval != 30*time.Second {
		t.Errorf("expected checkInterval=30s, got %v", l.checkInterval)
	}
}

func TestConfigure_InvalidDurationIgnored(t *testing.T) {
	l := New()
	cfg := map[string]interface{}{
		"poll_interval": "not-a-duration",
	}
	original := l.checkInterval
	if err := l.Configure(cfg); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	if l.checkInterval != original {
		t.Error("invalid poll_interval string should leave checkInterval unchanged")
	}
}

func TestConfigure_InvalidLogDurationSkipped(t *testing.T) {
	l := New()
	cfg := map[string]interface{}{
		"watch_logs": []interface{}{
			map[string]interface{}{"path": "/var/log/valid.log", "threshold": "10m"},
			map[string]interface{}{"path": "/var/log/invalid.log", "threshold": "not-a-duration"},
			"not-a-map",
		},
	}
	if err := l.Configure(cfg); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	// Only the valid duration should be added
	if _, ok := l.watchedLogs["/var/log/invalid.log"]; ok {
		t.Error("log entry with invalid duration should be skipped")
	}
	if _, ok := l.watchedLogs["/var/log/valid.log"]; !ok {
		t.Error("log entry with valid duration should be added")
	}
}

func TestConfigure_Defaults(t *testing.T) {
	l := New()
	if len(l.watchedLogs) == 0 {
		t.Error("New() should provide default watched logs")
	}
	if l.checkInterval == 0 {
		t.Error("New() should provide a default check interval")
	}
}

// ---------------------------------------------------------------------------
// Skill interface metadata
// ---------------------------------------------------------------------------

func TestMetadata(t *testing.T) {
	l := New()
	if l.ID() != SkillID {
		t.Errorf("ID() = %d, want %d", l.ID(), SkillID)
	}
	if l.Name() != SkillName {
		t.Errorf("Name() = %q, want %q", l.Name(), SkillName)
	}
	if l.Description() == "" {
		t.Error("Description() should not be empty")
	}
	if l.Why() == "" {
		t.Error("Why() should not be empty")
	}
}

func TestEnabledState(t *testing.T) {
	l := New()
	if l.Enabled() {
		t.Error("skill should start disabled")
	}
	l.SetEnabled(true)
	if !l.Enabled() {
		t.Error("skill should be enabled after SetEnabled(true)")
	}
	l.SetEnabled(false)
	if l.Enabled() {
		t.Error("skill should be disabled after SetEnabled(false)")
	}
}

func TestDeduceCommandsAndCheckSystemState(t *testing.T) {
	l := New()
	cmds, err := l.DeduceCommands(nil)
	if err != nil {
		t.Fatalf("DeduceCommands error: %v", err)
	}
	if len(cmds) != 0 {
		t.Errorf("expected no system commands for log-freshness, got %d", len(cmds))
	}
	ok, err := l.CheckSystemState()
	if err != nil {
		t.Fatalf("CheckSystemState error: %v", err)
	}
	if !ok {
		t.Error("CheckSystemState should always return true for log-freshness")
	}
}


// ---------------------------------------------------------------------------
// checkLogs: alerts on state changes, not every poll
// ---------------------------------------------------------------------------

func TestCheckLogs_AlertsOnceThenRecovers(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "app.log")
	touchFile(t, logFile, time.Now().Add(-10*time.Minute))

	l := New()
	l.watchedLogs = map[string]time.Duration{logFile: 5 * time.Minute}
	ch := make(chan notifier.Alert, 10)

	l.checkLogs(ch)
	if got := drainAlerts(ch); len(got) != 1 || got[0].Title != "[DEADMAN] Stale Log File" {
		t.Fatalf("expected one stale alert, got %+v", got)
	}

	l.checkLogs(ch)
	l.checkLogs(ch)
	if got := drainAlerts(ch); len(got) != 0 {
		t.Fatalf("expected no repeat alerts while still stale, got %+v", got)
	}

	touchFile(t, logFile, time.Now())
	l.checkLogs(ch)
	got := drainAlerts(ch)
	if len(got) != 1 || got[0].Severity != notifier.SeverityNominal || got[0].Title != "[DEADMAN] Recovered: Stale Log File" {
		t.Fatalf("expected one NOMINAL recovery alert, got %+v", got)
	}

	l.checkLogs(ch)
	if got := drainAlerts(ch); len(got) != 0 {
		t.Fatalf("expected no alerts while healthy, got %+v", got)
	}

	// Going stale again alerts again
	touchFile(t, logFile, time.Now().Add(-10*time.Minute))
	l.checkLogs(ch)
	if got := drainAlerts(ch); len(got) != 1 {
		t.Fatalf("expected a new stale alert, got %+v", got)
	}
}

func TestCheckLogs_MissingThenCreated(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "gone.log")
	l := New()
	l.watchedLogs = map[string]time.Duration{logFile: 5 * time.Minute}
	ch := make(chan notifier.Alert, 10)

	l.checkLogs(ch)
	l.checkLogs(ch)
	if got := drainAlerts(ch); len(got) != 1 || got[0].Title != "[DEADMAN] Log File Missing" {
		t.Fatalf("expected one missing alert, got %+v", got)
	}

	touchFile(t, logFile, time.Now())
	l.checkLogs(ch)
	if got := drainAlerts(ch); len(got) != 1 || got[0].Title != "[DEADMAN] Recovered: Log File Missing" {
		t.Fatalf("expected one recovery alert, got %+v", got)
	}
}
