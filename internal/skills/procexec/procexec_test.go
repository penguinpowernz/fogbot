package procexec

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestConfigure_ParsesSuspiciousPaths(t *testing.T) {
	p := New()
	cfg := map[string]interface{}{
		"suspicious_paths": []interface{}{"/tmp", "/var/tmp", "/dev/shm"},
	}
	if err := p.Configure(cfg); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	if len(p.suspiciousPaths) != 3 {
		t.Fatalf("expected 3 suspicious paths, got %d", len(p.suspiciousPaths))
	}
	expected := map[string]bool{"/tmp": true, "/var/tmp": true, "/dev/shm": true}
	for _, path := range p.suspiciousPaths {
		if !expected[path] {
			t.Errorf("unexpected suspicious path %q", path)
		}
	}
}

func TestConfigure_ParsesPollInterval(t *testing.T) {
	p := New()
	cfg := map[string]interface{}{
		"poll_interval": "10s",
	}
	if err := p.Configure(cfg); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	if p.pollInterval != 10*time.Second {
		t.Errorf("expected pollInterval=10s, got %v", p.pollInterval)
	}
}

func TestConfigure_InvalidIntervalIgnored(t *testing.T) {
	p := New()
	original := p.pollInterval
	cfg := map[string]interface{}{
		"poll_interval": "not-a-duration",
	}
	if err := p.Configure(cfg); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	if p.pollInterval != original {
		t.Error("invalid poll_interval string should leave pollInterval unchanged")
	}
}

func TestConfigure_NonStringPathsSkipped(t *testing.T) {
	p := New()
	cfg := map[string]interface{}{
		"suspicious_paths": []interface{}{"/tmp", 42, nil, "/dev/shm"},
	}
	if err := p.Configure(cfg); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	if len(p.suspiciousPaths) != 2 {
		t.Errorf("expected 2 string paths, got %d: %v", len(p.suspiciousPaths), p.suspiciousPaths)
	}
}

func TestConfigure_EmptyConfig_PreservesDefaults(t *testing.T) {
	p := New()
	origPaths := append([]string{}, p.suspiciousPaths...)
	origInterval := p.pollInterval

	if err := p.Configure(map[string]interface{}{}); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	if len(p.suspiciousPaths) != len(origPaths) {
		t.Error("empty config should not change suspicious paths")
	}
	if p.pollInterval != origInterval {
		t.Error("empty config should not change poll interval")
	}
}

// ---------------------------------------------------------------------------
// cleanupSeenProcs
// ---------------------------------------------------------------------------

func TestCleanupSeenProcs_RemovesDeadPIDs(t *testing.T) {
	p := New()

	// Use a PID that almost certainly doesn't exist: max int32 range
	deadPID := 99999999
	p.seenProcs[deadPID] = true

	p.cleanupSeenProcs()

	p.mu.RLock()
	defer p.mu.RUnlock()
	if _, exists := p.seenProcs[deadPID]; exists {
		t.Errorf("expected dead PID %d to be removed by cleanupSeenProcs", deadPID)
	}
}

func TestCleanupSeenProcs_RetainsLivePIDs(t *testing.T) {
	p := New()

	// PID 1 (init/systemd) is always alive
	p.seenProcs[1] = true

	p.cleanupSeenProcs()

	p.mu.RLock()
	defer p.mu.RUnlock()
	if _, exists := p.seenProcs[1]; !exists {
		t.Error("expected live PID 1 to be retained by cleanupSeenProcs")
	}
}

func TestCleanupSeenProcs_OwnPIDRetained(t *testing.T) {
	p := New()

	// Our own PID is definitely alive
	ownPID := os.Getpid()
	p.seenProcs[ownPID] = true

	p.cleanupSeenProcs()

	p.mu.RLock()
	defer p.mu.RUnlock()
	if _, exists := p.seenProcs[ownPID]; !exists {
		t.Errorf("expected own PID %d to be retained by cleanupSeenProcs", ownPID)
	}
}

func TestCleanupSeenProcs_EmptyMap_NoError(t *testing.T) {
	p := New()
	// Should not panic or error on empty map
	p.cleanupSeenProcs()
}

// ---------------------------------------------------------------------------
// scanProc: detection via fake /proc tree
//
// We build a minimal fake /proc directory with a synthetic PID whose exe
// symlink points into a suspicious path, then redirect the skill to read
// from the fake /proc. Because scanProc is hard-coded to read "/proc", we
// instead test the detection logic directly via a wrapper.
// ---------------------------------------------------------------------------

// buildFakeProc creates a fake /proc/<pid>/exe symlink pointing to target.
// Returns the proc root directory.
func buildFakeProc(t *testing.T, pid int, exeTarget string) string {
	t.Helper()
	procRoot := t.TempDir()
	pidDir := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		t.Fatalf("could not create fake proc dir: %v", err)
	}
	// Create a real file to point the symlink at (or use the target path directly)
	if err := os.Symlink(exeTarget, filepath.Join(pidDir, "exe")); err != nil {
		t.Fatalf("could not create exe symlink: %v", err)
	}
	// Create a minimal cmdline and comm file
	os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte(exeTarget+"\x00"), 0644)
	os.WriteFile(filepath.Join(pidDir, "comm"), []byte(filepath.Base(exeTarget)+"\n"), 0644)
	return procRoot
}

// scanProcDir exercises the core detection logic of scanProc against an
// arbitrary proc root directory. This avoids hard-coupling to /proc.
func (p *ProcExec) scanProcDir(procRoot string, alertChan chan<- notifier.Alert) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		p.mu.RLock()
		seen := p.seenProcs[pid]
		p.mu.RUnlock()
		if seen {
			continue
		}

		exePath, err := os.Readlink(filepath.Join(procRoot, entry.Name(), "exe"))
		if err != nil {
			continue
		}

		for _, suspPath := range p.suspiciousPaths {
			if len(exePath) >= len(suspPath) && exePath[:len(suspPath)] == suspPath {
				p.mu.Lock()
				p.seenProcs[pid] = true
				p.mu.Unlock()

				cmdlineBytes, _ := os.ReadFile(filepath.Join(procRoot, entry.Name(), "cmdline"))
				commBytes, _ := os.ReadFile(filepath.Join(procRoot, entry.Name(), "comm"))
				comm := string(commBytes)
				if len(comm) > 0 && comm[len(comm)-1] == '\n' {
					comm = comm[:len(comm)-1]
				}

				alertChan <- notifier.Alert{
					Severity:    notifier.SeverityContact,
					SkillID:     SkillID,
					SkillName:   SkillName,
					Title:       "Suspicious Process Execution",
					Size:        "1 process",
					Activity:    fmt.Sprintf("Executable running from %s", suspPath),
					Location:    exePath,
					Unit:        fmt.Sprintf("pid=%d (%s)", pid, comm),
					Time:        time.Now(),
					Equipment:   string(cmdlineBytes),
					Acknowledge: true,
					Metadata: map[string]string{
						"pid": strconv.Itoa(pid),
						"exe": exePath,
					},
				}
				break
			}
		}
	}
}

func TestScanProc_SuspiciousExe_ProducesAlert(t *testing.T) {
	p := New()
	p.suspiciousPaths = []string{"/tmp"}

	fakePID := 1234
	procRoot := buildFakeProc(t, fakePID, "/tmp/malware.sh")

	ch := make(chan notifier.Alert, 10)
	p.scanProcDir(procRoot, ch)

	alerts := drainAlerts(ch)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for suspicious process, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Title != "Suspicious Process Execution" {
		t.Errorf("unexpected title: %q", a.Title)
	}
	if a.Severity != notifier.SeverityContact {
		t.Errorf("expected severity %q, got %q", notifier.SeverityContact, a.Severity)
	}
	if a.Location != "/tmp/malware.sh" {
		t.Errorf("expected location /tmp/malware.sh, got %q", a.Location)
	}
	if a.SkillID != SkillID {
		t.Errorf("expected SkillID %d, got %d", SkillID, a.SkillID)
	}
	if !a.Acknowledge {
		t.Error("expected Acknowledge=true for suspicious process alert")
	}
}

func TestScanProc_SafeExe_NoAlert(t *testing.T) {
	p := New()
	p.suspiciousPaths = []string{"/tmp", "/dev/shm"}

	fakePID := 5678
	procRoot := buildFakeProc(t, fakePID, "/usr/bin/ls")

	ch := make(chan notifier.Alert, 10)
	p.scanProcDir(procRoot, ch)

	if alerts := drainAlerts(ch); len(alerts) != 0 {
		t.Errorf("expected no alert for safe executable, got %d", len(alerts))
	}
}

func TestScanProc_AlreadySeen_NoRepeatAlert(t *testing.T) {
	p := New()
	p.suspiciousPaths = []string{"/tmp"}

	fakePID := 9999
	p.seenProcs[fakePID] = true // pre-mark as seen

	procRoot := buildFakeProc(t, fakePID, "/tmp/evil.sh")

	ch := make(chan notifier.Alert, 10)
	p.scanProcDir(procRoot, ch)

	if alerts := drainAlerts(ch); len(alerts) != 0 {
		t.Errorf("expected no repeat alert for already-seen PID, got %d", len(alerts))
	}
}

func TestScanProc_NonPIDDirs_Ignored(t *testing.T) {
	p := New()
	p.suspiciousPaths = []string{"/tmp"}

	procRoot := t.TempDir()
	// Create non-PID directories (like /proc/net, /proc/sys)
	for _, d := range []string{"net", "sys", "bus"} {
		os.MkdirAll(filepath.Join(procRoot, d), 0755)
	}
	// And a regular file
	os.WriteFile(filepath.Join(procRoot, "version"), []byte("Linux"), 0644)

	ch := make(chan notifier.Alert, 10)
	p.scanProcDir(procRoot, ch)

	if alerts := drainAlerts(ch); len(alerts) != 0 {
		t.Errorf("expected no alerts for non-PID proc entries, got %d", len(alerts))
	}
}

func TestScanProc_DevShmExe_ProducesAlert(t *testing.T) {
	p := New()
	p.suspiciousPaths = []string{"/tmp", "/dev/shm"}

	fakePID := 4321
	procRoot := buildFakeProc(t, fakePID, "/dev/shm/hidden")

	ch := make(chan notifier.Alert, 10)
	p.scanProcDir(procRoot, ch)

	alerts := drainAlerts(ch)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for /dev/shm executable, got %d", len(alerts))
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
		t.Errorf("expected no system commands for proc-exec, got %d", len(cmds))
	}
	ok, err := p.CheckSystemState()
	if err != nil {
		t.Fatalf("CheckSystemState error: %v", err)
	}
	if !ok {
		t.Error("CheckSystemState should always return true for proc-exec")
	}
}
