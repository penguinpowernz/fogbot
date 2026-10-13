package suidsweep

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/penguinpowernz/fogbot/internal/baseline"
)

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestConfigure_ParsesSweepInterval(t *testing.T) {
	mgr := baseline.NewManager(t.TempDir())
	s := New(mgr)

	cfg := map[string]interface{}{
		"suid_sweep_interval": "30m",
	}
	if err := s.Configure(cfg); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	if s.sweepInterval != 30*time.Minute {
		t.Errorf("expected sweepInterval=30m, got %v", s.sweepInterval)
	}
}

func TestConfigure_InvalidIntervalIgnored(t *testing.T) {
	mgr := baseline.NewManager(t.TempDir())
	s := New(mgr)
	original := s.sweepInterval

	cfg := map[string]interface{}{
		"suid_sweep_interval": "not-a-duration",
	}
	if err := s.Configure(cfg); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	if s.sweepInterval != original {
		t.Error("invalid sweep interval should leave sweepInterval unchanged")
	}
}

func TestConfigure_EmptyConfig_PreservesDefaults(t *testing.T) {
	mgr := baseline.NewManager(t.TempDir())
	s := New(mgr)
	origInterval := s.sweepInterval

	if err := s.Configure(map[string]interface{}{}); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	if s.sweepInterval != origInterval {
		t.Error("empty config should not change sweepInterval")
	}
}

func TestNew_Defaults(t *testing.T) {
	mgr := baseline.NewManager(t.TempDir())
	s := New(mgr)
	if s.sweepInterval == 0 {
		t.Error("New() should provide a non-zero sweep interval")
	}
	if len(s.searchPaths) == 0 {
		t.Error("New() should provide default search paths")
	}
	if s.Enabled() {
		t.Error("skill should start disabled")
	}
}

// ---------------------------------------------------------------------------
// sweep: minimal filesystem integration
// ---------------------------------------------------------------------------

// TestSweep_EmptyDir returns an empty map for a directory with no SUID files.
func TestSweep_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	// Create a regular (non-SUID) file
	path := filepath.Join(dir, "regular.txt")
	if err := os.WriteFile(path, []byte("data"), 0644); err != nil {
		t.Fatalf("could not create test file: %v", err)
	}

	mgr := baseline.NewManager(t.TempDir())
	s := New(mgr)
	s.searchPaths = []string{dir}

	results := s.sweep()
	if len(results) != 0 {
		t.Errorf("expected 0 SUID entries in dir with no SUID files, got %d", len(results))
	}
}

// TestSweep_SuidFile detects a file with setuid set.
func TestSweep_SuidFile(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("setting SUID bit requires root; skipping")
	}

	dir := t.TempDir()
	suidFile := filepath.Join(dir, "suid_binary")
	if err := os.WriteFile(suidFile, []byte("#!/bin/sh"), 0755); err != nil {
		t.Fatalf("could not create test file: %v", err)
	}
	// Set the SUID bit
	if err := os.Chmod(suidFile, 0755|os.ModeSetuid); err != nil {
		t.Fatalf("could not set SUID bit: %v", err)
	}

	mgr := baseline.NewManager(t.TempDir())
	s := New(mgr)
	s.searchPaths = []string{dir}

	results := s.sweep()
	if _, ok := results[suidFile]; !ok {
		t.Errorf("expected suid file %q to appear in sweep results", suidFile)
	}
}

// ---------------------------------------------------------------------------
// Baseline integration: Diff detects new SUID binaries
// ---------------------------------------------------------------------------

func TestBaselineDiff_NewBinaryDetected(t *testing.T) {
	// Build a baseline that knows about one binary
	existing := map[string]baseline.SuidEntry{
		"/bin/su": {Path: "/bin/su", Mode: 0104755},
	}
	bl := &baseline.Baseline{
		Type:      "suid",
		Entries:   existing,
		CreatedAt: time.Now(),
		Approved:  true,
	}

	// Current state has an additional new binary
	current := map[string]baseline.SuidEntry{
		"/bin/su":      {Path: "/bin/su", Mode: 0104755},
		"/tmp/evil_su": {Path: "/tmp/evil_su", Mode: 0104755},
	}

	newEntries := bl.Diff(current)
	if len(newEntries) != 1 {
		t.Fatalf("expected 1 new entry from Diff, got %d", len(newEntries))
	}
	if newEntries[0].Path != "/tmp/evil_su" {
		t.Errorf("expected new entry path /tmp/evil_su, got %q", newEntries[0].Path)
	}
}

func TestBaselineDiff_NoNewBinaries(t *testing.T) {
	existing := map[string]baseline.SuidEntry{
		"/bin/su":   {Path: "/bin/su"},
		"/usr/bin/passwd": {Path: "/usr/bin/passwd"},
	}
	bl := &baseline.Baseline{
		Type:     "suid",
		Entries:  existing,
		Approved: true,
	}

	// Exact same state — nothing new
	current := map[string]baseline.SuidEntry{
		"/bin/su":         {Path: "/bin/su"},
		"/usr/bin/passwd": {Path: "/usr/bin/passwd"},
	}

	newEntries := bl.Diff(current)
	if len(newEntries) != 0 {
		t.Errorf("expected 0 new entries, got %d", len(newEntries))
	}
}

func TestBaselineDiff_AllNewWhenBaselineEmpty(t *testing.T) {
	bl := &baseline.Baseline{
		Type:     "suid",
		Entries:  map[string]baseline.SuidEntry{},
		Approved: true,
	}

	current := map[string]baseline.SuidEntry{
		"/bin/su":         {Path: "/bin/su"},
		"/usr/bin/passwd": {Path: "/usr/bin/passwd"},
	}

	newEntries := bl.Diff(current)
	if len(newEntries) != 2 {
		t.Errorf("expected 2 new entries from empty baseline, got %d", len(newEntries))
	}
}

func TestBaselineDiff_NilBaseline_AllNew(t *testing.T) {
	var bl *baseline.Baseline // nil baseline

	current := map[string]baseline.SuidEntry{
		"/bin/su": {Path: "/bin/su"},
	}

	newEntries := bl.Diff(current)
	if len(newEntries) != 1 {
		t.Errorf("expected 1 new entry from nil baseline, got %d", len(newEntries))
	}
}

// ---------------------------------------------------------------------------
// Skill interface metadata
// ---------------------------------------------------------------------------

func TestMetadata(t *testing.T) {
	mgr := baseline.NewManager(t.TempDir())
	s := New(mgr)
	if s.ID() != SkillID {
		t.Errorf("ID() = %d, want %d", s.ID(), SkillID)
	}
	if s.Name() != SkillName {
		t.Errorf("Name() = %q, want %q", s.Name(), SkillName)
	}
	if s.Description() == "" {
		t.Error("Description() should not be empty")
	}
	if s.Why() == "" {
		t.Error("Why() should not be empty")
	}
	if len(s.Requires()) == 0 {
		t.Error("Requires() should list at least one requirement")
	}
	if len(s.Tags()) == 0 {
		t.Error("Tags() should list at least one tag")
	}
}

func TestEnabledState(t *testing.T) {
	mgr := baseline.NewManager(t.TempDir())
	s := New(mgr)
	if s.Enabled() {
		t.Error("skill should start disabled")
	}
	s.SetEnabled(true)
	if !s.Enabled() {
		t.Error("skill should be enabled after SetEnabled(true)")
	}
	s.SetEnabled(false)
	if s.Enabled() {
		t.Error("skill should be disabled after SetEnabled(false)")
	}
}

func TestDeduceCommandsAndCheckSystemState(t *testing.T) {
	mgr := baseline.NewManager(t.TempDir())
	s := New(mgr)
	cmds, err := s.DeduceCommands(nil)
	if err != nil {
		t.Fatalf("DeduceCommands error: %v", err)
	}
	if len(cmds) != 0 {
		t.Errorf("expected no system commands for suid-sweep, got %d", len(cmds))
	}
	ok, err := s.CheckSystemState()
	if err != nil {
		t.Fatalf("CheckSystemState error: %v", err)
	}
	if !ok {
		t.Error("CheckSystemState should always return true for suid-sweep")
	}
}
