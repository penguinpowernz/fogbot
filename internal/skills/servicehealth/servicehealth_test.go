package servicehealth

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestConfigure_ParsesServices(t *testing.T) {
	s := New()
	cfg := map[string]interface{}{
		"watch_services": []interface{}{"sshd", "nginx", "postgresql"},
	}
	if err := s.Configure(cfg); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}

	if len(s.services) != 3 {
		t.Fatalf("expected 3 services, got %d", len(s.services))
	}

	expected := map[string]bool{"sshd": true, "nginx": true, "postgresql": true}
	for _, svc := range s.services {
		if !expected[svc] {
			t.Errorf("unexpected service %q in list", svc)
		}
	}
}

func TestConfigure_ParsesCheckInterval(t *testing.T) {
	s := New()
	cfg := map[string]interface{}{
		"poll_interval": "5m",
	}
	if err := s.Configure(cfg); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	if s.checkInterval != 5*time.Minute {
		t.Errorf("expected checkInterval=5m, got %v", s.checkInterval)
	}
}

func TestConfigure_InvalidIntervalIgnored(t *testing.T) {
	s := New()
	original := s.checkInterval
	cfg := map[string]interface{}{
		"poll_interval": "not-a-duration",
	}
	if err := s.Configure(cfg); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	if s.checkInterval != original {
		t.Error("invalid check_interval string should leave checkInterval unchanged")
	}
}

func TestConfigure_EmptyServices_ReplacesWithEmpty(t *testing.T) {
	s := New()
	cfg := map[string]interface{}{
		"watch_services": []interface{}{},
	}
	if err := s.Configure(cfg); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	if len(s.services) != 0 {
		t.Errorf("expected empty service list after Configure with empty slice, got %d", len(s.services))
	}
}

func TestConfigure_NonStringServicesSkipped(t *testing.T) {
	s := New()
	cfg := map[string]interface{}{
		"watch_services": []interface{}{"sshd", 42, nil, "auditd"},
	}
	if err := s.Configure(cfg); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	// Only string entries should be kept
	if len(s.services) != 2 {
		t.Errorf("expected 2 string services, got %d: %v", len(s.services), s.services)
	}
}

func TestConfigure_EmptyConfig_PreservesDefaults(t *testing.T) {
	s := New()
	origServices := append([]string{}, s.services...)
	origInterval := s.checkInterval

	if err := s.Configure(map[string]interface{}{}); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}

	if len(s.services) != len(origServices) {
		t.Error("empty config should not change services list")
	}
	if s.checkInterval != origInterval {
		t.Error("empty config should not change checkInterval")
	}
}

// ---------------------------------------------------------------------------
// New() defaults
// ---------------------------------------------------------------------------

func TestNew_Defaults(t *testing.T) {
	s := New()
	if len(s.services) == 0 {
		t.Error("New() should provide default services to watch")
	}
	if s.checkInterval == 0 {
		t.Error("New() should provide a non-zero check interval")
	}
	if s.Enabled() {
		t.Error("skill should start disabled")
	}
}

// ---------------------------------------------------------------------------
// Skill interface metadata
// ---------------------------------------------------------------------------

func TestMetadata(t *testing.T) {
	s := New()
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
	s := New()
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
	s := New()
	cmds, err := s.DeduceCommands(nil)
	if err != nil {
		t.Fatalf("DeduceCommands error: %v", err)
	}
	if len(cmds) != 0 {
		t.Errorf("expected no system commands for service-health, got %d", len(cmds))
	}
	ok, err := s.CheckSystemState()
	if err != nil {
		t.Fatalf("CheckSystemState error: %v", err)
	}
	if !ok {
		t.Error("CheckSystemState should always return true for service-health")
	}
}

func TestConfig_ReturnsConfigMap(t *testing.T) {
	s := New()
	cfg := map[string]interface{}{"poll_interval": "2m"}
	s.Configure(cfg)
	got := s.Config()
	if got == nil {
		t.Error("Config() should not return nil after Configure")
	}
}
