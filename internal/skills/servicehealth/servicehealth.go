package servicehealth

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
)

const (
	SkillID   = 410
	SkillName = "service-health"
)

// ServiceHealth monitors systemd services for unexpected stops (DEADMAN check)
type ServiceHealth struct {
	mu            sync.RWMutex
	enabled       bool
	config        map[string]interface{}
	services      []string
	checkInterval time.Duration
}

// New creates a new ServiceHealth skill
func New() *ServiceHealth {
	return &ServiceHealth{
		enabled:       false,
		services:      []string{"sshd", "systemd-journald"},
		checkInterval: 1 * time.Minute,
	}
}

func (s *ServiceHealth) ID() int      { return SkillID }
func (s *ServiceHealth) Name() string { return SkillName }
func (s *ServiceHealth) Description() string {
	return "[DEADMAN] Polls systemd to verify configured services are running"
}
func (s *ServiceHealth) Why() string {
	return "Critical services stopping unexpectedly may indicate attacks or system compromise."
}
func (s *ServiceHealth) Requires() []string { return []string{"systemd"} }
func (s *ServiceHealth) Tags() []string     { return []string{"deadman", "systemd", "health"} }
func (s *ServiceHealth) DropIns() []skills.DropIn { return nil }
func (s *ServiceHealth) Enabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled
}

func (s *ServiceHealth) SetEnabled(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = enabled
}

func (s *ServiceHealth) Config() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

func (s *ServiceHealth) Configure(cfg map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.config = cfg

	if svcs, ok := cfg["services"].([]interface{}); ok {
		s.services = make([]string, 0, len(svcs))
		for _, svc := range svcs {
			if svcStr, ok := svc.(string); ok {
				s.services = append(s.services, svcStr)
			}
		}
	}

	if intervalStr, ok := cfg["check_interval"].(string); ok {
		if d, err := time.ParseDuration(intervalStr); err == nil {
			s.checkInterval = d
		}
	}

	return nil
}

func (s *ServiceHealth) Watch(ctx context.Context) (<-chan notifier.Alert, error) {
	alertChan := make(chan notifier.Alert, 10)

	go s.watchLoop(ctx, alertChan)

	return alertChan, nil
}

func (s *ServiceHealth) watchLoop(ctx context.Context, alertChan chan<- notifier.Alert) {
	defer close(alertChan)

	ticker := time.NewTicker(s.checkInterval)
	defer ticker.Stop()

	log.Printf("[service-health] Monitoring %d services", len(s.services))

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			s.checkServices(alertChan)
		}
	}
}

func (s *ServiceHealth) checkServices(alertChan chan<- notifier.Alert) {
	now := time.Now()

	s.mu.RLock()
	services := s.services
	s.mu.RUnlock()

	for _, service := range services {
		// Use systemctl is-active to check service status
		cmd := exec.Command("systemctl", "is-active", service)
		output, err := cmd.Output()

		status := strings.TrimSpace(string(output))

		if err != nil || status != "active" {
			alertChan <- notifier.Alert{
				Severity:    notifier.SeverityContact,
				SkillID:     SkillID,
				SkillName:   SkillName,
				Title:       "[DEADMAN] Service Stopped",
				Size:        "1 service",
				Activity:    fmt.Sprintf("Service %s is not active", service),
				Location:    "systemd",
				Unit:        fmt.Sprintf("service=%s status=%s", service, status),
				Time:        now,
				Equipment:   "systemctl",
				Acknowledge: true,
			}
		}
	}
}




// DeduceCommands - stub for legacy skill
func (s *ServiceHealth) DeduceCommands(cfg map[string]interface{}) ([]skills.SystemCommand, error) {
	return []skills.SystemCommand{}, nil
}

// CheckSystemState - stub for legacy skill
func (s *ServiceHealth) CheckSystemState() (bool, error) {
	return true, nil
}
