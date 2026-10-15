package systemdwatch

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
)

const (
	SkillID   = 550
	SkillName = "systemd-watch"
)

// SystemdWatch monitors systemd via D-Bus for daemon-reload and unit changes
type SystemdWatch struct {
	mu      sync.RWMutex
	enabled bool
	config  map[string]interface{}
}

// New creates a SystemdWatch with default config (used by daemon registry).
func New() *SystemdWatch {
	return &SystemdWatch{
		enabled: false,
	}
}

// NewFromConfig creates a SystemdWatch pre-populated from a SkillConfig (used by CLI enabler).
func NewFromConfig(cfg skills.SkillConfig) *SystemdWatch {
	s := New()
	if cfg.Config != nil {
		s.Configure(cfg.Config)
	}
	return s
}

func (s *SystemdWatch) ID() int      { return SkillID }
func (s *SystemdWatch) Name() string { return SkillName }
func (s *SystemdWatch) Description() string {
	return "Monitor systemd for daemon-reload and service changes via D-Bus"
}
func (s *SystemdWatch) Why() string {
	return "Attackers often establish persistence via systemd services. Detecting daemon-reload and unit changes can reveal when new services are registered or existing ones modified."
}
func (s *SystemdWatch) Requires() []string { return []string{"dbus", "systemd"} }
func (s *SystemdWatch) Tags() []string {
	return []string{"persistence", "systemd", "configuration"}
}
func (s *SystemdWatch) DropIns() []skills.DropIn    { return nil }
func (s *SystemdWatch) SetupHints() []string        { return nil }
func (s *SystemdWatch) DeduceCommands(cfg map[string]interface{}) ([]skills.SystemCommand, error) {
	return []skills.SystemCommand{}, nil
}
func (s *SystemdWatch) CheckSystemState() (bool, error) { return true, nil }

func (s *SystemdWatch) Enabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled
}

func (s *SystemdWatch) SetEnabled(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = enabled
}

func (s *SystemdWatch) Config() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

func (s *SystemdWatch) Configure(cfg map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	log.Printf("[systemd-watch] Configure called with config: %+v", cfg)
	s.config = cfg
	return nil
}

func (s *SystemdWatch) Watch(ctx context.Context) (<-chan notifier.Alert, error) {
	log.Printf("[systemd-watch] Watch() called - connecting to D-Bus")

	// Use a private connection: SystemBus() is shared process-wide, and closing
	// it when the watcher stops would break a later restart on reload
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, fmt.Errorf("connecting to system bus: %w", err)
	}

	alerts := make(chan notifier.Alert, 10)

	// Subscribe to specific systemd manager signals via D-Bus match rules.
	// Each entry maps a member name to the options used to add it.
	type matchEntry struct {
		member string
		opts   []dbus.MatchOption
	}
	matchEntries := []matchEntry{
		{
			member: "Reloading",
			opts: []dbus.MatchOption{
				dbus.WithMatchInterface("org.freedesktop.systemd1.Manager"),
				dbus.WithMatchMember("Reloading"),
			},
		},
		{
			member: "UnitFilesChanged",
			opts: []dbus.MatchOption{
				dbus.WithMatchInterface("org.freedesktop.systemd1.Manager"),
				dbus.WithMatchMember("UnitFilesChanged"),
			},
		},
	}

	for _, entry := range matchEntries {
		if err := conn.AddMatchSignal(entry.opts...); err != nil {
			conn.Close()
			return nil, fmt.Errorf("adding match rule for %s: %w", entry.member, err)
		}
		log.Printf("[systemd-watch] Added D-Bus match for member: %s", entry.member)
	}

	// Create signal channel
	signals := make(chan *dbus.Signal, 10)
	conn.Signal(signals)

	// systemd only emits manager signals once a client has called Subscribe;
	// the subscription is dropped when this connection closes
	if call := conn.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1").Call("org.freedesktop.systemd1.Manager.Subscribe", 0); call.Err != nil {
		conn.Close()
		return nil, fmt.Errorf("subscribing to systemd signals: %w", call.Err)
	}

	log.Printf("[systemd-watch] Listening for systemd D-Bus signals")

	go func() {
		defer close(alerts)
		defer conn.Close()

		for {
			select {
			case <-ctx.Done():
				log.Printf("[systemd-watch] Context cancelled, stopping")
				return

			case sig, ok := <-signals:
				if !ok {
					log.Printf("[systemd-watch] Signal channel closed")
					return
				}

				log.Printf("[systemd-watch] Received D-Bus signal: %s from %s", sig.Name, sig.Path)
				s.handleSignal(sig, alerts)
			}
		}
	}()

	return alerts, nil
}

func (s *SystemdWatch) handleSignal(sig *dbus.Signal, alerts chan<- notifier.Alert) {
	var alert notifier.Alert

	switch sig.Name {
	case "org.freedesktop.systemd1.Manager.Reloading":
		// Reloading signal has one boolean argument:
		// true = reloading started, false = reloading finished
		// We only care about the start event, not the finish
		if len(sig.Body) > 0 {
			if reloading, ok := sig.Body[0].(bool); ok {
				if reloading {
					log.Printf("[systemd-watch] systemd daemon-reload executed")
					alert = notifier.Alert{
						Severity:  notifier.SeverityMovement,
						SkillID:   SkillID,
						SkillName: SkillName,
						Title:     "systemd daemon-reload",
						Activity:  "systemctl daemon-reload executed",
						Location:  "systemd",
						Time:      time.Now(),
						Equipment: "systemd-manager",
						Metadata: map[string]string{
							"event": "daemon-reload",
						},
					}
				} else {
					log.Printf("[systemd-watch] systemd daemon-reload finished (no alert)")
					return // Don't send alert for completion
				}
			}
		}

	// case "org.freedesktop.systemd1.Manager.UnitNew":
	// 	// UnitNew: new unit loaded (has unit name and object path)
	// 	if len(sig.Body) >= 2 {
	// 		unitName := fmt.Sprintf("%v", sig.Body[0])
	// 		log.Printf("[systemd-watch] New unit loaded: %s", unitName)
	// 		alert = notifier.Alert{
	// 			Severity:  notifier.SeverityContact,
	// 			SkillID:   SkillID,
	// 			SkillName: SkillName,
	// 			Title:     "New systemd unit loaded",
	// 			Activity:  fmt.Sprintf("Unit loaded: %s", unitName),
	// 			Location:  "systemd",
	// 			Unit:      unitName,
	// 			Time:      time.Now(),
	// 			Equipment: "systemd-unit",
	// 			Metadata: map[string]string{
	// 				"event":     "unit-new",
	// 				"unit_name": unitName,
	// 			},
	// 		}
	// 	}

	// case "org.freedesktop.systemd1.Manager.UnitRemoved":
	// 	// UnitRemoved: unit unloaded (has unit name and object path)
	// 	if len(sig.Body) >= 2 {
	// 		unitName := fmt.Sprintf("%v", sig.Body[0])
	// 		log.Printf("[systemd-watch] Unit removed: %s", unitName)
	// 		alert = notifier.Alert{
	// 			Severity:  notifier.SeverityMovement,
	// 			SkillID:   SkillID,
	// 			SkillName: SkillName,
	// 			Title:     "systemd unit removed",
	// 			Activity:  fmt.Sprintf("Unit unloaded: %s", unitName),
	// 			Location:  "systemd",
	// 			Unit:      unitName,
	// 			Time:      time.Now(),
	// 			Equipment: "systemd-unit",
	// 			Metadata: map[string]string{
	// 				"event":     "unit-removed",
	// 				"unit_name": unitName,
	// 			},
	// 		}
	// 	}

	case "org.freedesktop.systemd1.Manager.UnitFilesChanged":
		// UnitFilesChanged: unit files on disk changed
		log.Printf("[systemd-watch] Unit files changed on disk")
		alert = notifier.Alert{
			Severity:  notifier.SeverityMovement,
			SkillID:   SkillID,
			SkillName: SkillName,
			Title:     "systemd unit files changed",
			Activity:  "Unit files modified on disk",
			Location:  "/etc/systemd/system or /lib/systemd/system",
			Time:      time.Now(),
			Equipment: "systemd-files",
			Metadata: map[string]string{
				"event": "unit-files-changed",
			},
		}

	default:
		log.Printf("[systemd-watch] Unknown signal: %s", sig.Name)
		return
	}

	// Send alert if we created one
	if alert.Title != "" {
		log.Printf("[systemd-watch] Sending alert: %s - %s", alert.Title, alert.Activity)
		alerts <- alert
	}
}
