package systemdwatch

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
)

const (
	SkillID   = 550
	SkillName = "systemd-watch"
)

// dpkgLocks are the locks dpkg and its frontends (apt, unattended-upgrades,
// PackageKit) hold for the whole of a package run, maintainer scripts included
var dpkgLocks = []string{"/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock"}

// SystemdWatch monitors systemd via D-Bus for daemon-reload and unit changes
type SystemdWatch struct {
	mu              sync.RWMutex
	enabled         bool
	config          map[string]interface{}
	quietDuringDpkg bool
	dpkgLocks       []string
}

// New creates a SystemdWatch with default config (used by daemon registry).
func New() *SystemdWatch {
	return &SystemdWatch{
		enabled:         false,
		quietDuringDpkg: true,
		dpkgLocks:       dpkgLocks,
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
	if v, ok := cfg["quiet_during_dpkg"].(bool); ok {
		s.quietDuringDpkg = v
	}
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
				// Any client on the system bus can emit a signal with this
				// interface; only accept the ones systemd itself sends
				dbus.WithMatchSender("org.freedesktop.systemd1"),
				dbus.WithMatchInterface("org.freedesktop.systemd1.Manager"),
				dbus.WithMatchMember("Reloading"),
			},
		},
		{
			member: "UnitFilesChanged",
			opts: []dbus.MatchOption{
				// Any client on the system bus can emit a signal with this
				// interface; only accept the ones systemd itself sends
				dbus.WithMatchSender("org.freedesktop.systemd1"),
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

				if !fromSystemd(conn, sig) {
					log.Printf("[systemd-watch] Ignoring %s from %s: not sent by systemd", sig.Name, sig.Sender)
					continue
				}

				log.Printf("[systemd-watch] Received D-Bus signal: %s from %s", sig.Name, sig.Path)
				s.handleSignal(sig, alerts)
			}
		}
	}()

	return alerts, nil
}

// fromSystemd reports whether sig was sent by systemd. The match rules only
// filter broadcast signals: the system bus lets any local user send a signal
// straight to this connection, so a forged Reloading or UnitFilesChanged would
// otherwise raise alerts. The owner is looked up per signal because systemd
// gets a new unique name when it re-executes.
func fromSystemd(conn *dbus.Conn, sig *dbus.Signal) bool {
	if sig.Path != "/org/freedesktop/systemd1" {
		return false
	}
	var owner string
	if err := conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0, "org.freedesktop.systemd1").Store(&owner); err != nil {
		log.Printf("[systemd-watch] Failed to look up systemd's bus name: %v", err)
		return false
	}
	return sig.Sender == owner
}

// dpkgRunning reports whether any of locks is held by another process, which
// for the dpkg locks means a package is being installed, removed or upgraded.
// F_GETLK only tests the lock; it never takes it, so dpkg is not blocked.
func dpkgRunning(locks []string) bool {
	for _, path := range locks {
		f, err := os.Open(path)
		if err != nil {
			continue // no dpkg on this system, or nothing has ever locked it
		}
		lk := syscall.Flock_t{Type: syscall.F_WRLCK}
		err = syscall.FcntlFlock(f.Fd(), syscall.F_GETLK, &lk)
		f.Close()
		if err == nil && lk.Type != syscall.F_UNLCK {
			return true
		}
	}
	return false
}

func (s *SystemdWatch) handleSignal(sig *dbus.Signal, alerts chan<- notifier.Alert) {
	s.mu.RLock()
	quiet, locks := s.quietDuringDpkg, s.dpkgLocks
	s.mu.RUnlock()

	// Package maintainer scripts reload systemd and enable units as a matter
	// of course; pkg-monitor reports the package change itself
	if quiet && dpkgRunning(locks) {
		log.Printf("[systemd-watch] Ignoring %s: dpkg is running", sig.Name)
		return
	}

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
