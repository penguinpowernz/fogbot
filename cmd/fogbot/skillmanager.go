package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
)

// watcherStopTimeout bounds how long a reload waits for a stopped watcher to
// exit. A variable so tests can shorten it.
var watcherStopTimeout = 10 * time.Second

// stateCheckInterval is how often running skills' system config (audit rules,
// iptables rules) is checked. It doesn't only go missing across reboots:
// restarting auditd reloads its rules files, which deletes every rule added
// with auditctl, and anyone with root can flush the iptables raw table. Until
// fogbot restarted, those skills would sit there watching for events that
// could no longer happen.
const stateCheckInterval = 5 * time.Minute

// skillManager starts and stops skill watchers to match the enabled skill
// configs, so `fogbot skill enable/disable` followed by SIGHUP takes effect
// without a restart. All watchers feed one alert bus.
type skillManager struct {
	ctx      context.Context
	registry *skills.Registry
	bus      chan<- notifier.Alert
	hostname string

	// repair restores missing system config before a skill starts; nil disables it
	repair func(skills.Skill) error

	// enabledOnDisk reports whether a skill is still enabled in skills-enabled;
	// nil means always
	enabledOnDisk func(skills.Skill) bool

	mu      sync.Mutex
	running map[int]*runningSkill

	// configs are the enabled skill configs last applied. Guarded by mu.
	configs []skills.SkillConfig

	// missing tracks skills whose system config was found missing and could
	// not be restored, so that is alerted once rather than on every check.
	// Guarded by mu.
	missing skills.Deadman
}

type runningSkill struct {
	cancel context.CancelFunc
	done   chan struct{} // closed when the watcher's alert channel closes
	config map[string]interface{}

	// stopping is set when the watcher was told to stop but didn't exit in
	// time. Its skill isn't configured or started again until it has: each
	// skill is one object, which the old watcher is still using.
	stopping atomic.Bool
}

// exited reports whether the watcher has stopped
func (r *runningSkill) exited() bool {
	select {
	case <-r.done:
		return true
	default:
		return false
	}
}

// reloadResult lists skill names affected by apply
type reloadResult struct {
	started, stopped, restarted, failed []string
}

func (r reloadResult) changed() bool {
	return len(r.started)+len(r.stopped)+len(r.restarted)+len(r.failed) > 0
}

func (r reloadResult) String() string {
	var parts []string
	for _, p := range []struct {
		verb  string
		names []string
	}{{"started", r.started}, {"stopped", r.stopped}, {"restarted", r.restarted}, {"failed", r.failed}} {
		if len(p.names) > 0 {
			parts = append(parts, p.verb+" "+strings.Join(p.names, ", "))
		}
	}
	if len(parts) == 0 {
		return "no changes"
	}
	return strings.Join(parts, "; ")
}

func newSkillManager(ctx context.Context, registry *skills.Registry, bus chan<- notifier.Alert, hostname string) *skillManager {
	return &skillManager{
		ctx:      ctx,
		registry: registry,
		bus:      bus,
		hostname: hostname,
		running:  make(map[int]*runningSkill),
	}
}

// apply makes the running watchers match configs: stops skills no longer
// enabled, starts newly enabled ones and restarts those whose config changed.
func (m *skillManager) apply(configs []skills.SkillConfig) reloadResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configs = configs
	return m.applyLocked()
}

// reapply applies the last configs again, once a watcher that was slow to
// stop has exited and its skill can be started
func (m *skillManager) reapply() {
	m.mu.Lock()
	defer m.mu.Unlock()
	log.Printf("Skills: %s", m.applyLocked())
}

// applyLocked makes the running watchers match m.configs. Caller holds mu.
func (m *skillManager) applyLocked() reloadResult {
	configs := m.configs
	var res reloadResult

	// A watcher that died on its own is started again, like a newly enabled skill
	for id, r := range m.running {
		if r.exited() {
			r.cancel()
			if skill, ok := m.registry.Get(id); ok {
				skill.SetEnabled(false)
			}
			delete(m.running, id)
		}
	}

	want := make(map[int]skills.SkillConfig)
	for _, cfg := range configs {
		if _, ok := m.registry.Get(cfg.ID); !ok {
			log.Printf("Warning: skill %d (%s) enabled but not in registry", cfg.ID, cfg.Name)
			continue
		}
		want[cfg.ID] = cfg
	}

	for id, r := range m.running {
		skill, _ := m.registry.Get(id)
		cfg, keep := want[id]
		switch {
		case r.stopping.Load():
			// Still winding down from an earlier reload; reapply starts it
			// again once it has
			if keep {
				res.failed = append(res.failed, skill.Name())
			}
		case !keep:
			if !m.stop(skill, r) {
				res.failed = append(res.failed, skill.Name())
				continue
			}
			skill.SetEnabled(false)
			res.stopped = append(res.stopped, skill.Name())
		case !reflect.DeepEqual(cfg.Config, r.config):
			if !m.stop(skill, r) {
				res.failed = append(res.failed, skill.Name())
				continue
			}
			if m.start(skill, cfg) {
				res.restarted = append(res.restarted, skill.Name())
			} else {
				res.failed = append(res.failed, skill.Name())
			}
		}
	}

	ids := make([]int, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		if _, ok := m.running[id]; ok {
			continue
		}
		skill, _ := m.registry.Get(id)
		if m.start(skill, want[id]) {
			res.started = append(res.started, skill.Name())
		} else {
			res.failed = append(res.failed, skill.Name())
		}
	}

	return res
}

// start configures, repairs and starts a skill's watcher. Caller holds mu.
func (m *skillManager) start(skill skills.Skill, cfg skills.SkillConfig) bool {
	if err := skill.Configure(cfg.Config); err != nil {
		log.Printf("Failed to configure skill %s: %v", skill.Name(), err)
		return false
	}
	skill.SetEnabled(true)

	if m.repair != nil {
		key := strconv.Itoa(skill.ID())
		m.missing.Pass(key)
		if err := m.repair(skill); err != nil {
			// Alerted here, so the state check doesn't alert again
			m.missing.Fail(key)
			log.Printf("Startup repair failed for skill #%d %s: %v", skill.ID(), skill.Name(), err)
			m.send(notifier.Alert{
				Severity:  notifier.SeverityMovement,
				SkillID:   skill.ID(),
				SkillName: skill.Name(),
				Title:     "Startup Repair Failed",
				Activity:  fmt.Sprintf("System config for %s could not be restored; the skill may not detect anything", skill.Name()),
				Location:  m.hostname,
				Unit:      err.Error(),
				Time:      time.Now(),
				Equipment: "startup-repair",
			})
		}
	}

	ctx, cancel := context.WithCancel(m.ctx)
	alerts, err := skill.Watch(ctx)
	if err != nil {
		cancel()
		skill.SetEnabled(false)
		log.Printf("Failed to start skill %s: %v", skill.Name(), err)
		return false
	}

	r := &runningSkill{cancel: cancel, done: make(chan struct{}), config: cfg.Config}
	m.running[skill.ID()] = r
	go func() {
		defer func() {
			close(r.done)
			if r.stopping.Load() && m.ctx.Err() == nil {
				log.Printf("Watcher for skill #%d %s has now stopped", skill.ID(), skill.Name())
				go m.reapply()
			}
		}()
		forwardAlerts(m.ctx, alerts, m.bus)

		// The watcher closed its channel without being stopped, e.g. the log
		// it tails became unreadable or the D-Bus connection dropped. Its
		// sensor is now blind, which must not go unnoticed.
		if ctx.Err() == nil {
			log.Printf("Watcher for skill #%d %s exited unexpectedly", skill.ID(), skill.Name())
			m.send(notifier.Alert{
				Severity:    notifier.SeverityContact,
				SkillID:     skill.ID(),
				SkillName:   skill.Name(),
				Title:       "[DEADMAN] Sensor Stopped",
				Activity:    fmt.Sprintf("The %s watcher stopped unexpectedly and is no longer detecting anything", skill.Name()),
				Location:    m.hostname,
				Unit:        "see the fogbot daemon log for the cause; restart it with: systemctl reload fogbot",
				Time:        time.Now(),
				Equipment:   "skill-manager",
				Acknowledge: true,
			})
		}
	}()

	log.Printf("Started watcher for skill #%d: %s", skill.ID(), skill.Name())
	return true
}

// stop cancels a skill's watcher and waits for it to exit so it can be safely
// reconfigured, reporting whether it did. One that doesn't exit in time is
// left marked as stopping; reconfiguring it then would race with the watcher
// still using it. Caller holds mu.
func (m *skillManager) stop(skill skills.Skill, r *runningSkill) bool {
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(watcherStopTimeout):
		r.stopping.Store(true)
		// The watcher closes done before it looks at stopping, so one that
		// exited just now has either been seen here or will reapply itself
		if !r.exited() {
			log.Printf("Warning: watcher for skill %s did not exit within %v; it will be restarted once it has", skill.Name(), watcherStopTimeout)
			return false
		}
	}
	delete(m.running, skill.ID())
	log.Printf("Stopped watcher for skill #%d: %s", skill.ID(), skill.Name())
	return true
}

// runningNames returns the names of the skills whose watchers are running
func (m *skillManager) runningNames() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.running))
	for id, r := range m.running {
		if r.exited() || r.stopping.Load() {
			continue
		}
		if skill, ok := m.registry.Get(id); ok {
			names = append(names, skill.Name())
		}
	}
	sort.Strings(names)
	return names
}

// watchSystemState checks the running skills' system config every interval
// until the daemon stops
func (m *skillManager) watchSystemState(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.checkSystemState()
		}
	}
}

// checkSystemState restores system config that has gone missing from running
// skills, using only approved commands, and alerts on each disappearance
func (m *skillManager) checkSystemState() {
	m.mu.Lock()
	defer m.mu.Unlock()

	ids := make([]int, 0, len(m.running))
	for id := range m.running {
		ids = append(ids, id)
	}
	sort.Ints(ids)

	for _, id := range ids {
		if r := m.running[id]; r.exited() || r.stopping.Load() {
			continue
		}
		skill, _ := m.registry.Get(id)
		key := strconv.Itoa(id)

		configured, err := skill.CheckSystemState()
		if err == nil && !configured && m.enabledOnDisk != nil && !m.enabledOnDisk(skill) {
			// `fogbot skill disable` removed it; the reload that stops the
			// watcher hasn't happened yet
			log.Printf("[state-check] Skill #%d %s was disabled on the host; reload fogbot to stop it", id, skill.Name())
			continue
		}
		if err != nil {
			log.Printf("[state-check] Could not check system config for skill #%d %s: %v", id, skill.Name(), err)
			continue
		}
		if configured {
			m.missing.Pass(key)
			continue
		}

		log.Printf("[state-check] System config for skill #%d %s is missing", id, skill.Name())
		repairErr := errors.New("startup repair is unavailable")
		if m.repair != nil {
			repairErr = m.repair(skill)
		}

		// Restored: a later disappearance is a new event and alerts again.
		// Not restored: alert once, not on every check, until it is fixed.
		alert := notifier.Alert{
			SkillID:     skill.ID(),
			SkillName:   skill.Name(),
			Location:    m.hostname,
			Time:        time.Now(),
			Equipment:   "state-check",
			Acknowledge: true,
		}
		if repairErr == nil {
			m.missing.Pass(key)
			alert.Severity = notifier.SeverityMovement
			alert.Title = "System Config Restored"
			alert.Activity = fmt.Sprintf("System config for %s (e.g. audit or iptables rules) disappeared while fogbot was running and was put back", skill.Name())
			alert.Unit = "expected after restarting auditd; otherwise someone removed fogbot's rules"
		} else {
			if !m.missing.Fail(key) {
				continue
			}
			alert.Severity = notifier.SeverityContact
			alert.Title = "System Config Missing"
			alert.Activity = fmt.Sprintf("System config for %s disappeared while fogbot was running and could not be restored; the skill can't detect anything", skill.Name())
			alert.Unit = repairErr.Error()
		}
		log.Printf("[state-check] %s: %s", alert.Title, alert.Activity)
		m.send(alert)
	}
}

func (m *skillManager) send(alert notifier.Alert) {
	select {
	case m.bus <- alert:
	case <-m.ctx.Done():
	}
}

// forwardAlerts copies a watcher's alerts onto the bus until the watcher closes
// its channel. After the daemon context ends it drops alerts but keeps
// draining, so a watcher is never left blocked sending.
func forwardAlerts(ctx context.Context, alerts <-chan notifier.Alert, bus chan<- notifier.Alert) {
	for alert := range alerts {
		select {
		case bus <- alert:
		case <-ctx.Done():
		}
	}
}
