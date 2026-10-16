package main

import (
	"context"
	"fmt"
	"log"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
)

// watcherStopTimeout bounds how long a reload waits for a stopped watcher to exit
const watcherStopTimeout = 10 * time.Second

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

	mu      sync.Mutex
	running map[int]*runningSkill
}

type runningSkill struct {
	cancel context.CancelFunc
	done   chan struct{} // closed when the watcher's alert channel closes
	config map[string]interface{}
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

	var res reloadResult
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
		case !keep:
			m.stop(skill, r)
			skill.SetEnabled(false)
			res.stopped = append(res.stopped, skill.Name())
		case !reflect.DeepEqual(cfg.Config, r.config):
			m.stop(skill, r)
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
		if err := m.repair(skill); err != nil {
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
		defer close(r.done)
		forwardAlerts(m.ctx, alerts, m.bus)
	}()

	log.Printf("Started watcher for skill #%d: %s", skill.ID(), skill.Name())
	return true
}

// stop cancels a skill's watcher and waits for it to exit so it can be safely
// reconfigured. Caller holds mu.
func (m *skillManager) stop(skill skills.Skill, r *runningSkill) {
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(watcherStopTimeout):
		log.Printf("Warning: watcher for skill %s did not exit within %v", skill.Name(), watcherStopTimeout)
	}
	delete(m.running, skill.ID())
	log.Printf("Stopped watcher for skill #%d: %s", skill.ID(), skill.Name())
}

// runningNames returns the names of the skills whose watchers are running
func (m *skillManager) runningNames() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.running))
	for id := range m.running {
		if skill, ok := m.registry.Get(id); ok {
			names = append(names, skill.Name())
		}
	}
	sort.Strings(names)
	return names
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
