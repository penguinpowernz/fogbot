package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
)

// stubSkill records its lifecycle; its watcher runs until cancelled
type stubSkill struct {
	skills.Skill
	id   int
	name string

	mu       sync.Mutex
	enabled  bool
	config   map[string]interface{}
	watching int // live watchers
	starts   int

	stopDelay time.Duration // how long the watcher takes to exit once cancelled
}

func (s *stubSkill) ID() int      { return s.id }
func (s *stubSkill) Name() string { return s.name }
func (s *stubSkill) Configure(c map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.watching > 0 {
		panic("reconfigured while its watcher was still running")
	}
	s.config = c
	return nil
}
func (s *stubSkill) SetEnabled(e bool) { s.mu.Lock(); s.enabled = e; s.mu.Unlock() }
func (s *stubSkill) Watch(ctx context.Context) (<-chan notifier.Alert, error) {
	s.mu.Lock()
	s.watching++
	s.starts++
	s.mu.Unlock()
	ch := make(chan notifier.Alert)
	delay := s.stopDelay
	if delay == 0 {
		delay = 20 * time.Millisecond // a watcher that takes a moment to wind down
	}
	go func() {
		<-ctx.Done()
		time.Sleep(delay)
		s.mu.Lock()
		s.watching--
		s.mu.Unlock()
		close(ch)
	}()
	return ch, nil
}

func (s *stubSkill) state() (bool, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enabled, s.watching, s.starts
}

func cfg(id int, c map[string]interface{}) skills.SkillConfig {
	return skills.SkillConfig{ID: id, Config: c}
}

func TestSkillManager_ReloadStartsStopsAndRestarts(t *testing.T) {
	a := &stubSkill{id: 1, name: "a"}
	b := &stubSkill{id: 2, name: "b"}
	reg := skills.NewRegistry()
	reg.Register(a)
	reg.Register(b)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newSkillManager(ctx, reg, make(chan notifier.Alert, 10), "host")

	res := m.apply([]skills.SkillConfig{cfg(1, map[string]interface{}{"x": 1})})
	if len(res.started) != 1 {
		t.Fatalf("expected a to start, got %s", res)
	}
	if en, w, _ := a.state(); !en || w != 1 {
		t.Fatalf("a should be enabled and watching, enabled=%v watching=%d", en, w)
	}

	// Same config again: nothing changes
	if res := m.apply([]skills.SkillConfig{cfg(1, map[string]interface{}{"x": 1})}); res.changed() {
		t.Fatalf("expected no change, got %s", res)
	}

	// Enable b and change a's config
	res = m.apply([]skills.SkillConfig{cfg(1, map[string]interface{}{"x": 2}), cfg(2, nil)})
	if len(res.started) != 1 || len(res.restarted) != 1 {
		t.Fatalf("expected b started and a restarted, got %s", res)
	}
	if _, w, starts := a.state(); w != 1 || starts != 2 {
		t.Fatalf("a should have one live watcher after restart, watching=%d starts=%d", w, starts)
	}

	// Disable a
	res = m.apply([]skills.SkillConfig{cfg(2, nil)})
	if len(res.stopped) != 1 {
		t.Fatalf("expected a stopped, got %s", res)
	}
	if en, w, _ := a.state(); en || w != 0 {
		t.Fatalf("a should be disabled with no watcher, enabled=%v watching=%d", en, w)
	}
	if _, w, _ := b.state(); w != 1 {
		t.Fatal("b should still be watching")
	}
}

func TestSkillManager_UnknownSkillIgnored(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newSkillManager(ctx, skills.NewRegistry(), make(chan notifier.Alert, 1), "host")
	if res := m.apply([]skills.SkillConfig{cfg(99, nil)}); res.changed() {
		t.Fatalf("unknown skill should be ignored, got %s", res)
	}
}

func TestSkillManager_RepairFailureAlerts(t *testing.T) {
	a := &stubSkill{id: 1, name: "a"}
	reg := skills.NewRegistry()
	reg.Register(a)
	bus := make(chan notifier.Alert, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newSkillManager(ctx, reg, bus, "host")
	m.repair = func(skills.Skill) error { return context.DeadlineExceeded }

	m.apply([]skills.SkillConfig{cfg(1, nil)})
	select {
	case alert := <-bus:
		if alert.Title != "Startup Repair Failed" {
			t.Fatalf("unexpected alert %+v", alert)
		}
	default:
		t.Fatal("expected a repair failure alert")
	}
	if _, w, _ := a.state(); w != 1 {
		t.Fatal("the skill should still start after a failed repair")
	}
}

func TestReloadResult_String(t *testing.T) {
	if got := (reloadResult{}).String(); got != "no changes" {
		t.Errorf("got %q", got)
	}
	r := reloadResult{started: []string{"a", "b"}, stopped: []string{"c"}}
	if got := r.String(); got != "started a, b; stopped c" {
		t.Errorf("got %q", got)
	}
}

// dyingSkill's watcher stops on its own as soon as die is closed, like a tail
// whose log became unreadable
type dyingSkill struct {
	stubSkill
	die chan struct{}
}

func (s *dyingSkill) Watch(ctx context.Context) (<-chan notifier.Alert, error) {
	ch := make(chan notifier.Alert)
	die := s.die
	go func() {
		select {
		case <-die:
		case <-ctx.Done():
		}
		close(ch)
	}()
	return ch, nil
}

func waitAlert(t *testing.T, bus <-chan notifier.Alert) notifier.Alert {
	t.Helper()
	select {
	case a := <-bus:
		return a
	case <-time.After(2 * time.Second):
		t.Fatal("expected an alert")
	}
	return notifier.Alert{}
}

// The bug: a watcher that exited by itself left its skill listed as running,
// with no alert, so a blind sensor looked healthy in /status
func TestSkillManager_DeadWatcherAlertsAndRestartsOnReload(t *testing.T) {
	a := &dyingSkill{stubSkill: stubSkill{id: 1, name: "a"}, die: make(chan struct{})}
	reg := skills.NewRegistry()
	reg.Register(a)
	bus := make(chan notifier.Alert, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newSkillManager(ctx, reg, bus, "host")

	m.apply([]skills.SkillConfig{cfg(1, nil)})
	close(a.die)

	if alert := waitAlert(t, bus); alert.Title != "[DEADMAN] Sensor Stopped" || alert.Severity != notifier.SeverityContact {
		t.Fatalf("unexpected alert %+v", alert)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(m.runningNames()) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("dead watcher still listed as running: %v", m.runningNames())
		}
		time.Sleep(5 * time.Millisecond)
	}

	a.die = make(chan struct{})
	if res := m.apply([]skills.SkillConfig{cfg(1, nil)}); len(res.started) != 1 {
		t.Fatalf("reload should start the dead skill again, got %s", res)
	}
	if got := m.runningNames(); len(got) != 1 {
		t.Fatalf("expected a running again, got %v", got)
	}
}

func TestSkillManager_StoppedWatcherDoesNotAlert(t *testing.T) {
	a := &stubSkill{id: 1, name: "a"}
	reg := skills.NewRegistry()
	reg.Register(a)
	bus := make(chan notifier.Alert, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newSkillManager(ctx, reg, bus, "host")

	m.apply([]skills.SkillConfig{cfg(1, nil)})
	m.apply(nil)
	select {
	case alert := <-bus:
		t.Fatalf("disabling a skill raised %+v", alert)
	case <-time.After(50 * time.Millisecond):
	}
}

// stateSkill reports its system config as present or not
type stateSkill struct {
	stubSkill
	configured bool
}

func (s *stateSkill) CheckSystemState() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.configured, nil
}

func (s *stateSkill) setConfigured(c bool) { s.mu.Lock(); s.configured = c; s.mu.Unlock() }

// The bug: restarting auditd deletes rules added with auditctl, and the skills
// relying on them went blind until fogbot itself restarted
func TestSkillManager_StateCheckRestoresMissingConfig(t *testing.T) {
	a := &stateSkill{stubSkill: stubSkill{id: 1, name: "a"}, configured: true}
	reg := skills.NewRegistry()
	reg.Register(a)
	bus := make(chan notifier.Alert, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newSkillManager(ctx, reg, bus, "host")
	m.apply([]skills.SkillConfig{cfg(1, nil)})

	repairs := 0
	var repairErr error
	m.repair = func(skills.Skill) error {
		repairs++
		if repairErr == nil {
			a.setConfigured(true)
		}
		return repairErr
	}

	m.checkSystemState()
	if repairs != 0 || len(bus) != 0 {
		t.Fatalf("configured skill was repaired (%d) or alerted (%d)", repairs, len(bus))
	}

	// Rules removed: put back, with a heads-up
	a.setConfigured(false)
	m.checkSystemState()
	if alert := waitAlert(t, bus); repairs != 1 || alert.Title != "System Config Restored" || alert.Severity != notifier.SeverityMovement {
		t.Fatalf("repairs=%d alert=%+v", repairs, alert)
	}

	// Removed again later: a new event, so a new alert
	a.setConfigured(false)
	m.checkSystemState()
	if alert := waitAlert(t, bus); alert.Title != "System Config Restored" {
		t.Fatalf("second removal: unexpected alert %+v", alert)
	}

	// Can't be restored: CONTACT once, retried quietly after that
	repairErr = context.DeadlineExceeded
	a.setConfigured(false)
	m.checkSystemState()
	if alert := waitAlert(t, bus); alert.Title != "System Config Missing" || alert.Severity != notifier.SeverityContact {
		t.Fatalf("unexpected alert %+v", alert)
	}
	m.checkSystemState()
	if len(bus) != 0 || repairs != 4 {
		t.Fatalf("expected a quiet retry, got %d alerts and %d repairs", len(bus), repairs)
	}
}

func TestSkillManager_StateCheckDoesNotRepeatStartupRepairAlert(t *testing.T) {
	a := &stateSkill{stubSkill: stubSkill{id: 1, name: "a"}}
	reg := skills.NewRegistry()
	reg.Register(a)
	bus := make(chan notifier.Alert, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newSkillManager(ctx, reg, bus, "host")
	m.repair = func(skills.Skill) error { return context.DeadlineExceeded }

	m.apply([]skills.SkillConfig{cfg(1, nil)})
	if alert := waitAlert(t, bus); alert.Title != "Startup Repair Failed" {
		t.Fatalf("unexpected alert %+v", alert)
	}
	m.checkSystemState()
	if len(bus) != 0 {
		t.Fatalf("state check repeated the startup repair alert: %+v", <-bus)
	}
}

// A watcher that outlives the stop timeout used to be reconfigured and
// started again while it was still running, two watchers sharing one skill
func TestSkillManager_SlowStopIsNotReconfiguredUntilItExits(t *testing.T) {
	old := watcherStopTimeout
	watcherStopTimeout = 20 * time.Millisecond
	t.Cleanup(func() { watcherStopTimeout = old })

	a := &stubSkill{id: 1, name: "a", stopDelay: 200 * time.Millisecond}
	reg := skills.NewRegistry()
	reg.Register(a)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newSkillManager(ctx, reg, make(chan notifier.Alert, 10), "host")

	m.apply([]skills.SkillConfig{cfg(1, map[string]interface{}{"x": 1})})
	// stubSkill.Configure panics if called while its watcher still runs
	res := m.apply([]skills.SkillConfig{cfg(1, map[string]interface{}{"x": 2})})
	if len(res.failed) != 1 {
		t.Fatalf("expected the slow skill reported as failed, got %s", res)
	}
	if names := m.runningNames(); len(names) != 0 {
		t.Fatalf("a stopping watcher was reported running: %v", names)
	}

	// Once it has exited it is started again with the new config
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, w, starts := a.state()
		a.mu.Lock()
		x := a.config["x"]
		a.mu.Unlock()
		if starts == 2 && w == 1 && x == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not restarted after stopping: starts=%d watching=%d config=%v", starts, w, x)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// `fogbot skill disable` removes a skill's rules before the reload that stops
// it; that isn't the tampering the state check alerts on
func TestSkillManager_StateCheckIgnoresSkillDisabledOnHost(t *testing.T) {
	a := &stateSkill{stubSkill: stubSkill{id: 1, name: "a"}, configured: true}
	reg := skills.NewRegistry()
	reg.Register(a)
	bus := make(chan notifier.Alert, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newSkillManager(ctx, reg, bus, "host")
	m.apply([]skills.SkillConfig{cfg(1, nil)})

	repairs := 0
	m.repair = func(skills.Skill) error { repairs++; return nil }
	m.enabledOnDisk = func(skills.Skill) bool { return false }

	a.setConfigured(false)
	m.checkSystemState()
	if repairs != 0 || len(bus) != 0 {
		t.Fatalf("disabled skill was repaired (%d) or alerted (%d)", repairs, len(bus))
	}
}
