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
	go func() {
		<-ctx.Done()
		time.Sleep(20 * time.Millisecond) // a watcher that takes a moment to wind down
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
