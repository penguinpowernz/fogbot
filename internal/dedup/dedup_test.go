package dedup

import "testing"

func TestNewEngine_ZeroWindowDoesNotPanic(t *testing.T) {
	e := NewEngine(0, 0)
	defer e.Close()
	if e.window <= 0 || e.maxBurst <= 0 {
		t.Fatalf("expected defaults, got window=%v maxBurst=%d", e.window, e.maxBurst)
	}
}
