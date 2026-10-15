package skills

// Deadman tracks which health conditions are failing, so DEADMAN checks can
// alert when a condition starts and when it clears instead of on every poll.
// The zero value is ready to use. Not safe for concurrent use; each check
// loop owns its own.
type Deadman struct {
	failing map[string]bool
}

// Fail records that the condition is failing and reports whether it just started
func (d *Deadman) Fail(key string) bool {
	if d.failing == nil {
		d.failing = make(map[string]bool)
	}
	if d.failing[key] {
		return false
	}
	d.failing[key] = true
	return true
}

// Pass records that the condition is healthy and reports whether it just recovered
func (d *Deadman) Pass(key string) bool {
	if !d.failing[key] {
		return false
	}
	delete(d.failing, key)
	return true
}
