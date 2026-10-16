package procexec

import (
	"testing"
	"time"
)

// time.NewTicker panics on a non-positive interval, which would crash the daemon
func TestConfigure_IgnoresNonPositiveInterval(t *testing.T) {
	for _, v := range []string{"0s", "-5s"} {
		p := New()
		p.Configure(map[string]interface{}{"poll_interval": v})
		if p.pollInterval != 5*time.Second {
			t.Errorf("poll_interval %q: got %v, want the 5s default", v, p.pollInterval)
		}
	}
}
