package sshmonitor

import (
	"testing"
	"time"

	"github.com/penguinpowernz/fogbot/internal/skills"
)

// shippedConfig returns the config block of the skill YAML shipped in the package,
// so these tests fail if the code and the YAML keys drift apart.
func shippedConfig(t *testing.T) map[string]interface{} {
	t.Helper()
	cfgs, err := skills.LoadAvailable("../../../usr/share/fogbot/contrib/skills-available")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cfgs {
		if c.ID == 100 {
			return c.Config
		}
	}
	t.Fatalf("skill 100 not found in shipped YAML")
	return nil
}

func TestShippedYAML(t *testing.T) {
	s := New()
	s.Configure(shippedConfig(t))
	if s.bruteForceThreshold != 5 || s.bruteForceWindow != 60*time.Second || !s.alertNewIPLogin {
		t.Fatalf("shipped YAML not applied: threshold=%d window=%v alertNewIP=%v", s.bruteForceThreshold, s.bruteForceWindow, s.alertNewIPLogin)
	}
}
