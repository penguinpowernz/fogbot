package servicehealth

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
		if c.ID == 410 {
			return c.Config
		}
	}
	t.Fatalf("skill 410 not found in shipped YAML")
	return nil
}

func TestShippedYAML(t *testing.T) {
	s := New()
	s.Configure(shippedConfig(t))
	if len(s.services) != 2 || s.services[1] != "auditd" || s.checkInterval != 60*time.Second {
		t.Fatalf("shipped YAML not applied: services=%v interval=%v", s.services, s.checkInterval)
	}
}
