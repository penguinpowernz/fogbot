package procexec

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
		if c.ID == 210 {
			return c.Config
		}
	}
	t.Fatalf("skill 210 not found in shipped YAML")
	return nil
}

func TestShippedYAML(t *testing.T) {
	p := New()
	p.Configure(shippedConfig(t))
	if p.pollInterval != 30*time.Second || len(p.suspiciousPaths) != 3 {
		t.Fatalf("shipped YAML not applied: poll=%v paths=%v", p.pollInterval, p.suspiciousPaths)
	}
}
