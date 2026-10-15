package pkgmonitor

import (
	"testing"

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
		if c.ID == 300 {
			return c.Config
		}
	}
	t.Fatalf("skill 300 not found in shipped YAML")
	return nil
}

func TestShippedYAML(t *testing.T) {
	p := New()
	p.Configure(shippedConfig(t))
	if p.logPath != "/var/log/dpkg.log" || !p.alertOnInstall || !p.alertOnRemove || p.alertOnUpgrade {
		t.Fatalf("shipped YAML not applied: %+v", p)
	}
}
