package auditdhealth

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
		if c.ID == 420 {
			return c.Config
		}
	}
	t.Fatalf("skill 420 not found in shipped YAML")
	return nil
}

func TestShippedYAML(t *testing.T) {
	a := New()
	a.Configure(shippedConfig(t))
	if a.checkInterval != 30*time.Second || a.auditLogPath != "/var/log/audit/audit.log" || a.maxLogAge != 2*time.Minute {
		t.Fatalf("shipped YAML not applied: interval=%v path=%q maxAge=%v", a.checkInterval, a.auditLogPath, a.maxLogAge)
	}
}
