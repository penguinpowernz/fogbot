package logfreshness

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
		if c.ID == 400 {
			return c.Config
		}
	}
	t.Fatalf("skill 400 not found in shipped YAML")
	return nil
}

func TestShippedYAML(t *testing.T) {
	l := New()
	l.Configure(shippedConfig(t))
	if len(l.watchedLogs) != 2 || l.watchedLogs["/var/log/auth.log"] != 10*time.Minute || l.watchedLogs["/var/log/syslog"] != 5*time.Minute {
		t.Fatalf("shipped YAML not applied: %v", l.watchedLogs)
	}
}
