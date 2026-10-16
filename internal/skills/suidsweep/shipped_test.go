package suidsweep

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
		if c.ID == 200 {
			return c.Config
		}
	}
	t.Fatalf("skill 200 not found in shipped YAML")
	return nil
}

func TestShippedYAML(t *testing.T) {
	s := New(nil)
	s.Configure(shippedConfig(t))
	if s.sweepInterval != time.Hour {
		t.Errorf("expected sweep_interval 1h, got %v", s.sweepInterval)
	}
	if len(s.searchPaths) != 6 || s.searchPaths[0] != "/bin" {
		t.Errorf("expected watch_paths from YAML, got %v", s.searchPaths)
	}
	if len(s.noSuidPaths) != 5 || s.noSuidPaths[0] != "/home" {
		t.Errorf("expected no_suid_paths from YAML, got %v", s.noSuidPaths)
	}
}
