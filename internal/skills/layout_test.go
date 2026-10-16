package skills

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shippedSkills is where the package's skill YAMLs live, relative to this dir
const shippedSkills = "../../usr/share/fogbot/contrib/skills-available"

// TestEverySkillHasAREADME checks each shipped skill has a directory here,
// named after it without dashes, with a README.md describing it
func TestEverySkillHasAREADME(t *testing.T) {
	cfgs, err := LoadAvailable(shippedSkills)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfgs) == 0 {
		t.Fatalf("no skill YAMLs found in %s", shippedSkills)
	}

	for _, cfg := range cfgs {
		readme := filepath.Join(strings.ReplaceAll(cfg.Name, "-", ""), "README.md")
		if _, err := os.Stat(readme); err != nil {
			t.Errorf("skill %d %s has no %s", cfg.ID, cfg.Name, readme)
		}
	}
}
