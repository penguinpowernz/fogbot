package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/penguinpowernz/fogbot/internal/skills"
)

// TestEverySkillImplementationCanBeEnabled checks the CLI can instantiate each
// shipped skill that has code, so `fogbot skill enable` doesn't report an
// implemented skill as missing one.
func TestEverySkillImplementationCanBeEnabled(t *testing.T) {
	cfgs, err := skills.LoadAvailable("../../usr/share/fogbot/contrib/skills-available")
	if err != nil {
		t.Fatal(err)
	}

	for _, cfg := range cfgs {
		dir := filepath.Join("../../internal/skills", strings.ReplaceAll(cfg.Name, "-", ""))
		if !hasCode(t, dir) {
			continue
		}

		s := instantiateSkill(cfg)
		if s == nil {
			t.Errorf("skill %d %s is implemented in %s but instantiateSkill doesn't know it", cfg.ID, cfg.Name, dir)
			continue
		}
		if s.ID() != cfg.ID {
			t.Errorf("instantiateSkill(%d) returned skill %d", cfg.ID, s.ID())
		}
	}
}

// hasCode reports whether dir holds non-test Go files
func hasCode(t *testing.T, dir string) bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if !strings.HasSuffix(f, "_test.go") {
			return true
		}
	}
	return false
}
