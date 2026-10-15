package skills

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsSkillFile(t *testing.T) {
	cases := []struct {
		file, skill string
		want        bool
	}{
		{"500-file-watch.yaml", "file-watch", true},
		{"500-file-watch.yaml", "watch", false},
		{"500-file-watch.yaml", "file", false},
		{"x-file-watch.yaml", "file-watch", false},
		{"-file-watch.yaml", "file-watch", false},
	}
	for _, c := range cases {
		if got := isSkillFile(c.file, c.skill); got != c.want {
			t.Errorf("isSkillFile(%q, %q) = %v, want %v", c.file, c.skill, got, c.want)
		}
	}
}

// A partial name must not disable some other skill
func TestDisable_PartialNameDoesNotMatch(t *testing.T) {
	available, enabled := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(available, "500-file-watch.yaml"), []byte("id: 500\nname: file-watch\n"), 0644)
	if err := Enable("file-watch", available, enabled); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	if IsEnabled("watch", enabled) {
		t.Error("IsEnabled matched a partial skill name")
	}
	if err := Disable("watch", enabled); err == nil {
		t.Error("Disable removed a skill by partial name")
	}
	if !IsEnabled("file-watch", enabled) {
		t.Error("file-watch should still be enabled")
	}
}
