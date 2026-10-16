package dirwatch

import (
	"testing"

	"github.com/penguinpowernz/fogbot/internal/skills"
)

// The CLI enabler deduces commands from Config(), so a skill built from YAML
// must return that config
func TestNewFromConfig_DeducesCommandsFromConfig(t *testing.T) {
	d := NewFromConfig(skills.SkillConfig{Config: map[string]interface{}{
		"watch_paths": []interface{}{"/etc/cron.d/"},
	}})

	cmds, err := d.DeduceCommands(d.Config())
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 || cmds[0].Command != "auditctl -w /etc/cron.d/ -p wa -k fb-dir-540" {
		t.Fatalf("unexpected commands: %+v", cmds)
	}
}

func TestConfigure_RemovedOptionsReset(t *testing.T) {
	d := New()
	d.Configure(map[string]interface{}{
		"glob_filter": "*.sh",
		"whitelist":   []interface{}{"ok"},
		"recursive":   true,
	})
	d.Configure(map[string]interface{}{})

	if d.globFilter != "" || len(d.whitelist) != 0 || d.recursive {
		t.Fatalf("stale options kept: glob=%q whitelist=%v recursive=%v", d.globFilter, d.whitelist, d.recursive)
	}
}
