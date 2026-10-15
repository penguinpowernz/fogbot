package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveStateDir(t *testing.T) {
	defer func(c, s string) { configPath, stateDir = c, s }(configPath, stateDir)

	cfgFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgFile, []byte("state_dir: /from/config\n"), 0600); err != nil {
		t.Fatal(err)
	}
	configPath = cfgFile

	stateDir = ""
	if got := resolveStateDir(); got != "/from/config" {
		t.Errorf("expected state_dir from config, got %q", got)
	}

	stateDir = "/from/flag"
	if got := resolveStateDir(); got != "/from/flag" {
		t.Errorf("expected --state-dir to win, got %q", got)
	}
}
