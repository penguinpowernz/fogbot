package config

import (
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
)

func TestLoad_MissingFileIsDetectableAsNotExist(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected an error wrapping fs.ErrNotExist, got %v", err)
	}
}

func TestDefault_AppliesDefaults(t *testing.T) {
	cfg := Default()
	if cfg.Dedup.Window <= 0 || cfg.Dedup.MaxBurst <= 0 || cfg.StateDir == "" {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
}
