package filewatch

import (
	"path/filepath"
	"strings"
	"testing"
)

// The bug: the shipped config lists canaries such as /root/.bitcoin/wallet.dat.
// auditd refuses to watch a file whose directory doesn't exist, so on a host
// without that directory auditctl failed and the whole enable with it.
func TestDeduceSkipsPathsWithoutParentDir(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "passwd")
	missing := filepath.Join(dir, "nope", "wallet.dat")

	f := NewDefault()
	cmds, err := f.DeduceCommands(map[string]interface{}{
		"watch_paths": map[string]interface{}{present: "rwa", missing: "rwa"},
	})
	if err != nil {
		t.Fatalf("DeduceCommands: %v", err)
	}
	if len(cmds) != 1 || !strings.Contains(cmds[0].Command, present) {
		t.Fatalf("expected only the watchable path, got %+v", cmds)
	}

	if _, err := f.DeduceCommands(map[string]interface{}{
		"watch_paths": map[string]interface{}{missing: "rwa"},
	}); err == nil {
		t.Fatal("expected an error when no path can be watched")
	}
}
