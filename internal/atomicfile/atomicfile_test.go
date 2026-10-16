package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileReplacesContentsAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	os.WriteFile(path, []byte("old"), 0644)

	if err := WriteFile(path, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	if string(data) != "new" {
		t.Fatalf("contents = %q, want new", data)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("expected only state.json in dir, got %d entries", len(entries))
	}
}

func TestWriteFileFailureKeepsOldContents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	os.WriteFile(path, []byte("old"), 0600)
	// Renaming a file over a non-empty directory fails
	os.Mkdir(filepath.Join(dir, "sub"), 0700)
	os.WriteFile(filepath.Join(dir, "sub", "x"), nil, 0600)

	if err := WriteFile(filepath.Join(dir, "sub"), []byte("new"), 0600); err == nil {
		t.Fatal("expected an error writing over a directory")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "old" {
		t.Fatalf("unrelated file changed: %q", data)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("temporary file left behind: %d entries", len(entries))
	}
}

func TestTargetOf(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"/var/lib/fogbot/.state.json.tmp-1a2b3c4d", "/var/lib/fogbot/state.json", true},
		{"/var/lib/fogbot/.suid_baseline.pending.json.tmp-00ff00ff", "/var/lib/fogbot/suid_baseline.pending.json", true},
		{"/var/lib/fogbot/state.json", "", false},
		{"/var/lib/fogbot/.hidden", "", false},
		{"/var/lib/fogbot/.tmp-1234", "", false},
	} {
		got, ok := TargetOf(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("TargetOf(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
