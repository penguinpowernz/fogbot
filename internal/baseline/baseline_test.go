package baseline

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// HashFile
// ---------------------------------------------------------------------------

func TestHashFile_KnownContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	content := []byte("hello fogbot")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("could not write test file: %v", err)
	}

	hash, err := HashFile(path)
	if err != nil {
		t.Fatalf("HashFile returned error: %v", err)
	}
	if hash == "" {
		t.Error("HashFile should return a non-empty hash")
	}
	// SHA256 is always 64 hex chars
	if len(hash) != 64 {
		t.Errorf("expected 64-char hex hash, got %d chars: %q", len(hash), hash)
	}
}

func TestHashFile_Deterministic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	os.WriteFile(path, []byte("deterministic content"), 0644)

	h1, err := HashFile(path)
	if err != nil {
		t.Fatalf("first HashFile call failed: %v", err)
	}
	h2, err := HashFile(path)
	if err != nil {
		t.Fatalf("second HashFile call failed: %v", err)
	}
	if h1 != h2 {
		t.Errorf("HashFile is not deterministic: %q != %q", h1, h2)
	}
}

func TestHashFile_DifferentContent_DifferentHash(t *testing.T) {
	dir := t.TempDir()

	f1 := filepath.Join(dir, "a.txt")
	f2 := filepath.Join(dir, "b.txt")
	os.WriteFile(f1, []byte("content A"), 0644)
	os.WriteFile(f2, []byte("content B"), 0644)

	h1, _ := HashFile(f1)
	h2, _ := HashFile(f2)
	if h1 == h2 {
		t.Error("different file content should produce different hashes")
	}
}

func TestHashFile_MissingFile_Error(t *testing.T) {
	_, err := HashFile(filepath.Join(t.TempDir(), "nonexistent.txt"))
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestHashFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	os.WriteFile(path, []byte{}, 0644)

	hash, err := HashFile(path)
	if err != nil {
		t.Fatalf("HashFile of empty file returned error: %v", err)
	}
	// SHA256 of empty input is well-known
	const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if hash != emptySHA256 {
		t.Errorf("expected SHA256 of empty file = %q, got %q", emptySHA256, hash)
	}
}

// ---------------------------------------------------------------------------
// Baseline.Diff
// ---------------------------------------------------------------------------

func TestDiff_NewEntryDetected(t *testing.T) {
	bl := &Baseline{
		Entries: map[string]SuidEntry{
			"/bin/su": {Path: "/bin/su"},
		},
		Approved: true,
	}
	current := map[string]SuidEntry{
		"/bin/su":       {Path: "/bin/su"},
		"/tmp/new_suid": {Path: "/tmp/new_suid"},
	}

	newEntries := bl.Diff(current)
	if len(newEntries) != 1 {
		t.Fatalf("expected 1 new entry, got %d", len(newEntries))
	}
	if newEntries[0].Path != "/tmp/new_suid" {
		t.Errorf("expected new entry /tmp/new_suid, got %q", newEntries[0].Path)
	}
}

func TestDiff_NoNewEntries(t *testing.T) {
	bl := &Baseline{
		Entries: map[string]SuidEntry{
			"/bin/su":         {Path: "/bin/su"},
			"/usr/bin/passwd": {Path: "/usr/bin/passwd"},
		},
	}
	current := map[string]SuidEntry{
		"/bin/su":         {Path: "/bin/su"},
		"/usr/bin/passwd": {Path: "/usr/bin/passwd"},
	}

	newEntries := bl.Diff(current)
	if len(newEntries) != 0 {
		t.Errorf("expected 0 new entries, got %d", len(newEntries))
	}
}

func TestDiff_EntryRemovedFromCurrent_NotReported(t *testing.T) {
	// Diff only reports additions, not removals
	bl := &Baseline{
		Entries: map[string]SuidEntry{
			"/bin/su":         {Path: "/bin/su"},
			"/usr/bin/passwd": {Path: "/usr/bin/passwd"},
		},
	}
	// /usr/bin/passwd is gone from current state
	current := map[string]SuidEntry{
		"/bin/su": {Path: "/bin/su"},
	}

	newEntries := bl.Diff(current)
	if len(newEntries) != 0 {
		t.Errorf("Diff should not report removed entries, but got %d", len(newEntries))
	}
}

func TestDiff_NilBaseline_AllCurrentAreNew(t *testing.T) {
	var bl *Baseline
	current := map[string]SuidEntry{
		"/bin/su":         {Path: "/bin/su"},
		"/usr/bin/passwd": {Path: "/usr/bin/passwd"},
	}

	newEntries := bl.Diff(current)
	if len(newEntries) != 2 {
		t.Errorf("nil baseline should report all current entries as new, got %d", len(newEntries))
	}
}

func TestDiff_EmptyBaseline_AllCurrentAreNew(t *testing.T) {
	bl := &Baseline{
		Entries: map[string]SuidEntry{},
	}
	current := map[string]SuidEntry{
		"/tmp/evil": {Path: "/tmp/evil"},
	}

	newEntries := bl.Diff(current)
	if len(newEntries) != 1 {
		t.Errorf("empty baseline should report all current entries as new, got %d", len(newEntries))
	}
}

func TestDiff_EmptyCurrent_NoNewEntries(t *testing.T) {
	bl := &Baseline{
		Entries: map[string]SuidEntry{
			"/bin/su": {Path: "/bin/su"},
		},
	}
	newEntries := bl.Diff(map[string]SuidEntry{})
	if len(newEntries) != 0 {
		t.Errorf("empty current state should produce no new entries, got %d", len(newEntries))
	}
}

func TestDiff_MultipleNewEntries(t *testing.T) {
	bl := &Baseline{
		Entries: map[string]SuidEntry{
			"/bin/su": {Path: "/bin/su"},
		},
	}
	current := map[string]SuidEntry{
		"/bin/su":      {Path: "/bin/su"},
		"/tmp/evil1":   {Path: "/tmp/evil1"},
		"/tmp/evil2":   {Path: "/tmp/evil2"},
		"/dev/shm/bad": {Path: "/dev/shm/bad"},
	}

	newEntries := bl.Diff(current)
	if len(newEntries) != 3 {
		t.Errorf("expected 3 new entries, got %d", len(newEntries))
	}
}

// ---------------------------------------------------------------------------
// Manager.SavePendingSuid / LoadPendingSuid
// ---------------------------------------------------------------------------

func TestSavePendingSuid_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	pending := &Baseline{
		Type: "suid",
		Entries: map[string]SuidEntry{
			"/bin/su": {Path: "/bin/su", Mode: 0104755, UID: 0, GID: 0, Size: 1024},
		},
		CreatedAt: time.Now().Truncate(time.Second),
		Approved:  false,
	}

	if err := mgr.SavePendingSuid(pending); err != nil {
		t.Fatalf("SavePendingSuid returned error: %v", err)
	}

	loaded, err := mgr.LoadPendingSuid()
	if err != nil {
		t.Fatalf("LoadPendingSuid returned error: %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadPendingSuid returned nil after saving")
	}
	if loaded.Type != "suid" {
		t.Errorf("expected type=suid, got %q", loaded.Type)
	}
	if loaded.Approved {
		t.Error("pending baseline should not be marked approved")
	}
	if len(loaded.Entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(loaded.Entries))
	}
	entry, ok := loaded.Entries["/bin/su"]
	if !ok {
		t.Fatal("expected /bin/su entry in loaded baseline")
	}
	if entry.Path != "/bin/su" {
		t.Errorf("expected path=/bin/su, got %q", entry.Path)
	}
	if entry.Mode != 0104755 {
		t.Errorf("expected mode=0104755, got %o", entry.Mode)
	}
}

func TestLoadPendingSuid_NoFile_ReturnsNil(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	loaded, err := mgr.LoadPendingSuid()
	if err != nil {
		t.Fatalf("LoadPendingSuid on empty dir returned error: %v", err)
	}
	if loaded != nil {
		t.Error("LoadPendingSuid should return nil when no pending baseline exists")
	}
}

func TestLoadSuid_NoFile_ReturnsNil(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	loaded, err := mgr.LoadSuid()
	if err != nil {
		t.Fatalf("LoadSuid on empty dir returned error: %v", err)
	}
	if loaded != nil {
		t.Error("LoadSuid should return nil when no baseline exists")
	}
}

// ---------------------------------------------------------------------------
// Manager.ApproveSuid
// ---------------------------------------------------------------------------

func TestApproveSuid_PromotesToActive(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	pending := &Baseline{
		Type: "suid",
		Entries: map[string]SuidEntry{
			"/bin/su": {Path: "/bin/su"},
		},
		CreatedAt: time.Now(),
		Approved:  false,
	}
	if err := mgr.SavePendingSuid(pending); err != nil {
		t.Fatalf("SavePendingSuid failed: %v", err)
	}

	if err := mgr.ApproveSuid("chat123"); err != nil {
		t.Fatalf("ApproveSuid returned error: %v", err)
	}

	// Pending file should be gone
	pendingLoaded, err := mgr.LoadPendingSuid()
	if err != nil {
		t.Fatalf("LoadPendingSuid after approval failed: %v", err)
	}
	if pendingLoaded != nil {
		t.Error("pending baseline should be removed after approval")
	}

	// Active baseline should exist and be approved
	active, err := mgr.LoadSuid()
	if err != nil {
		t.Fatalf("LoadSuid after approval failed: %v", err)
	}
	if active == nil {
		t.Fatal("active baseline should exist after approval")
	}
	if !active.Approved {
		t.Error("active baseline should be marked approved")
	}
	if active.ApprovedBy != "chat123" {
		t.Errorf("expected ApprovedBy=chat123, got %q", active.ApprovedBy)
	}
	if active.ApprovedAt == nil {
		t.Error("ApprovedAt should be set after approval")
	}
	if len(active.Entries) != 1 {
		t.Errorf("expected 1 entry in active baseline, got %d", len(active.Entries))
	}
}

func TestApproveSuid_NoPending_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	if err := mgr.ApproveSuid("chat123"); err == nil {
		t.Error("expected error when no pending baseline exists")
	}
}

func TestApproveSuid_PreservesEntries(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	pending := &Baseline{
		Type: "suid",
		Entries: map[string]SuidEntry{
			"/bin/su":         {Path: "/bin/su", Mode: 0104755, UID: 0},
			"/usr/bin/passwd": {Path: "/usr/bin/passwd", Mode: 0104755, UID: 0},
		},
		CreatedAt: time.Now(),
	}
	mgr.SavePendingSuid(pending)
	mgr.ApproveSuid("operator1")

	active, _ := mgr.LoadSuid()
	if len(active.Entries) != 2 {
		t.Errorf("expected 2 entries after approval, got %d", len(active.Entries))
	}
}

// ---------------------------------------------------------------------------
// Manager.SavePendingSuid: file permissions
// ---------------------------------------------------------------------------

func TestSavePendingSuid_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	pending := &Baseline{
		Type:    "suid",
		Entries: map[string]SuidEntry{},
	}
	mgr.SavePendingSuid(pending)

	info, err := os.Stat(filepath.Join(dir, "suid_baseline.pending.json"))
	if err != nil {
		t.Fatalf("could not stat pending baseline file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("expected file permissions 0600, got %04o", perm)
	}
}
