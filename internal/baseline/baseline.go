package baseline

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/penguinpowernz/fogbot/internal/selfwatch"
)

// SuidEntry represents a single SUID/SGID file
type SuidEntry struct {
	Path  string    `json:"path"`
	Mode  uint32    `json:"mode"`
	UID   int       `json:"uid"`
	GID   int       `json:"gid"`
	Size  int64     `json:"size"`
	Hash  string    `json:"hash"`  // SHA256 of file
	MTime time.Time `json:"mtime"` // modification time
}

// Baseline represents a known-good state snapshot
type Baseline struct {
	Type      string                `json:"type"` // "suid", "ports", etc
	Entries   map[string]SuidEntry  `json:"entries"`
	CreatedAt time.Time             `json:"created_at"`
	Approved  bool                  `json:"approved"`
	ApprovedAt *time.Time           `json:"approved_at,omitempty"`
	ApprovedBy string               `json:"approved_by,omitempty"` // chat_id
	mu        sync.RWMutex
}

// Manager handles baseline storage and approval
type Manager struct {
	stateDir string
	mu       sync.RWMutex
}

// NewManager creates a new baseline manager
func NewManager(stateDir string) *Manager {
	return &Manager{
		stateDir: stateDir,
	}
}

// LoadSuid loads the SUID baseline from disk
func (m *Manager) LoadSuid() (*Baseline, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	path := filepath.Join(m.stateDir, "suid_baseline.json")

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no baseline yet
		}
		return nil, fmt.Errorf("failed to read baseline: %w", err)
	}

	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("failed to parse baseline: %w", err)
	}

	return &baseline, nil
}

// LoadPendingSuid loads the pending SUID baseline
func (m *Manager) LoadPendingSuid() (*Baseline, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	path := filepath.Join(m.stateDir, "suid_baseline.pending.json")

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no pending baseline
		}
		return nil, fmt.Errorf("failed to read pending baseline: %w", err)
	}

	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("failed to parse pending baseline: %w", err)
	}

	return &baseline, nil
}

// SavePendingSuid saves a pending SUID baseline (awaiting approval)
func (m *Manager) SavePendingSuid(baseline *Baseline) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	path := filepath.Join(m.stateDir, "suid_baseline.pending.json")

	// Marshal without the mutex
	data, err := json.MarshalIndent(&struct {
		Type       string               `json:"type"`
		Entries    map[string]SuidEntry `json:"entries"`
		CreatedAt  time.Time            `json:"created_at"`
		Approved   bool                 `json:"approved"`
		ApprovedAt *time.Time           `json:"approved_at,omitempty"`
		ApprovedBy string               `json:"approved_by,omitempty"`
	}{
		Type:       baseline.Type,
		Entries:    baseline.Entries,
		CreatedAt:  baseline.CreatedAt,
		Approved:   baseline.Approved,
		ApprovedAt: baseline.ApprovedAt,
		ApprovedBy: baseline.ApprovedBy,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}

	selfwatch.ExpectWrite(path)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write pending baseline: %w", err)
	}

	return nil
}

// ApproveSuid approves a pending baseline and promotes it to active
func (m *Manager) ApproveSuid(approvedBy string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pendingPath := filepath.Join(m.stateDir, "suid_baseline.pending.json")
	activePath := filepath.Join(m.stateDir, "suid_baseline.json")

	// Load pending baseline
	data, err := os.ReadFile(pendingPath)
	if err != nil {
		return fmt.Errorf("no pending baseline to approve: %w", err)
	}

	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return fmt.Errorf("failed to parse pending baseline: %w", err)
	}

	// Mark as approved
	now := time.Now()
	baseline.Approved = true
	baseline.ApprovedAt = &now
	baseline.ApprovedBy = approvedBy

	// Save as active baseline (don't marshal the mutex)
	data, err = json.MarshalIndent(&struct {
		Type       string               `json:"type"`
		Entries    map[string]SuidEntry `json:"entries"`
		CreatedAt  time.Time            `json:"created_at"`
		Approved   bool                 `json:"approved"`
		ApprovedAt *time.Time           `json:"approved_at,omitempty"`
		ApprovedBy string               `json:"approved_by,omitempty"`
	}{
		Type:       baseline.Type,
		Entries:    baseline.Entries,
		CreatedAt:  baseline.CreatedAt,
		Approved:   baseline.Approved,
		ApprovedAt: baseline.ApprovedAt,
		ApprovedBy: baseline.ApprovedBy,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}

	if err := os.WriteFile(activePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write active baseline: %w", err)
	}

	// Remove pending file
	_ = os.Remove(pendingPath)

	return nil
}

// Diff compares current state against baseline and returns new entries
func (baseline *Baseline) Diff(current map[string]SuidEntry) []SuidEntry {
	if baseline == nil {
		// No baseline yet - everything is "new"
		result := make([]SuidEntry, 0, len(current))
		for _, entry := range current {
			result = append(result, entry)
		}
		return result
	}

	baseline.mu.RLock()
	defer baseline.mu.RUnlock()

	new := make([]SuidEntry, 0)
	for path, entry := range current {
		if _, exists := baseline.Entries[path]; !exists {
			new = append(new, entry)
		}
	}

	return new
}

// Changed returns entries that are in the baseline but whose content, mode or
// ownership differs, e.g. a SUID binary replaced in place.
func (baseline *Baseline) Changed(current map[string]SuidEntry) []SuidEntry {
	if baseline == nil {
		return nil
	}

	baseline.mu.RLock()
	defer baseline.mu.RUnlock()

	changed := make([]SuidEntry, 0)
	for path, entry := range current {
		old, exists := baseline.Entries[path]
		if !exists {
			continue
		}
		hashDiffers := old.Hash != "" && entry.Hash != "" && old.Hash != entry.Hash
		if hashDiffers || old.Mode != entry.Mode || old.UID != entry.UID || old.GID != entry.GID {
			changed = append(changed, entry)
		}
	}

	return changed
}

// HashFile computes SHA256 hash of a regular file without loading it all into
// memory. Anything else is refused: the SUID sweep walks user-writable trees,
// and opening a FIFO there (which a user can chmod u+s) would block forever and
// silently stop every later sweep. O_NONBLOCK keeps the open itself from
// blocking if the path is swapped for a FIFO after it was stat'ed.
func HashFile(path string) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
