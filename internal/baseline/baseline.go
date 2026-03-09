package baseline

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
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

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write pending baseline: %w", err)
	}

	return nil
}

// ApproveSuid approves a pending baseline and promotes it to active
func (m *Manager) ApproveSuid(chatID string) error {
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
	baseline.ApprovedBy = chatID

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

// HashFile computes SHA256 hash of a file
func HashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash), nil
}
