package approval

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ApprovedCommand represents a command that has been approved by the user
type ApprovedCommand struct {
	SkillID     int               `json:"skill_id"`
	SkillName   string            `json:"skill_name"`
	Command     string            `json:"command"`
	Description string            `json:"description"`
	Metadata    map[string]string `json:"metadata"`
	Hash        string            `json:"hash"`        // Hash of the command for identity
	ApprovedAt  time.Time         `json:"approved_at"`
}

// Tracker manages approved commands
type Tracker struct {
	mu        sync.RWMutex
	approvals map[string]ApprovedCommand // key is command hash
	dataFile  string
}

// NewTracker creates a new approval tracker
func NewTracker(dataDir string) (*Tracker, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	tracker := &Tracker{
		approvals: make(map[string]ApprovedCommand),
		dataFile:  filepath.Join(dataDir, "approved-commands.json"),
	}

	// Load existing approvals
	if err := tracker.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to load approvals: %w", err)
	}

	return tracker, nil
}

// hashCommand creates a stable hash for a command
func hashCommand(skillID int, command string) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%d:%s", skillID, command)))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// CommandInfo is a minimal interface to avoid circular dependencies
type CommandInfo interface {
	GetCommand() string
	GetDescription() string
	GetMetadata() map[string]string
}

// Approve records a user's approval of a command
func (t *Tracker) Approve(skillID int, skillName string, cmd CommandInfo) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	hash := hashCommand(skillID, cmd.GetCommand())
	approval := ApprovedCommand{
		SkillID:     skillID,
		SkillName:   skillName,
		Command:     cmd.GetCommand(),
		Description: cmd.GetDescription(),
		Metadata:    cmd.GetMetadata(),
		Hash:        hash,
		ApprovedAt:  time.Now(),
	}

	t.approvals[hash] = approval
	return t.save()
}

// IsApproved checks if a command has been previously approved
func (t *Tracker) IsApproved(skillID int, command string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	hash := hashCommand(skillID, command)
	_, exists := t.approvals[hash]
	return exists
}

// GetApprovedCommands returns all approved commands for a skill
func (t *Tracker) GetApprovedCommands(skillID int) []ApprovedCommand {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var commands []ApprovedCommand
	for _, approval := range t.approvals {
		if approval.SkillID == skillID {
			commands = append(commands, approval)
		}
	}
	return commands
}

// Revoke removes approval for a command
func (t *Tracker) Revoke(skillID int, command string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	hash := hashCommand(skillID, command)
	delete(t.approvals, hash)
	return t.save()
}

// RevokeSkill removes all approvals for a skill
func (t *Tracker) RevokeSkill(skillID int) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Collect hashes to delete first, then delete them
	// This avoids modifying the map while iterating over it
	toDelete := make([]string, 0)
	for hash, approval := range t.approvals {
		if approval.SkillID == skillID {
			toDelete = append(toDelete, hash)
		}
	}

	for _, hash := range toDelete {
		delete(t.approvals, hash)
	}

	return t.save()
}

// load reads approvals from disk
func (t *Tracker) load() error {
	data, err := os.ReadFile(t.dataFile)
	if err != nil {
		return err
	}

	var approvals []ApprovedCommand
	if err := json.Unmarshal(data, &approvals); err != nil {
		return fmt.Errorf("failed to parse approvals: %w", err)
	}

	for _, approval := range approvals {
		t.approvals[approval.Hash] = approval
	}

	return nil
}

// save writes approvals to disk
func (t *Tracker) save() error {
	approvals := make([]ApprovedCommand, 0, len(t.approvals))
	for _, approval := range t.approvals {
		approvals = append(approvals, approval)
	}

	data, err := json.MarshalIndent(approvals, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal approvals: %w", err)
	}

	if err := os.WriteFile(t.dataFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write approvals: %w", err)
	}

	return nil
}
