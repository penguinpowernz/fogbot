package suidsweep

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/penguinpowernz/fogbot/internal/baseline"
	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
)

const (
	SkillID   = 200
	SkillName = "suid-sweep"
)

// SuidSweep watches for SUID/SGID changes
type SuidSweep struct {
	mu              sync.RWMutex
	enabled         bool
	config          map[string]interface{}
	sweepInterval   time.Duration
	baselineManager *baseline.Manager
	searchPaths     []string
}

// New creates a new SuidSweep skill
func New(baselineManager *baseline.Manager) *SuidSweep {
	return &SuidSweep{
		enabled:         false,
		sweepInterval:   1 * time.Hour,
		baselineManager: baselineManager,
		searchPaths:     []string{"/usr", "/bin", "/sbin", "/opt", "/home"},
	}
}

func (s *SuidSweep) ID() int      { return SkillID }
func (s *SuidSweep) Name() string { return SkillName }
func (s *SuidSweep) Description() string {
	return "Detects SUID/SGID changes via periodic sweep and baseline diff"
}
func (s *SuidSweep) Why() string {
	return "SUID binaries run with elevated privileges. New ones are a common persistence mechanism."
}
func (s *SuidSweep) Requires() []string { return []string{"root"} }
func (s *SuidSweep) Tags() []string     { return []string{"permissions", "suid", "persistence"} }
func (s *SuidSweep) DropIns() []skills.DropIn    { return nil }
func (s *SuidSweep) SetupHints() []string        { return nil }
func (s *SuidSweep) Enabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled
}

func (s *SuidSweep) SetEnabled(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = enabled
}

func (s *SuidSweep) Config() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

func (s *SuidSweep) Configure(cfg map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.config = cfg

	if intervalStr, ok := cfg["sweep_interval"].(string); ok {
		if d, err := time.ParseDuration(intervalStr); err == nil && d > 0 { // time.NewTicker panics on d <= 0
			s.sweepInterval = d
		}
	}

	if paths, ok := cfg["watch_paths"].([]interface{}); ok {
		searchPaths := make([]string, 0, len(paths))
		for _, path := range paths {
			if p, ok := path.(string); ok {
				searchPaths = append(searchPaths, p)
			}
		}
		if len(searchPaths) > 0 {
			s.searchPaths = searchPaths
		}
	}

	return nil
}

func (s *SuidSweep) Watch(ctx context.Context) (<-chan notifier.Alert, error) {
	alertChan := make(chan notifier.Alert, 10)

	go s.watchLoop(ctx, alertChan)

	return alertChan, nil
}

func (s *SuidSweep) watchLoop(ctx context.Context, alertChan chan<- notifier.Alert) {
	defer close(alertChan)

	// Changes already reported (path -> hash), so each one alerts once rather
	// than on every sweep until the operator approves the new state
	reported := make(map[string]string)

	// Sweep straight away so anything planted while fogbot was down is reported
	// at startup rather than an interval later
	log.Printf("[suid-sweep] Performing initial SUID/SGID sweep...")
	s.check(alertChan, reported, true)

	ticker := time.NewTicker(s.sweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			log.Printf("[suid-sweep] Running periodic SUID/SGID sweep")
			s.check(alertChan, reported, false)
		}
	}
}

// check sweeps the filesystem and compares it against the approved baseline.
// Any difference is saved as the pending baseline for the operator to review and
// approve on the host with `fogbot baseline approve`.
func (s *SuidSweep) check(alertChan chan<- notifier.Alert, reported map[string]string, initial bool) {
	current := s.sweep()

	bl, err := s.baselineManager.LoadSuid()
	if err != nil {
		log.Printf("[suid-sweep] Failed to load baseline: %v", err)
		return
	}

	if bl == nil || !bl.Approved {
		if err := s.savePending(current); err != nil {
			return
		}
		if initial {
			log.Printf("[suid-sweep] No approved baseline, pending baseline saved")
			alertChan <- notifier.Alert{
				Severity:  notifier.SeverityNominal,
				SkillID:   SkillID,
				SkillName: SkillName,
				Title:     "SUID Baseline Pending Approval",
				Size:      fmt.Sprintf("%d binaries", len(current)),
				Activity:  "Initial SUID/SGID sweep complete",
				Location:  "system-wide",
				Unit:      "awaiting approval: sudo fogbot baseline approve",
				Time:      time.Now(),
				Equipment: "baseline-approval",
			}
		}
		return
	}

	newBinaries := bl.Diff(current)
	changedBinaries := bl.Changed(current)
	if len(newBinaries) == 0 && len(changedBinaries) == 0 {
		return
	}
	log.Printf("[suid-sweep] Found %d new and %d changed SUID/SGID binaries", len(newBinaries), len(changedBinaries))

	if err := s.savePending(current); err != nil {
		return
	}

	report := func(binary baseline.SuidEntry, title, verb string) {
		if h, ok := reported[binary.Path]; ok && h == binary.Hash {
			return
		}
		reported[binary.Path] = binary.Hash
		alertChan <- notifier.Alert{
			Severity:    notifier.SeverityContact,
			SkillID:     SkillID,
			SkillName:   SkillName,
			Title:       title,
			Size:        "1 binary",
			Activity:    fmt.Sprintf("SUID/SGID binary %s: %s", verb, filepath.Base(binary.Path)),
			Location:    binary.Path,
			Unit:        fmt.Sprintf("uid=%d gid=%d mode=%s", binary.UID, binary.GID, os.FileMode(binary.Mode)),
			Time:        time.Now(),
			Equipment:   "if expected: sudo fogbot baseline approve",
			Acknowledge: true,
		}
	}
	for _, binary := range newBinaries {
		report(binary, "New SUID/SGID Binary Detected", "appeared")
	}
	for _, binary := range changedBinaries {
		report(binary, "SUID/SGID Binary Modified", "modified")
	}
}

func (s *SuidSweep) savePending(current map[string]baseline.SuidEntry) error {
	err := s.baselineManager.SavePendingSuid(&baseline.Baseline{
		Type:      "suid",
		Entries:   current,
		CreatedAt: time.Now(),
	})
	if err != nil {
		log.Printf("[suid-sweep] Failed to save pending baseline: %v", err)
	}
	return err
}

// sweep performs a filesystem walk looking for SUID/SGID binaries
func (s *SuidSweep) sweep() map[string]baseline.SuidEntry {
	results := make(map[string]baseline.SuidEntry)

	for _, searchPath := range s.searchPaths {
		filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				// Log permission/access errors so the operator knows the sweep is incomplete
				log.Printf("[suid-sweep] Walk error at %s: %v", path, err)
				return nil // continue walking other paths
			}

			if info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
				// This file has SUID or SGID set
				stat, ok := info.Sys().(*syscall.Stat_t)
				if !ok {
					return nil
				}

				hash, _ := baseline.HashFile(path)

				entry := baseline.SuidEntry{
					Path:  path,
					Mode:  uint32(info.Mode()),
					UID:   int(stat.Uid),
					GID:   int(stat.Gid),
					Size:  info.Size(),
					Hash:  hash,
					MTime: info.ModTime(),
				}

				results[path] = entry
			}

			return nil
		})
	}

	log.Printf("[suid-sweep] Found %d SUID/SGID binaries", len(results))
	return results
}




// DeduceCommands - stub for legacy skill
func (s *SuidSweep) DeduceCommands(cfg map[string]interface{}) ([]skills.SystemCommand, error) {
	return []skills.SystemCommand{}, nil
}

// CheckSystemState - stub for legacy skill
func (s *SuidSweep) CheckSystemState() (bool, error) {
	return true, nil
}
