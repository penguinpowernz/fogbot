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
func (s *SuidSweep) DropIns() []skills.DropIn { return nil }
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

	if intervalStr, ok := cfg["suid_sweep_interval"].(string); ok {
		if d, err := time.ParseDuration(intervalStr); err == nil {
			s.sweepInterval = d
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

	// Perform initial sweep
	log.Printf("[suid-sweep] Performing initial SUID/SGID sweep...")
	current := s.sweep()

	// Load existing baseline
	existingBaseline, err := s.baselineManager.LoadSuid()
	if err != nil {
		log.Printf("[suid-sweep] Failed to load baseline: %v", err)
	}

	if existingBaseline == nil || !existingBaseline.Approved {
		// No approved baseline - create pending and request approval
		log.Printf("[suid-sweep] No approved baseline found, creating pending baseline")

		pending := &baseline.Baseline{
			Type:      "suid",
			Entries:   current,
			CreatedAt: time.Now(),
			Approved:  false,
		}

		if err := s.baselineManager.SavePendingSuid(pending); err != nil {
			log.Printf("[suid-sweep] Failed to save pending baseline: %v", err)
		} else {
			// Send alert requesting approval
			alertChan <- notifier.Alert{
				Severity:  notifier.SeverityNominal,
				SkillID:   SkillID,
				SkillName: SkillName,
				Title:     "SUID Baseline Pending Approval",
				Size:      fmt.Sprintf("%d binaries", len(current)),
				Activity:  "Initial SUID/SGID sweep complete",
				Location:  "system-wide",
				Unit:      "awaiting operator approval",
				Time:      time.Now(),
				Equipment: "baseline-approval",
			}
		}
	}

	ticker := time.NewTicker(s.sweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			log.Printf("[suid-sweep] Running periodic SUID/SGID sweep")
			current := s.sweep()

			// Load current approved baseline
			bl, err := s.baselineManager.LoadSuid()
			if err != nil {
				log.Printf("[suid-sweep] Failed to load baseline: %v", err)
				continue
			}

			if bl == nil || !bl.Approved {
				// Still waiting for approval
				log.Printf("[suid-sweep] Baseline not yet approved, skipping diff")
				continue
			}

			// Find new SUID binaries
			newBinaries := bl.Diff(current)

			if len(newBinaries) > 0 {
				log.Printf("[suid-sweep] Found %d new SUID/SGID binaries!", len(newBinaries))

				// Send alert for each new binary
				for _, binary := range newBinaries {
					alertChan <- notifier.Alert{
						Severity:    notifier.SeverityContact,
						SkillID:     SkillID,
						SkillName:   SkillName,
						Title:       "New SUID/SGID Binary Detected",
						Size:        "1 binary",
						Activity:    fmt.Sprintf("SUID/SGID binary appeared: %s", filepath.Base(binary.Path)),
						Location:    binary.Path,
						Unit:        fmt.Sprintf("uid=%d gid=%d mode=%o", binary.UID, binary.GID, binary.Mode),
						Time:        time.Now(),
						Equipment:   "filesystem-sweep",
						Acknowledge: true,
					}
				}
			}
		}
	}
}

// sweep performs a filesystem walk looking for SUID/SGID binaries
func (s *SuidSweep) sweep() map[string]baseline.SuidEntry {
	results := make(map[string]baseline.SuidEntry)

	for _, searchPath := range s.searchPaths {
		filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // skip errors
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
