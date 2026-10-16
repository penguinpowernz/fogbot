package suidsweep

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	// noSuidPaths are swept for SUID/SGID files that have no business
	// existing at all; they are kept out of the baseline so approving it
	// never silences them
	noSuidPaths []string
	// flagged holds no-SUID-path findings already reported (path -> hash)
	flagged map[string]string

	// maxHashSize is the largest file hashed, in bytes. Anything bigger is
	// recorded by size and mtime instead: a user can set the SUID bit on a
	// huge file of their own, and reading it all would stall every sweep.
	maxHashSize int64
	// alertTooLarge raises an alert for each SUID/SGID file over maxHashSize
	alertTooLarge bool
	// tooLarge holds too-large files already reported (path -> size:mtime)
	tooLarge map[string]string
}

// defaultMaxHashMB is the default max_hash_mb
const defaultMaxHashMB = 200

// New creates a new SuidSweep skill
func New(baselineManager *baseline.Manager) *SuidSweep {
	return &SuidSweep{
		enabled:         false,
		sweepInterval:   1 * time.Hour,
		baselineManager: baselineManager,
		searchPaths:     []string{"/usr", "/bin", "/sbin", "/opt", "/home"},
		maxHashSize:     defaultMaxHashMB << 20,
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
func (s *SuidSweep) Requires() []string       { return []string{"root"} }
func (s *SuidSweep) Tags() []string           { return []string{"permissions", "suid", "persistence"} }
func (s *SuidSweep) DropIns() []skills.DropIn { return nil }
func (s *SuidSweep) SetupHints() []string     { return nil }
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

	s.maxHashSize = defaultMaxHashMB << 20
	if mb, ok := cfg["max_hash_mb"].(int); ok {
		if mb <= 0 {
			return fmt.Errorf("invalid max_hash_mb %d: must be at least 1", mb)
		}
		s.maxHashSize = int64(mb) << 20
	}
	s.alertTooLarge = false
	if v, ok := cfg["alert_on_too_large"].(bool); ok {
		s.alertTooLarge = v
	}

	// An empty list is honoured, to switch the check off
	if paths, ok := cfg["no_suid_paths"].([]interface{}); ok {
		s.noSuidPaths = make([]string, 0, len(paths))
		for _, path := range paths {
			if p, ok := path.(string); ok && p != "" {
				s.noSuidPaths = append(s.noSuidPaths, filepath.Clean(p))
			}
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
	// Runs whether or not a baseline is approved: there is nothing to approve
	s.checkNoSuid(alertChan)

	current := s.sweep()
	s.checkTooLarge(alertChan, current)

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

	// Forget changes that are gone (removed, or put back as approved). Otherwise
	// a planted binary that the operator deletes could be planted again, with
	// the same content, and never be reported.
	outstanding := make(map[string]bool, len(newBinaries)+len(changedBinaries))
	for _, binary := range append(newBinaries, changedBinaries...) {
		outstanding[binary.Path] = true
	}
	for path := range reported {
		if !outstanding[path] {
			delete(reported, path)
		}
	}

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

// checkNoSuid reports every SUID/SGID file under noSuidPaths, once per file
// and content, until it is removed or loses the bit.
func (s *SuidSweep) checkNoSuid(alertChan chan<- notifier.Alert) {
	if s.flagged == nil {
		s.flagged = make(map[string]string)
	}
	found := s.sweepNoSuid()

	for path := range s.flagged {
		if _, ok := found[path]; !ok {
			delete(s.flagged, path)
		}
	}

	paths := make([]string, 0, len(found))
	for path := range found {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	for _, path := range paths {
		entry := found[path]
		if h, ok := s.flagged[path]; ok && h == entry.Hash {
			continue
		}
		s.flagged[path] = entry.Hash
		log.Printf("[suid-sweep] SUID/SGID file in a no-SUID path: %s", path)
		alertChan <- notifier.Alert{
			Severity:    notifier.SeverityContact,
			SkillID:     SkillID,
			SkillName:   SkillName,
			Title:       "SUID/SGID File in No-SUID Path",
			Size:        "1 file",
			Activity:    fmt.Sprintf("SUID/SGID file where none should exist: %s", filepath.Base(path)),
			Location:    path,
			Unit:        fmt.Sprintf("uid=%d gid=%d mode=%s", entry.UID, entry.GID, os.FileMode(entry.Mode)),
			Time:        time.Now(),
			Equipment:   "not covered by baseline approval: remove the file or its SUID/SGID bit",
			Acknowledge: true,
		}
	}
}

// checkTooLarge reports, if alert_on_too_large is set, each SUID/SGID file
// too large to hash, once per size and mtime. Such a file can only be
// compared against the baseline by size and mtime, which someone with root
// can put back after changing it.
func (s *SuidSweep) checkTooLarge(alertChan chan<- notifier.Alert, current map[string]baseline.SuidEntry) {
	if s.tooLarge == nil {
		s.tooLarge = make(map[string]string)
	}
	for path := range s.tooLarge {
		if !current[path].TooLarge {
			delete(s.tooLarge, path)
		}
	}
	if !s.alertTooLarge {
		return
	}

	paths := make([]string, 0)
	for path, entry := range current {
		if entry.TooLarge {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)

	for _, path := range paths {
		entry := current[path]
		id := fmt.Sprintf("%d:%d", entry.Size, entry.MTime.UnixNano())
		if s.tooLarge[path] == id {
			continue
		}
		s.tooLarge[path] = id
		alertChan <- notifier.Alert{
			Severity:    notifier.SeverityContact,
			SkillID:     SkillID,
			SkillName:   SkillName,
			Title:       "SUID/SGID File Too Large to Hash",
			Size:        fmt.Sprintf("%d MB", entry.Size>>20),
			Activity:    fmt.Sprintf("SUID/SGID file over the %d MB hashing limit: %s", s.maxHashSize>>20, filepath.Base(path)),
			Location:    path,
			Unit:        fmt.Sprintf("uid=%d gid=%d mode=%s", entry.UID, entry.GID, os.FileMode(entry.Mode)),
			Time:        time.Now(),
			Equipment:   "changes to it are detected by size and mtime only",
			Acknowledge: true,
		}
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

// under reports whether path is root or inside it
func under(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

// underAny reports whether path is any of roots or inside one
func underAny(path string, roots []string) bool {
	for _, root := range roots {
		if under(path, root) {
			return true
		}
	}
	return false
}

// insideAnother reports whether path is inside one of roots other than itself
func insideAnother(path string, roots []string) bool {
	for _, root := range roots {
		if root != path && under(path, root) {
			return true
		}
	}
	return false
}

// sweep performs a filesystem walk of the watch paths looking for SUID/SGID
// binaries. No-SUID paths are skipped: sweepNoSuid covers them.
func (s *SuidSweep) sweep() map[string]baseline.SuidEntry {
	results := make(map[string]baseline.SuidEntry)
	for _, searchPath := range s.searchPaths {
		walkSuid(searchPath, s.noSuidPaths, s.maxHashSize, results)
	}
	log.Printf("[suid-sweep] Found %d SUID/SGID binaries", len(results))
	return results
}

// sweepNoSuid walks the no-SUID paths, each once even where they nest
func (s *SuidSweep) sweepNoSuid() map[string]baseline.SuidEntry {
	results := make(map[string]baseline.SuidEntry)
	walked := make(map[string]bool)
	for _, root := range s.noSuidPaths {
		if walked[root] || insideAnother(root, s.noSuidPaths) {
			continue
		}
		walked[root] = true
		walkSuid(root, nil, s.maxHashSize, results)
	}
	return results
}

// walkSuid records every SUID/SGID file under root into results, not
// descending into skip
func walkSuid(root string, skip []string, maxHashSize int64, results map[string]baseline.SuidEntry) {
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Log permission/access errors so the operator knows the sweep is incomplete
			log.Printf("[suid-sweep] Walk error at %s: %v", path, err)
			return nil // continue walking other paths
		}

		if info.IsDir() && underAny(path, skip) {
			return filepath.SkipDir
		}

		if info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
			// This file has SUID or SGID set
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return nil
			}

			hash, err := baseline.HashFile(path, maxHashSize)
			tooLarge := errors.Is(err, baseline.ErrTooLarge)
			if tooLarge {
				log.Printf("[suid-sweep] Not hashing %s: %d MB is over the %d MB limit", path, info.Size()>>20, maxHashSize>>20)
			}

			entry := baseline.SuidEntry{
				Path:  path,
				Mode:  uint32(info.Mode()),
				UID:   int(stat.Uid),
				GID:   int(stat.Gid),
				Size:  info.Size(),
				Hash:  hash,
				MTime: info.ModTime(),

				TooLarge: tooLarge,
			}

			results[path] = entry
		}

		return nil
	})
}

// DeduceCommands - stub for legacy skill
func (s *SuidSweep) DeduceCommands(cfg map[string]interface{}) ([]skills.SystemCommand, error) {
	return []skills.SystemCommand{}, nil
}

// CheckSystemState - stub for legacy skill
func (s *SuidSweep) CheckSystemState() (bool, error) {
	return true, nil
}
