package selfwatch

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/penguinpowernz/fogbot/internal/notifier"
)

// SelfWatch monitors fogbot's own files for tampering
type SelfWatch struct {
	mu              sync.RWMutex
	binaryPath      string
	configPath      string
	stateDir        string
	watcher         *fsnotify.Watcher
	expectedWrites  map[string]time.Time // whitelist of expected writes
}

// New creates a new SelfWatch instance
func New(binaryPath, configPath, stateDir string) (*SelfWatch, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("creating fsnotify watcher: %w", err)
	}

	return &SelfWatch{
		binaryPath:     binaryPath,
		configPath:     configPath,
		stateDir:       stateDir,
		watcher:        watcher,
		expectedWrites: make(map[string]time.Time),
	}, nil
}

// Watch starts monitoring fogbot's own files
func (s *SelfWatch) Watch(ctx context.Context, hostname string) (<-chan notifier.Alert, error) {
	alertChan := make(chan notifier.Alert, 10)

	// Add watches
	if err := s.addWatches(); err != nil {
		return nil, fmt.Errorf("adding watches: %w", err)
	}

	go s.watchLoop(ctx, alertChan, hostname)

	return alertChan, nil
}

func (s *SelfWatch) addWatches() error {
	// Watch binary if it exists
	if s.binaryPath != "" {
		if _, err := os.Stat(s.binaryPath); err == nil {
			if err := s.watcher.Add(s.binaryPath); err != nil {
				log.Printf("[selfwatch] Failed to watch binary %s: %v", s.binaryPath, err)
			} else {
				log.Printf("[selfwatch] Watching binary: %s", s.binaryPath)
			}
		}
	}

	// Watch config if it exists
	if s.configPath != "" {
		if _, err := os.Stat(s.configPath); err == nil {
			if err := s.watcher.Add(s.configPath); err != nil {
				log.Printf("[selfwatch] Failed to watch config %s: %v", s.configPath, err)
			} else {
				log.Printf("[selfwatch] Watching config: %s", s.configPath)
			}
		}
	}

	// Watch state directory if it exists
	if s.stateDir != "" {
		if _, err := os.Stat(s.stateDir); err == nil {
			if err := s.watcher.Add(s.stateDir); err != nil {
				log.Printf("[selfwatch] Failed to watch state dir %s: %v", s.stateDir, err)
			} else {
				log.Printf("[selfwatch] Watching state dir: %s", s.stateDir)
			}

			// Watch changes.log specifically
			changesLog := filepath.Join(s.stateDir, "changes.log")
			if _, err := os.Stat(changesLog); err == nil {
				if err := s.watcher.Add(changesLog); err != nil {
					log.Printf("[selfwatch] Failed to watch changes.log: %v", err)
				}
			}
		}
	}

	return nil
}

func (s *SelfWatch) watchLoop(ctx context.Context, alertChan chan<- notifier.Alert, hostname string) {
	defer close(alertChan)
	defer s.watcher.Close()

	for {
		select {
		case <-ctx.Done():
			return

		case event, ok := <-s.watcher.Events:
			if !ok {
				return
			}

			// Check if this was an expected write
			if s.isExpectedWrite(event.Name) {
				log.Printf("[selfwatch] Expected write to %s, ignoring", event.Name)
				continue
			}

			// Alert on modifications to watched files
			if event.Op&fsnotify.Write == fsnotify.Write {
				log.Printf("[selfwatch] Unexpected modification to %s", event.Name)

				alertChan <- notifier.Alert{
					Severity:    notifier.SeverityContact,
					SkillID:     999, // special ID for selfwatch
					SkillName:   "selfwatch",
					Title:       "fogbot File Tamper Detected",
					Size:        "1 file",
					Activity:    fmt.Sprintf("Unexpected modification to %s", filepath.Base(event.Name)),
					Location:    event.Name,
					Unit:        "filesystem",
					Time:        time.Now(),
					Equipment:   "inotify",
					Host:        hostname,
					Acknowledge: true,
				}
			}

			if event.Op&fsnotify.Remove == fsnotify.Remove {
				log.Printf("[selfwatch] File removed: %s", event.Name)

				alertChan <- notifier.Alert{
					Severity:    notifier.SeverityContact,
					SkillID:     999,
					SkillName:   "selfwatch",
					Title:       "fogbot File Deleted",
					Size:        "1 file",
					Activity:    fmt.Sprintf("Watched file deleted: %s", filepath.Base(event.Name)),
					Location:    event.Name,
					Unit:        "filesystem",
					Time:        time.Now(),
					Equipment:   "inotify",
					Host:        hostname,
					Acknowledge: true,
				}
			}

		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("[selfwatch] Error: %v", err)
		}
	}
}

// WhitelistWrite marks a write as expected (to avoid false positives from fogbot's own writes)
func (s *SelfWatch) WhitelistWrite(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expectedWrites[path] = time.Now().Add(5 * time.Second) // valid for 5 seconds
}

func (s *SelfWatch) isExpectedWrite(path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	expiry, exists := s.expectedWrites[path]
	if !exists {
		return false
	}

	if time.Now().After(expiry) {
		delete(s.expectedWrites, path)
		return false
	}

	// Consume the whitelist entry
	delete(s.expectedWrites, path)
	return true
}

// AddWatch dynamically adds a new file to watch (for drop-ins created at runtime)
func (s *SelfWatch) AddWatch(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.watcher.Add(path); err != nil {
		return fmt.Errorf("adding watch for %s: %w", path, err)
	}

	log.Printf("[selfwatch] Added watch: %s", path)
	return nil
}
