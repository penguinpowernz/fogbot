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
	mu         sync.RWMutex
	binaryPath string
	configPath string
	stateDir   string
	watcher    *fsnotify.Watcher
}

// ownWriteGrace is how long after ExpectWrite events on a path are treated as
// the daemon's own. A single os.WriteFile produces several inotify events.
const ownWriteGrace = 2 * time.Second

// ownWrites holds paths this process is about to write, mapped to when the
// grace period ends. Package-level so writers (auth, baseline) can register
// without holding a SelfWatch.
var ownWrites = struct {
	sync.Mutex
	until map[string]time.Time
}{until: make(map[string]time.Time)}

// ExpectWrite marks path as about to be written or removed by this process, so
// the resulting inotify events aren't reported as tampering. Call it before
// writing.
func ExpectWrite(path string) {
	ownWrites.Lock()
	defer ownWrites.Unlock()
	ownWrites.until[filepath.Clean(path)] = time.Now().Add(ownWriteGrace)
}

func isOwnWrite(path string) bool {
	ownWrites.Lock()
	defer ownWrites.Unlock()

	now := time.Now()
	for p, until := range ownWrites.until {
		if now.After(until) {
			delete(ownWrites.until, p)
		}
	}
	_, ok := ownWrites.until[filepath.Clean(path)]
	return ok
}

// stateFileHints says which host-side command legitimately changes a state file
var stateFileHints = map[string]string{
	"suid_baseline.json":         "fogbot baseline approve",
	"suid_baseline.pending.json": "fogbot baseline approve",
	"approved-commands.json":     "fogbot skill enable/disable",
}

// New creates a new SelfWatch instance
func New(binaryPath, configPath, stateDir string) (*SelfWatch, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("creating fsnotify watcher: %w", err)
	}

	return &SelfWatch{
		binaryPath: binaryPath,
		configPath: configPath,
		stateDir:   stateDir,
		watcher:    watcher,
	}, nil
}

// Watch starts monitoring fogbot's own files
func (s *SelfWatch) Watch(ctx context.Context, hostname string) (<-chan notifier.Alert, error) {
	alertChan := make(chan notifier.Alert, 10)

	// Add watches
	if err := s.addWatches(); err != nil {
		// Clean up watcher on error
		s.watcher.Close()
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

	lastAlert := make(map[string]time.Time)

	for {
		select {
		case <-ctx.Done():
			return

		case event, ok := <-s.watcher.Events:
			if !ok {
				return
			}

			if alert, ok := s.classify(event, hostname); ok {
				// One write produces several events; report each file once per burst
				if last, seen := lastAlert[event.Name]; seen && time.Since(last) < ownWriteGrace {
					continue
				}
				lastAlert[event.Name] = time.Now()
				alertChan <- alert
			}

		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("[selfwatch] Error: %v", err)
		}
	}
}

// classify turns an inotify event into an alert, if it warrants one.
//
// The binary and config are never written by fogbot, so any change is CONTACT.
// State files are also written by fogbot's own CLI (e.g. baseline approval),
// which can't be told apart from an attacker here, so changes not made by the
// daemon itself are MOVEMENT with a note on which command explains them.
func (s *SelfWatch) classify(event fsnotify.Event, hostname string) (notifier.Alert, bool) {
	var verb string
	switch {
	case event.Op&fsnotify.Write == fsnotify.Write:
		verb = "modified"
	case event.Op&fsnotify.Remove == fsnotify.Remove:
		verb = "deleted"
	default:
		return notifier.Alert{}, false
	}

	if isOwnWrite(event.Name) {
		return notifier.Alert{}, false
	}

	name := filepath.Base(event.Name)
	alert := notifier.Alert{
		Severity:    notifier.SeverityContact,
		SkillID:     999, // special ID for selfwatch
		SkillName:   "selfwatch",
		Title:       "fogbot File Tamper Detected",
		Size:        "1 file",
		Activity:    fmt.Sprintf("Unexpected change: %s %s", name, verb),
		Location:    event.Name,
		Unit:        "filesystem",
		Time:        time.Now(),
		Equipment:   "inotify",
		Host:        hostname,
		Acknowledge: true,
	}

	if s.stateDir != "" && filepath.Dir(filepath.Clean(event.Name)) == filepath.Clean(s.stateDir) {
		alert.Severity = notifier.SeverityMovement
		alert.Title = "fogbot State Changed"
		alert.Activity = fmt.Sprintf("%s %s outside the fogbot daemon", name, verb)
		alert.Acknowledge = false
		if cmd, ok := stateFileHints[name]; ok {
			alert.Unit = "expected only after running: " + cmd
		} else {
			alert.Unit = "not expected: only the daemon writes this file"
			alert.Severity = notifier.SeverityContact
			alert.Acknowledge = true
		}
	}

	log.Printf("[selfwatch] %s: %s", alert.Title, alert.Activity)
	return alert, true
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
