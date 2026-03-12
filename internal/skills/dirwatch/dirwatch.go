package dirwatch

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
	"github.com/penguinpowernz/fogbot/internal/skills"
)

const (
	SkillID   = 540
	SkillName = "dir-watch"
)

// DirWatch monitors configured directories for new files and subdirectories
type DirWatch struct {
	mu          sync.RWMutex
	enabled     bool
	config      map[string]interface{}
	watchPaths  []string
	recursive   bool
	globFilter  string
	whitelist   map[string]bool
}

// New creates a DirWatch with default config (used by daemon registry).
func New() *DirWatch {
	return &DirWatch{
		enabled:    false,
		watchPaths: []string{"/usr/local/bin/", "/etc/cron.d/", "/root/"},
		whitelist:  make(map[string]bool),
	}
}

// NewFromConfig creates a DirWatch pre-populated from a SkillConfig (used by CLI enabler).
func NewFromConfig(cfg skills.SkillConfig) *DirWatch {
	d := New()
	if cfg.Config != nil {
		d.applyConfig(cfg.Config)
	}
	return d
}

func (d *DirWatch) applyConfig(cfg map[string]interface{}) {
	if paths, ok := cfg["watch_paths"].([]interface{}); ok {
		d.watchPaths = make([]string, 0, len(paths))
		for _, p := range paths {
			if s, ok := p.(string); ok {
				d.watchPaths = append(d.watchPaths, s)
			}
		}
	}

	if recursive, ok := cfg["recursive"].(bool); ok {
		d.recursive = recursive
	}

	if glob, ok := cfg["glob_filter"].(string); ok {
		d.globFilter = glob
	}

	if wl, ok := cfg["whitelist"].([]interface{}); ok {
		d.whitelist = make(map[string]bool, len(wl))
		for _, entry := range wl {
			if s, ok := entry.(string); ok {
				d.whitelist[s] = true
			}
		}
	}
}

func (d *DirWatch) ID() int          { return SkillID }
func (d *DirWatch) Name() string     { return SkillName }
func (d *DirWatch) Description() string {
	return "Alert on new files/directories added to watched folders"
}
func (d *DirWatch) Why() string {
	return "New files in sensitive directories outside maintenance windows indicate delivery or persistence activity."
}
func (d *DirWatch) Requires() []string             { return []string{"inotify"} }
func (d *DirWatch) Tags() []string                 { return []string{"filesystem", "persistence", "delivery"} }
func (d *DirWatch) DropIns() []skills.DropIn       { return nil }
func (d *DirWatch) DeduceCommands(cfg map[string]interface{}) ([]skills.SystemCommand, error) {
	return []skills.SystemCommand{}, nil
}
func (d *DirWatch) CheckSystemState() (bool, error) { return true, nil }

func (d *DirWatch) Enabled() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.enabled
}

func (d *DirWatch) SetEnabled(enabled bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.enabled = enabled
}

func (d *DirWatch) Config() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.config
}

func (d *DirWatch) Configure(cfg map[string]interface{}) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	log.Printf("[dir-watch] Configure called with config: %+v", cfg)
	d.config = cfg
	d.applyConfig(cfg)
	log.Printf("[dir-watch] After applyConfig: watch_paths=%v, recursive=%v, glob_filter=%s, whitelist=%v",
		d.watchPaths, d.recursive, d.globFilter, d.whitelist)
	return nil
}

func (d *DirWatch) Watch(ctx context.Context) (<-chan notifier.Alert, error) {
	log.Printf("[dir-watch] Watch() called - starting watcher")
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("creating inotify watcher: %w", err)
	}

	d.mu.RLock()
	paths := make([]string, len(d.watchPaths))
	copy(paths, d.watchPaths)
	recursive := d.recursive
	d.mu.RUnlock()

	log.Printf("[dir-watch] Will watch %d paths: %v", len(paths), paths)

	// Add paths to watcher
	for _, p := range paths {
		if err := d.addPath(watcher, p, recursive); err != nil {
			log.Printf("[dir-watch] Warning: could not watch %s: %v", p, err)
		} else {
			log.Printf("[dir-watch] ✓ Watching %s (recursive=%v)", p, recursive)
		}
	}

	alerts := make(chan notifier.Alert, 10)
	log.Printf("[dir-watch] Event loop starting, monitoring for CREATE|RENAME|WRITE events")

	go func() {
		defer close(alerts)
		defer watcher.Close()

		for {
			select {
			case <-ctx.Done():
				return

			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				log.Printf("[dir-watch] Event received: %s %s", event.Op, event.Name)

				// Care about new entries, renames, and modifications
				if event.Op&(fsnotify.Create|fsnotify.Rename|fsnotify.Write) != 0 {
					log.Printf("[dir-watch] Processing event (matched filter)")
					d.handleEvent(event.Name, event.Op, watcher, recursive, alerts)
				} else {
					log.Printf("[dir-watch] Ignoring event (not CREATE|RENAME|WRITE)")
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("[dir-watch] Watcher error: %v", err)
			}
		}
	}()

	return alerts, nil
}

func (d *DirWatch) addPath(watcher *fsnotify.Watcher, path string, recursive bool) error {
	if err := watcher.Add(path); err != nil {
		return err
	}

	if recursive {
		return filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
			if err != nil || !info.IsDir() || p == path {
				return nil
			}
			return watcher.Add(p)
		})
	}

	return nil
}

func (d *DirWatch) handleEvent(path string, op fsnotify.Op, watcher *fsnotify.Watcher, recursive bool, alerts chan<- notifier.Alert) {
	name := filepath.Base(path)
	log.Printf("[dir-watch] handleEvent: path=%s, op=%s, name=%s", path, op, name)

	// Check whitelist
	d.mu.RLock()
	whitelisted := d.whitelist[name]
	globFilter := d.globFilter
	d.mu.RUnlock()

	if whitelisted {
		log.Printf("[dir-watch] Ignoring whitelisted file: %s", name)
		return
	}

	// Apply glob filter if set
	if globFilter != "" {
		matched, err := filepath.Match(globFilter, name)
		if err != nil || !matched {
			log.Printf("[dir-watch] File %s doesn't match glob filter %s", name, globFilter)
			return
		}
	}

	// Stat the new entry
	info, err := os.Lstat(path)
	if err != nil {
		// File may have been removed immediately after creation (e.g. tmp files)
		log.Printf("[dir-watch] Could not stat %s: %v (may have been deleted)", path, err)
		return
	}
	log.Printf("[dir-watch] File stat successful: %s (mode=%04o, isDir=%v)", path, info.Mode().Perm(), info.IsDir())

	// If it's a new directory and recursive mode is on, watch it too
	if info.IsDir() && recursive {
		if err := watcher.Add(path); err != nil {
			log.Printf("[dir-watch] Failed to watch new dir %s: %v", path, err)
		}
	}

	kind := "file"
	if info.IsDir() {
		kind = "directory"
	}

	executable := info.Mode()&0111 != 0

	owner := fmt.Sprintf("mode=%04o", info.Mode().Perm())
	equip := kind
	if executable {
		equip = kind + " (executable)"
	}

	// Determine operation type and alert details
	var operation, title, activity string
	severity := notifier.SeverityContact

	if op&fsnotify.Write != 0 {
		operation = "modified"
		title = "File Modified in Watched Directory"
		activity = fmt.Sprintf("File modified: %s", name)
		severity = notifier.SeverityMovement // modifications are more concerning
	} else if op&fsnotify.Rename != 0 {
		operation = "renamed"
		title = "File Renamed in Watched Directory"
		activity = fmt.Sprintf("File renamed: %s", name)
	} else {
		operation = "created"
		title = "New Entry in Watched Directory"
		activity = fmt.Sprintf("New %s created: %s", kind, name)
		if info.IsDir() {
			severity = notifier.SeverityMovement
			title = "New Directory in Watched Path"
		}
	}

	alert := notifier.Alert{
		Severity:  severity,
		SkillID:   SkillID,
		SkillName: SkillName,
		Title:     title,
		Size:      "1 " + kind,
		Activity:  activity,
		Location:  filepath.Dir(path),
		Unit:      owner,
		Time:      time.Now(),
		Equipment: equip,
		Metadata: map[string]string{
			"path":       path,
			"kind":       kind,
			"operation":  operation,
			"executable": fmt.Sprintf("%v", executable),
		},
	}
	log.Printf("[dir-watch] Sending alert: %s - %s", alert.Title, alert.Activity)
	alerts <- alert
}
