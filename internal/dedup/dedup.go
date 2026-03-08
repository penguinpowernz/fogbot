package dedup

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
)

// Engine handles alert deduplication and rate limiting
type Engine struct {
	mu         sync.RWMutex
	window     time.Duration
	maxBurst   int
	alerts     map[string]*alertState
	ticker     *time.Ticker
	stopClean  chan struct{}
	suppressed int64 // counter for suppressed alerts
}

type alertState struct {
	firstSeen time.Time
	lastSeen  time.Time
	count     int
	digest    []notifier.Alert // for building digest messages
}

// NewEngine creates a new deduplication engine
func NewEngine(window time.Duration, maxBurst int) *Engine {
	e := &Engine{
		window:    window,
		maxBurst:  maxBurst,
		alerts:    make(map[string]*alertState),
		ticker:    time.NewTicker(window),
		stopClean: make(chan struct{}),
	}

	// Start cleanup goroutine
	go e.cleanupLoop()

	return e
}

// Process checks if an alert should be sent or suppressed
// Returns (shouldSend, isDigest, digestCount)
func (e *Engine) Process(alert notifier.Alert) (bool, bool, int) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// RED (CONTACT) alerts always fire immediately
	if alert.Severity == notifier.SeverityContact {
		return true, false, 0
	}

	// Generate fingerprint for this alert type
	fingerprint := e.fingerprint(alert)

	state, exists := e.alerts[fingerprint]
	if !exists {
		// First time seeing this alert
		state = &alertState{
			firstSeen: time.Now(),
			lastSeen:  time.Now(),
			count:     1,
			digest:    []notifier.Alert{alert},
		}
		e.alerts[fingerprint] = state
		return true, false, 0
	}

	// Update state
	state.lastSeen = time.Now()
	state.count++
	state.digest = append(state.digest, alert)

	// Check if we're within the burst window
	if time.Since(state.firstSeen) < e.window {
		if state.count <= e.maxBurst {
			// Within burst limit, send it
			return true, false, 0
		} else {
			// Exceeded burst limit, suppress
			e.suppressed++
			return false, false, 0
		}
	}

	// Window expired, send digest and reset
	digestCount := state.count
	state.firstSeen = time.Now()
	state.lastSeen = time.Now()
	state.count = 1
	state.digest = []notifier.Alert{alert}

	return true, true, digestCount
}

// fingerprint generates a unique key for alert deduplication
func (e *Engine) fingerprint(alert notifier.Alert) string {
	// Deduplicate based on: skill + title + location
	data := fmt.Sprintf("%d:%s:%s", alert.SkillID, alert.Title, alert.Location)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:8])
}

// cleanupLoop periodically removes stale alert states
func (e *Engine) cleanupLoop() {
	for {
		select {
		case <-e.ticker.C:
			e.cleanup()
		case <-e.stopClean:
			return
		}
	}
}

// cleanup removes alert states older than 2x the window
func (e *Engine) cleanup() {
	e.mu.Lock()
	defer e.mu.Unlock()

	cutoff := time.Now().Add(-2 * e.window)
	for fp, state := range e.alerts {
		if state.lastSeen.Before(cutoff) {
			delete(e.alerts, fp)
		}
	}
}

// SuppressedCount returns the number of suppressed alerts
func (e *Engine) SuppressedCount() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.suppressed
}

// ResetSuppressedCount resets the suppressed counter (for periodic reports)
func (e *Engine) ResetSuppressedCount() int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	count := e.suppressed
	e.suppressed = 0
	return count
}

// Close shuts down the deduplication engine
func (e *Engine) Close() {
	close(e.stopClean)
	e.ticker.Stop()
}
