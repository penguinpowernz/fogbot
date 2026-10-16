package dedup

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
)

// Engine handles alert deduplication and rate limiting
type Engine struct {
	mu       sync.RWMutex
	window   time.Duration
	maxBurst int
	alerts   map[string]*alertState

	// CONTACT alerts are rate limited separately, see processContact
	contactBurst int
	contacts     map[string]*contactState

	ticker     *time.Ticker
	stopClean  chan struct{}
	closeOnce  sync.Once
	suppressed int64 // counter for suppressed alerts
}

type alertState struct {
	firstSeen  time.Time
	lastSeen   time.Time
	count      int
	suppressed int            // alerts held back this window, reported by Digests
	last       notifier.Alert // the latest suppressed alert
}

// contactState tracks one kind of CONTACT alert over a window
type contactState struct {
	start      time.Time
	sent       int
	suppressed int
	last       notifier.Alert // the latest suppressed alert
	locations  []string       // distinct locations of suppressed alerts, capped
}

// maxDigestLocations caps how many locations a CONTACT digest lists
const maxDigestLocations = 5

// NewEngine creates a new deduplication engine. Up to contactBurst CONTACT
// alerts of each kind are sent per window, the rest summarised in a digest.
func NewEngine(window time.Duration, maxBurst, contactBurst int) *Engine {
	// time.NewTicker panics on a non-positive interval
	if window <= 0 {
		window = 5 * time.Minute
	}
	if maxBurst <= 0 {
		maxBurst = 10
	}
	if contactBurst <= 0 {
		contactBurst = 20
	}

	e := &Engine{
		window:       window,
		maxBurst:     maxBurst,
		contactBurst: contactBurst,
		contacts:     make(map[string]*contactState),
		alerts:       make(map[string]*alertState),
		ticker:       time.NewTicker(window),
		stopClean:    make(chan struct{}),
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

	if alert.Severity == notifier.SeverityContact {
		return e.processContact(alert, time.Now()), false, 0
	}

	now := time.Now()
	fingerprint := e.fingerprint(alert)

	state, exists := e.alerts[fingerprint]
	if !exists || now.Sub(state.firstSeen) >= e.window {
		// A new window. Alerts still held back from the last one go out with
		// this one, in case Digests hasn't reported them yet.
		held := 0
		if exists {
			held = state.suppressed
		}
		e.alerts[fingerprint] = &alertState{firstSeen: now, lastSeen: now, count: 1}
		if held > 0 {
			return true, true, held + 1
		}
		return true, false, 0
	}

	state.lastSeen = now
	state.count++
	if state.count <= e.maxBurst {
		return true, false, 0
	}

	// Exceeded the burst limit. Held back, not dropped: Digests reports these
	// when the window ends. Before, they were only counted into a digest sent
	// with the next alert of the kind, so if none came they were never
	// reported, and the 11th package of an install went unseen.
	state.suppressed++
	state.last = alert
	e.suppressed++
	return false, false, 0
}

// processContact reports whether a CONTACT alert is sent now.
//
// CONTACT alerts used to bypass rate limiting entirely, so anything that could
// cause a stream of them buried the ones that mattered: a spoofed SYN flood to
// tripwire ports alerts once per source address, and Telegram rate limits a
// bot sending more than about one message a second, so every later alert
// (from any skill) queued behind retries. Now the first contactBurst of each
// kind per window go out at once, as before, and the rest are folded into one
// digest sent when the window ends (see Digests). None are dropped unreported.
func (e *Engine) processContact(alert notifier.Alert, now time.Time) bool {
	key := e.contactKey(alert)
	st, ok := e.contacts[key]
	if !ok {
		st = &contactState{start: now}
		e.contacts[key] = st
	}
	if st.sent < e.contactBurst {
		st.sent++
		return true
	}

	st.suppressed++
	e.suppressed++
	st.last = alert
	if len(st.locations) < maxDigestLocations && alert.Location != "" {
		seen := false
		for _, l := range st.locations {
			seen = seen || l == alert.Location
		}
		if !seen {
			st.locations = append(st.locations, alert.Location)
		}
	}
	return false
}

// contactKey groups CONTACT alerts by skill and title. Location is left out:
// a flood varies it (one alert per source address), which is what made each
// alert look new.
func (e *Engine) contactKey(alert notifier.Alert) string {
	return fmt.Sprintf("%d:%s", alert.SkillID, alert.Title)
}

// Digests returns a digest for each kind of alert whose window has ended with
// alerts suppressed, and starts a new window for it. Call it regularly;
// suppressed alerts are only reported through it.
func (e *Engine) Digests(now time.Time) []notifier.Alert {
	e.mu.Lock()
	defer e.mu.Unlock()

	var digests []notifier.Alert
	for key, st := range e.contacts {
		if now.Sub(st.start) < e.window {
			continue
		}
		if st.suppressed == 0 {
			delete(e.contacts, key)
			continue
		}

		d := e.digest(st.last, st.suppressed, now)
		locations := strings.Join(st.locations, ", ")
		if st.suppressed > len(st.locations) {
			locations += ", …"
		}
		d.Location = locations
		digests = append(digests, d)

		// The next alert of this kind starts a fresh window, so one arriving
		// after a flood has stopped isn't held back
		delete(e.contacts, key)
	}

	// Other alerts are grouped by location too, so the digest keeps it
	for fp, st := range e.alerts {
		if st.suppressed == 0 || now.Sub(st.firstSeen) < e.window {
			continue
		}
		digests = append(digests, e.digest(st.last, st.suppressed, now))
		delete(e.alerts, fp)
	}
	return digests
}

// digest summarises suppressed alerts, of which last is the latest
func (e *Engine) digest(last notifier.Alert, suppressed int, now time.Time) notifier.Alert {
	d := last
	d.Title = fmt.Sprintf("%s (digest: %d more)", d.Title, suppressed)
	d.Size = fmt.Sprintf("%d events", suppressed)
	d.Activity = fmt.Sprintf("%d more alerts like this in %v, held back to keep alerts flowing; latest: %s", suppressed, e.window, d.Activity)
	d.Time = now
	return d
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
		// Held-back alerts wait for Digests
		if state.lastSeen.Before(cutoff) && state.suppressed == 0 {
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

// Close shuts down the deduplication engine. Safe to call multiple times.
func (e *Engine) Close() {
	e.closeOnce.Do(func() {
		close(e.stopClean)
		e.ticker.Stop()
	})
}
