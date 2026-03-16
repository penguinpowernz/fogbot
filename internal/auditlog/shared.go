package auditlog

import (
	"sync"
)

var (
	globalTailer *Tailer
	tailerMu     sync.Mutex
	tailerStarted bool
)

// GetGlobalTailer returns the singleton audit log tailer
// Creates it on first call, subsequent calls return the same instance
func GetGlobalTailer() (*Tailer, error) {
	tailerMu.Lock()
	defer tailerMu.Unlock()

	if globalTailer == nil {
		t, err := NewTailer("")
		if err != nil {
			return nil, err
		}
		globalTailer = t
	}

	return globalTailer, nil
}

// StartGlobalTailer ensures the global tailer is started
// Safe to call multiple times - only starts once
func StartGlobalTailer() error {
	tailerMu.Lock()
	defer tailerMu.Unlock()

	// Get or create the tailer
	if globalTailer == nil {
		t, err := NewTailer("")
		if err != nil {
			return err
		}
		globalTailer = t
	}

	// Only start if not already started
	if !tailerStarted {
		if err := globalTailer.Start(); err != nil {
			return err
		}
		tailerStarted = true
	}

	return nil
}

// StopGlobalTailer stops the global tailer if it exists
func StopGlobalTailer() {
	tailerMu.Lock()
	defer tailerMu.Unlock()

	if globalTailer != nil {
		globalTailer.Stop()
		globalTailer = nil
		tailerStarted = false
	}
}
