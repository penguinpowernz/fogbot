package auditlog

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hpcloud/tail"
)

// Event represents a parsed audit log event
type Event struct {
	Timestamp   time.Time
	RecordType  string // e.g., "SYSCALL", "PATH", "CWD"
	RuleKey     string // The -k key from auditctl
	UID         string
	AUID        string // Audit UID (original user)
	PID         string
	PPID        string
	Comm        string // Command name
	Exe         string // Executable path
	Cwd         string // Current working directory
	Path        string // File path being accessed
	Name        string // File name
	Syscall     string
	Success     string
	Exit        string
	RawMessage  string
	Metadata    map[string]string // Additional key=value pairs
}

// Subscriber receives events matching its filter key
type Subscriber struct {
	Key    string            // The auditctl -k key to filter on
	Events chan<- Event      // Channel to receive matching events
}

// Tailer tails the audit log and distributes events to subscribers
type Tailer struct {
	mu          sync.RWMutex
	subscribers map[string][]chan<- Event
	logPath     string
	tail        *tail.Tail
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

var (
	// Regex to extract key=value pairs from audit log lines
	kvRegex = regexp.MustCompile(`(\w+)=(?:"([^"]*)"|(\S+))`)
	// Regex to extract the rule key from "key=" field
	keyRegex = regexp.MustCompile(`key="([^"]+)"`)
)

// NewTailer creates a new audit log tailer
func NewTailer(logPath string) (*Tailer, error) {
	if logPath == "" {
		logPath = "/var/log/audit/audit.log"
	}

	ctx, cancel := context.WithCancel(context.Background())

	t := &Tailer{
		subscribers: make(map[string][]chan<- Event),
		logPath:     logPath,
		ctx:         ctx,
		cancel:      cancel,
	}

	return t, nil
}

// Subscribe registers a channel to receive events with the given rule key
func (t *Tailer) Subscribe(key string, events chan<- Event) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.subscribers[key] == nil {
		t.subscribers[key] = make([]chan<- Event, 0)
	}
	t.subscribers[key] = append(t.subscribers[key], events)
	log.Printf("[audit-tailer] New subscription for key: %s (total subscribers for key: %d)", key, len(t.subscribers[key]))
}

// Unsubscribe removes a channel from receiving events
func (t *Tailer) Unsubscribe(key string, events chan<- Event) {
	t.mu.Lock()
	defer t.mu.Unlock()

	subs := t.subscribers[key]
	for i, ch := range subs {
		if ch == events {
			t.subscribers[key] = append(subs[:i], subs[i+1:]...)
			break
		}
	}

	if len(t.subscribers[key]) == 0 {
		delete(t.subscribers, key)
	}
}

// Start begins tailing the audit log
func (t *Tailer) Start() error {
	// Check if log file exists
	if _, err := os.Stat(t.logPath); err != nil {
		return fmt.Errorf("audit log not found at %s: %w", t.logPath, err)
	}

	// Use hpcloud/tail to follow the log file
	tailConfig := tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: true,
		Location:  &tail.SeekInfo{Offset: 0, Whence: io.SeekEnd}, // Start at end
		Logger:    tail.DiscardingLogger,
	}

	var err error
	t.tail, err = tail.TailFile(t.logPath, tailConfig)
	if err != nil {
		return fmt.Errorf("failed to tail %s: %w", t.logPath, err)
	}

	log.Printf("[audit-tailer] Started tailing %s", t.logPath)

	t.wg.Add(1)
	go t.processLines()

	return nil
}

// Stop stops the tailer
func (t *Tailer) Stop() {
	t.cancel()
	if t.tail != nil {
		t.tail.Stop()
	}
	t.wg.Wait()
	log.Printf("[audit-tailer] Stopped")
}

// processLines reads lines from the tail and parses them
func (t *Tailer) processLines() {
	defer t.wg.Done()

	for {
		select {
		case <-t.ctx.Done():
			return

		case line, ok := <-t.tail.Lines:
			if !ok {
				return
			}

			if line.Err != nil {
				log.Printf("[audit-tailer] Error reading line: %v", line.Err)
				continue
			}

			// Parse the line
			event := t.parseLine(line.Text)
			if event == nil {
				continue // Not a line we care about
			}

			// Distribute to subscribers
			t.distribute(event)
		}
	}
}

// parseLine parses an audit log line into an Event
// Returns nil if the line doesn't have a key or isn't relevant
func (t *Tailer) parseLine(line string) *Event {
	// Skip empty lines
	if line == "" {
		return nil
	}

	// Extract the rule key first to see if anyone cares about this event
	keyMatch := keyRegex.FindStringSubmatch(line)
	if len(keyMatch) < 2 {
		return nil // No key, not from our rules
	}

	key := keyMatch[1]

	// Check if anyone is subscribed to this key
	t.mu.RLock()
	hasSubscribers := len(t.subscribers[key]) > 0
	t.mu.RUnlock()

	if !hasSubscribers {
		return nil // No one cares about this key
	}

	// Parse the full line
	event := &Event{
		RuleKey:    key,
		RawMessage: line,
		Metadata:   make(map[string]string),
	}

	// Extract timestamp from msg=audit(TIMESTAMP.MSEC:SEQUENCE)
	if idx := strings.Index(line, "msg=audit("); idx != -1 {
		tsStr := line[idx+10:]
		if end := strings.Index(tsStr, "."); end != -1 {
			tsStr = tsStr[:end]
			// Parse Unix timestamp
			if unixTime, err := strconv.ParseInt(tsStr, 10, 64); err == nil {
				event.Timestamp = time.Unix(unixTime, 0)
			}
		}
	}

	// If we couldn't parse timestamp, use now
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Extract record type
	if strings.HasPrefix(line, "type=") {
		parts := strings.SplitN(line, " ", 2)
		if len(parts) > 0 {
			event.RecordType = strings.TrimPrefix(parts[0], "type=")
		}
	}

	// Extract all key=value pairs
	matches := kvRegex.FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}

		key := match[1]
		value := match[2]
		if value == "" {
			value = match[3]
		}

		// Map common fields to Event struct
		switch key {
		case "uid":
			event.UID = value
		case "auid":
			event.AUID = value
		case "pid":
			event.PID = value
		case "ppid":
			event.PPID = value
		case "comm":
			event.Comm = value
		case "exe":
			event.Exe = value
		case "cwd":
			event.Cwd = value
		case "name":
			event.Name = value
		case "syscall":
			event.Syscall = value
		case "success":
			event.Success = value
		case "exit":
			event.Exit = value
		default:
			// Store in metadata
			event.Metadata[key] = value
		}
	}

	// For PATH records, extract the path from metadata if not already set
	// PATH records contain the actual file path in the "name" field
	if event.RecordType == "PATH" && event.Path == "" {
		if name, ok := event.Metadata["name"]; ok {
			event.Path = name
		}
	}

	return event
}

// distribute sends an event to all subscribers for its key
func (t *Tailer) distribute(event *Event) {
	t.mu.RLock()
	// Make a copy of the subscribers slice while holding the lock
	subscribers := make([]chan<- Event, len(t.subscribers[event.RuleKey]))
	copy(subscribers, t.subscribers[event.RuleKey])
	t.mu.RUnlock()

	for _, ch := range subscribers {
		select {
		case ch <- *event:
		default:
			log.Printf("[audit-tailer] Subscriber channel full for key %s, dropping event", event.RuleKey)
		}
	}
}

// ParseAuditLog is a simple helper for testing/debugging that reads a log file once
func ParseAuditLog(reader io.Reader) ([]Event, error) {
	var events []Event
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// This is a simplified parser - in production use the full tailer
		keyMatch := keyRegex.FindStringSubmatch(line)
		if len(keyMatch) < 2 {
			continue
		}

		event := Event{
			RuleKey:    keyMatch[1],
			RawMessage: line,
			Timestamp:  time.Now(),
			Metadata:   make(map[string]string),
		}

		// Extract basic fields
		matches := kvRegex.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) < 3 {
				continue
			}
			key := match[1]
			value := match[2]
			if value == "" {
				value = match[3]
			}

			switch key {
			case "uid":
				event.UID = value
			case "comm":
				event.Comm = value
			case "exe":
				event.Exe = value
			case "name":
				event.Name = value
			}
		}

		events = append(events, event)
	}

	return events, scanner.Err()
}
