package auditlog

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
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

	// pending holds keyed SYSCALL events, by audit serial, until their
	// CWD/PATH records and EOE arrive. Only touched by the processing goroutine.
	pending map[string]*pendingEvent

	// dead is set when the tailer stopped reading on its own. Guarded by mu.
	dead bool
}

// pendingEvent is a SYSCALL event waiting for the rest of its records
type pendingEvent struct {
	event    *Event
	paths    []map[string]string
	received time.Time
}

// pendingTimeout is how long to wait for an EOE record before emitting an event anyway
const pendingTimeout = 2 * time.Second

var (
	// Regex to extract key=value pairs from audit log lines
	kvRegex = regexp.MustCompile(`(\w+)=(?:"([^"]*)"|(\S+))`)
	// Regex to extract the event serial from msg=audit(TIMESTAMP:SERIAL)
	serialRegex = regexp.MustCompile(`msg=audit\([\d.]+:(\d+)\)`)
)

// x86_64Syscalls maps the syscall numbers the file and dir watchers care about
// to names, for audit logs written in RAW format (ENRICHED adds SYSCALL=name).
var x86_64Syscalls = map[string]string{
	"2": "open", "76": "truncate", "82": "rename", "83": "mkdir", "84": "rmdir",
	"85": "creat", "86": "link", "87": "unlink", "88": "symlink", "90": "chmod",
	"91": "fchmod", "92": "chown", "93": "fchown", "94": "lchown", "257": "openat",
	"258": "mkdirat", "260": "fchownat", "263": "unlinkat", "264": "renameat",
	"265": "linkat", "266": "symlinkat", "268": "fchmodat", "316": "renameat2",
}

// NewTailer creates a new audit log tailer
func NewTailer(logPath string) (*Tailer, error) {
	if logPath == "" {
		logPath = "/var/log/audit/audit.log"
	}

	ctx, cancel := context.WithCancel(context.Background())

	t := &Tailer{
		subscribers: make(map[string][]chan<- Event),
		pending:     make(map[string]*pendingEvent),
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

	if t.dead {
		// Nothing will ever arrive, so tell the subscriber straight away
		close(events)
		return
	}

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
	defer func() {
		if t.ctx.Err() == nil {
			log.Printf("[audit-tailer] Stopped reading %s: %v", t.logPath, t.tail.Err())
			t.fail()
		}
	}()

	ticker := time.NewTicker(pendingTimeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-t.ctx.Done():
			return

		case <-ticker.C:
			for _, event := range t.flushStale(time.Now()) {
				t.distribute(event)
			}

		case line, ok := <-t.tail.Lines:
			if !ok {
				return
			}

			if line.Err != nil {
				log.Printf("[audit-tailer] Error reading line: %v", line.Err)
				continue
			}

			for _, event := range t.handleLine(line.Text, time.Now()) {
				t.distribute(event)
			}
		}
	}
}

// handleLine feeds one audit log line into event assembly and returns any
// events that are now complete.
//
// auditd only puts the rule key on the SYSCALL record. The file path lives in
// the PATH records and the working directory in the CWD record, which share the
// SYSCALL's serial and are followed by an EOE record.
func (t *Tailer) handleLine(line string, now time.Time) []*Event {
	if t.pending == nil {
		t.pending = make(map[string]*pendingEvent)
	}

	m := serialRegex.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	serial := m[1]

	switch recordType(line) {
	case "SYSCALL":
		if event := t.parseLine(line); event != nil {
			t.pending[serial] = &pendingEvent{event: event, received: now}
		}
	case "CWD":
		if p := t.pending[serial]; p != nil {
			p.event.Cwd = parseFields(line)["cwd"]
		}
	case "PATH":
		if p := t.pending[serial]; p != nil {
			p.paths = append(p.paths, parseFields(line))
		}
	case "EOE":
		if p := t.pending[serial]; p != nil {
			delete(t.pending, serial)
			return append([]*Event{p.finish()}, t.flushStale(now)...)
		}
	}

	return t.flushStale(now)
}

// flushStale emits pending events that never received an EOE record
func (t *Tailer) flushStale(now time.Time) []*Event {
	var done []*Event
	for serial, p := range t.pending {
		if now.Sub(p.received) >= pendingTimeout {
			delete(t.pending, serial)
			done = append(done, p.finish())
		}
	}
	return done
}

// finish fills in the event's path from its PATH records
func (p *pendingEvent) finish() *Event {
	e := p.event

	// Prefer the record for the object acted on over its parent directory
	var chosen map[string]string
	for _, want := range []string{"CREATE", "DELETE", "NORMAL", ""} {
		for _, rec := range p.paths {
			if want == "" || rec["nametype"] == want {
				chosen = rec
				break
			}
		}
		if chosen != nil {
			break
		}
	}

	if chosen != nil {
		name := chosen["name"]
		if name != "" && name != "(null)" {
			if !filepath.IsAbs(name) && e.Cwd != "" {
				name = filepath.Join(e.Cwd, name)
			}
			e.Path = filepath.Clean(name)
			e.Name = filepath.Base(e.Path)
		}
		if mode := chosen["mode"]; mode != "" {
			e.Metadata["mode"] = mode
		}
	}

	return e
}

// ruleKey returns the record's key= field. It walks the line field by field
// rather than searching for `key="`, because comm and exe are attacker
// controlled: a process named `xkey=` would otherwise shift the match onto a
// bogus key and the event would be dropped unseen.
func ruleKey(line string) (string, bool) {
	key := ""
	for _, match := range kvRegex.FindAllStringSubmatch(line, -1) {
		if match[1] == "key" {
			key = match[2] // only a quoted key is a real rule key
		}
	}
	return key, key != ""
}

// recordType returns the value of the leading type= field
func recordType(line string) string {
	if !strings.HasPrefix(line, "type=") {
		return ""
	}
	end := strings.IndexByte(line, ' ')
	if end == -1 {
		end = len(line)
	}
	return line[len("type="):end]
}

// parseFields extracts all key=value pairs from an audit record
func parseFields(line string) map[string]string {
	fields := make(map[string]string)
	for _, match := range kvRegex.FindAllStringSubmatch(line, -1) {
		fields[match[1]] = fieldValue(match)
	}
	return fields
}

// hexEncodedFields are written unquoted as hex by auditd when the value
// contains spaces, quotes or control characters.
var hexEncodedFields = map[string]bool{"comm": true, "exe": true, "cwd": true, "name": true, "proctitle": true}

// fieldValue returns the value of a kvRegex match, decoding hex-encoded strings
func fieldValue(match []string) string {
	if match[2] != "" {
		return match[2]
	}
	value := match[3]
	if hexEncodedFields[match[1]] && value != "(null)" {
		if decoded, err := hex.DecodeString(value); err == nil {
			return string(decoded)
		}
	}
	return value
}

// parseLine parses an audit log line into an Event
// Returns nil if the line doesn't have a key or isn't relevant
func (t *Tailer) parseLine(line string) *Event {
	// Skip empty lines
	if line == "" {
		return nil
	}

	// Extract the rule key first to see if anyone cares about this event
	key, ok := ruleKey(line)
	if !ok {
		return nil // No key, not from our rules
	}

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
		value := fieldValue(match)

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

	// ENRICHED logs include the syscall name; RAW logs only have the number
	if name := event.Metadata["SYSCALL"]; name != "" {
		event.Syscall = name
	} else if name, ok := x86_64Syscalls[event.Syscall]; ok && event.Metadata["arch"] == "c000003e" {
		event.Syscall = name
	}

	return event
}

// fail marks the tailer dead and closes every subscriber's channel. Otherwise
// the file and dir watchers would carry on, looking healthy, without ever
// receiving another event; with their channels closed they exit, which raises
// a DEADMAN alert. Only called from processLines, so distribute can't be
// sending on a channel as it is closed.
func (t *Tailer) fail() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dead = true
	for _, subs := range t.subscribers {
		for _, ch := range subs {
			close(ch)
		}
	}
	t.subscribers = make(map[string][]chan<- Event)
}

// Dead reports whether the tailer stopped reading the audit log on its own
func (t *Tailer) Dead() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.dead
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
		key, ok := ruleKey(line)
		if !ok {
			continue
		}

		event := Event{
			RuleKey:    key,
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
