package auditlog

import (
	"strings"
	"testing"
)

func TestParseAuditLogLine(t *testing.T) {
	// Sample audit log line for file watch event
	sampleLine := `type=SYSCALL msg=audit(1710547200.123:456): arch=c000003e syscall=2 success=yes exit=3 a0=7ffd12345678 a1=0 a2=1b6 a3=0 items=1 ppid=1234 pid=5678 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="bash" exe="/bin/bash" key="fb-file-500"`

	tailer := &Tailer{
		subscribers: make(map[string][]chan<- Event),
	}

	// Add a subscriber for this key
	eventChan := make(chan Event, 1)
	tailer.Subscribe("fb-file-500", eventChan)

	// Parse the line
	event := tailer.parseLine(sampleLine)

	if event == nil {
		t.Fatal("Expected event to be parsed, got nil")
	}

	if event.RuleKey != "fb-file-500" {
		t.Errorf("Expected RuleKey=fb-file-500, got %s", event.RuleKey)
	}

	if event.UID != "0" {
		t.Errorf("Expected UID=0, got %s", event.UID)
	}

	if event.Comm != "bash" {
		t.Errorf("Expected Comm=bash, got %s", event.Comm)
	}

	if event.Exe != "/bin/bash" {
		t.Errorf("Expected Exe=/bin/bash, got %s", event.Exe)
	}

	if event.PID != "5678" {
		t.Errorf("Expected PID=5678, got %s", event.PID)
	}

	if event.PPID != "1234" {
		t.Errorf("Expected PPID=1234, got %s", event.PPID)
	}
}

func TestParseAuditLogLineNoKey(t *testing.T) {
	// Line without a key should return nil
	sampleLine := `type=SYSCALL msg=audit(1710547200.123:456): arch=c000003e syscall=2 success=yes`

	tailer := &Tailer{
		subscribers: make(map[string][]chan<- Event),
	}

	event := tailer.parseLine(sampleLine)

	if event != nil {
		t.Errorf("Expected nil for line without key, got %+v", event)
	}
}

func TestParseAuditLogLineNoSubscribers(t *testing.T) {
	// Line with key but no subscribers should return nil
	sampleLine := `type=SYSCALL msg=audit(1710547200.123:456): arch=c000003e syscall=2 key="fb-file-500"`

	tailer := &Tailer{
		subscribers: make(map[string][]chan<- Event),
	}

	event := tailer.parseLine(sampleLine)

	if event != nil {
		t.Errorf("Expected nil for line with no subscribers, got %+v", event)
	}
}

func TestParseAuditLog(t *testing.T) {
	// Test the helper function with multiple lines
	logData := `type=SYSCALL msg=audit(1710547200.123:456): uid=0 comm="vi" exe="/usr/bin/vi" key="fb-file-500"
type=PATH msg=audit(1710547200.123:456): item=0 name="/etc/passwd" inode=12345 key="fb-file-500"
type=SYSCALL msg=audit(1710547200.124:457): uid=1000 comm="touch" exe="/usr/bin/touch" key="fb-dir-540"
`

	reader := strings.NewReader(logData)
	events, err := ParseAuditLog(reader)

	if err != nil {
		t.Fatalf("ParseAuditLog failed: %v", err)
	}

	if len(events) != 3 {
		t.Errorf("Expected 3 events, got %d", len(events))
	}

	// Check first event
	if events[0].RuleKey != "fb-file-500" {
		t.Errorf("Expected first event key=fb-file-500, got %s", events[0].RuleKey)
	}

	if events[0].Comm != "vi" {
		t.Errorf("Expected first event comm=vi, got %s", events[0].Comm)
	}

	// Check third event
	if events[2].RuleKey != "fb-dir-540" {
		t.Errorf("Expected third event key=fb-dir-540, got %s", events[2].RuleKey)
	}

	if events[2].UID != "1000" {
		t.Errorf("Expected third event uid=1000, got %s", events[2].UID)
	}
}
