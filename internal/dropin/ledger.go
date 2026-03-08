package dropin

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Ledger is an append-only log of configuration changes
type Ledger struct {
	mu   sync.Mutex
	path string
	file *os.File
}

// NewLedger creates or opens a ledger file
func NewLedger(path string) (*Ledger, error) {
	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating ledger directory: %w", err)
	}

	// Open file in append mode
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("opening ledger: %w", err)
	}

	return &Ledger{
		path: path,
		file: file,
	}, nil
}

// Write records a file write operation
func (l *Ledger) Write(operation, path, checksum string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := time.Now().UTC().Format(time.RFC3339)
	entry := fmt.Sprintf("%s  WRITE    file=%s  sha256=%s\n", timestamp, path, checksum)

	if _, err := l.file.WriteString(entry); err != nil {
		return fmt.Errorf("writing to ledger: %w", err)
	}

	return l.file.Sync()
}

// Enable records a skill enable operation
func (l *Ledger) Enable(skillName, dropinPath string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := time.Now().UTC().Format(time.RFC3339)
	entry := fmt.Sprintf("%s  ENABLE   skill=%s  dropin=%s\n", timestamp, skillName, dropinPath)

	if _, err := l.file.WriteString(entry); err != nil {
		return fmt.Errorf("writing to ledger: %w", err)
	}

	return l.file.Sync()
}

// Disable records a skill disable operation
func (l *Ledger) Disable(skillName, dropinPath string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := time.Now().UTC().Format(time.RFC3339)
	entry := fmt.Sprintf("%s  DISABLE  skill=%s  dropin=%s (removed)\n", timestamp, skillName, dropinPath)

	if _, err := l.file.WriteString(entry); err != nil {
		return fmt.Errorf("writing to ledger: %w", err)
	}

	return l.file.Sync()
}

// Remove records a file removal
func (l *Ledger) Remove(path string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := time.Now().UTC().Format(time.RFC3339)
	entry := fmt.Sprintf("%s  REMOVE   file=%s\n", timestamp, path)

	if _, err := l.file.WriteString(entry); err != nil {
		return fmt.Errorf("writing to ledger: %w", err)
	}

	return l.file.Sync()
}

// Approve records a baseline approval
func (l *Ledger) Approve(baselineType, path string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := time.Now().UTC().Format(time.RFC3339)
	entry := fmt.Sprintf("%s  APPROVE  baseline=%s  file=%s\n", timestamp, baselineType, path)

	if _, err := l.file.WriteString(entry); err != nil {
		return fmt.Errorf("writing to ledger: %w", err)
	}

	return l.file.Sync()
}

// Configure records a skill configuration change
func (l *Ledger) Configure(skillName, field, oldValue, newValue string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := time.Now().UTC().Format(time.RFC3339)
	entry := fmt.Sprintf("%s  CONFIG   skill=%s  changed=%s  old=%q  new=%q\n",
		timestamp, skillName, field, oldValue, newValue)

	if _, err := l.file.WriteString(entry); err != nil {
		return fmt.Errorf("writing to ledger: %w", err)
	}

	return l.file.Sync()
}

// ReadAll returns all ledger entries
func (l *Ledger) ReadAll() ([]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Open for reading
	file, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("opening ledger for reading: %w", err)
	}
	defer file.Close()

	var entries []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		entries = append(entries, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading ledger: %w", err)
	}

	return entries, nil
}

// Tail returns the last n entries from the ledger
func (l *Ledger) Tail(n int) ([]string, error) {
	entries, err := l.ReadAll()
	if err != nil {
		return nil, err
	}

	if len(entries) <= n {
		return entries, nil
	}

	return entries[len(entries)-n:], nil
}

// Close closes the ledger file
func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Close()
	}
	return nil
}
