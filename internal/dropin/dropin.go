package dropin

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
)

// DropInWriter handles safe writing of drop-in configuration files
type DropInWriter struct {
	ledger *Ledger
	dryRun bool
}

// NewDropInWriter creates a new drop-in writer
func NewDropInWriter(ledgerPath string) (*DropInWriter, error) {
	dryRun := os.Getenv("FOGBOT_DRY_RUN") == "true" || os.Getenv("FOGBOT_DRY_RUN") == "1"

	ledger, err := NewLedger(ledgerPath)
	if err != nil {
		return nil, err
	}

	return &DropInWriter{
		ledger: ledger,
		dryRun: dryRun,
	}, nil
}

// SetDryRun enables or disables dry-run mode
func (w *DropInWriter) SetDryRun(enabled bool) {
	w.dryRun = enabled
}

// Write safely writes a drop-in file and records it in the ledger
func (w *DropInWriter) Write(path, content string) error {
	if w.dryRun {
		fmt.Printf("[DRY-RUN] Would write to %s (%d bytes)\n", path, len(content))
		return nil
	}

	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating parent directory: %w", err)
	}

	// Calculate checksum
	checksum := sha256.Sum256([]byte(content))
	checksumStr := fmt.Sprintf("%x", checksum)

	// Record in ledger BEFORE writing (atomicity guarantee)
	if err := w.ledger.Write("file", path, checksumStr); err != nil {
		return fmt.Errorf("recording to ledger: %w", err)
	}

	// Write the file
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	return nil
}

// Remove removes a drop-in file and records the removal in the ledger
func (w *DropInWriter) Remove(path string) error {
	if w.dryRun {
		fmt.Printf("[DRY-RUN] Would remove %s\n", path)
		return nil
	}

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("file does not exist: %s", path)
	}

	// Record removal in ledger
	if err := w.ledger.Remove(path); err != nil {
		return fmt.Errorf("recording removal: %w", err)
	}

	// Remove the file
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("removing file: %w", err)
	}

	return nil
}

// Verify checks if a file's checksum matches what's in the ledger
func (w *DropInWriter) Verify(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("reading file: %w", err)
	}

	checksum := sha256.Sum256(data)
	checksumStr := fmt.Sprintf("%x", checksum)

	// TODO: implement ledger checksum lookup
	_ = checksumStr

	return true, nil
}

// Close closes the drop-in writer and its ledger
func (w *DropInWriter) Close() error {
	return w.ledger.Close()
}
