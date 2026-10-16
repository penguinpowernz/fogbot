// Package atomicfile writes files so that a crash or power loss part way
// through leaves either the old contents or the new, never a truncated file.
// fogbot refuses to start on a state file it can't parse, so a half-written
// state.json would otherwise keep the daemon down until someone fixed it.
package atomicfile

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// tmpMarker sits between the target's name and a random suffix in the name
// of the temporary file, e.g. .state.json.tmp-1a2b3c4d
const tmpMarker = ".tmp-"

// WriteFile writes data to a temporary file in path's directory, syncs it,
// and renames it over path. The file gets perm, whatever umask is in force.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	tmp := filepath.Join(dir, "."+base+tmpMarker+randomSuffix())

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	// Removes the temporary file if anything below fails; after the rename
	// there is nothing at tmp and this does nothing
	defer os.Remove(tmp)

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}

	// The rename only survives a crash once the directory is synced too
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("syncing %s: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("syncing %s: %w", dir, err)
	}
	return nil
}

// TargetOf returns the path a temporary file made by WriteFile is renamed
// to, and whether path is such a temporary file at all
func TargetOf(path string) (string, bool) {
	dir, base := filepath.Split(path)
	if !strings.HasPrefix(base, ".") {
		return "", false
	}
	i := strings.LastIndex(base, tmpMarker)
	if i <= 1 {
		return "", false
	}
	return filepath.Join(dir, base[1:i]), true
}

func randomSuffix() string {
	b := make([]byte, 4)
	rand.Read(b) // never fails; see crypto/rand
	return hex.EncodeToString(b)
}
