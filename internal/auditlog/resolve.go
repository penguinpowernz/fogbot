package auditlog

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// ResolvePath finds the real path of an event whose PATH record was relative
// to a directory that couldn't be looked up (see Event.PathUnresolved), among
// roots, the paths the event's audit rule watches. It matches the inodes the
// PATH records give against each root, its directory, and the entry of that
// name in it.
func ResolvePath(e Event, roots []string) (string, bool) {
	name := filepath.Base(e.Path)
	for _, root := range roots {
		root = filepath.Clean(root)
		switch {
		case e.Inode != "" && SameFile(root, e.Inode, e.Dev):
			return root, true // the watched file itself
		case e.ParentInode != "" && SameFile(root, e.ParentInode, e.ParentDev):
			return filepath.Join(root, name), true // an entry in a watched directory
		case e.ParentInode != "" && filepath.Base(root) == name && SameFile(filepath.Dir(root), e.ParentInode, e.ParentDev):
			return root, true // the watched file, since deleted or replaced
		case e.Inode != "" && SameFile(filepath.Join(root, name), e.Inode, e.Dev):
			return filepath.Join(root, name), true
		}
	}
	return "", false
}

// SameFile reports whether path is the file with inode on dev, as a PATH
// record gives them: inode in decimal, dev as hex major:minor ("fd:01"). An
// empty dev isn't checked.
func SameFile(path, inode, dev string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if strconv.FormatUint(st.Ino, 10) != inode {
		return false
	}
	return dev == "" || formatDev(uint64(st.Dev)) == dev
}

// formatDev formats a device number the way audit does, hex major:minor
func formatDev(dev uint64) string {
	major := (dev>>8)&0xfff | (dev>>32)&^0xfff
	minor := dev&0xff | (dev>>12)&^0xff
	return fmt.Sprintf("%02x:%02x", major, minor)
}
