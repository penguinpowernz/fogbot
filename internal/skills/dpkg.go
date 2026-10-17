package skills

import (
	"os"
	"syscall"
)

// DpkgLocks are the locks dpkg and its frontends (apt, unattended-upgrades,
// PackageKit) hold for the whole of a package run, maintainer scripts included
var DpkgLocks = []string{"/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock"}

// DpkgRunning reports whether any of locks is held by another process, which
// for the dpkg locks means a package is being installed, removed or upgraded.
// F_GETLK only tests the lock; it never takes it, so dpkg is not blocked.
func DpkgRunning(locks []string) bool {
	for _, path := range locks {
		f, err := os.Open(path)
		if err != nil {
			continue // no dpkg on this system, or nothing has ever locked it
		}
		lk := syscall.Flock_t{Type: syscall.F_WRLCK}
		err = syscall.FcntlFlock(f.Fd(), syscall.F_GETLK, &lk)
		f.Close()
		if err == nil && lk.Type != syscall.F_UNLCK {
			return true
		}
	}
	return false
}
