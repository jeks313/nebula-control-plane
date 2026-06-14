//go:build !windows

package paths

import "os"

// DefaultBase is the system-wide location for Pilot's identity material on POSIX.
func DefaultBase() string { return "/etc/nebula-control-plane" }

// secureMkdir creates dir (and parents) restricted to the owner. We chmod after
// MkdirAll because the process umask can clear bits passed to MkdirAll.
func secureMkdir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}
