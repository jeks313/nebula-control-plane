//go:build windows

package paths

import "os"

// DefaultBase is %ProgramData%\NebulaControlPlane (per M1.3). ProgramData is the
// right home for machine-scoped service state on Windows.
func DefaultBase() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return pd + `\NebulaControlPlane`
}

// secureMkdir creates the directory. Windows ignores POSIX mode bits, so this is
// only the floor: the directory exists, but it is NOT yet locked down.
//
// TODO(M1.3 Windows / M1.3a): apply an explicit DACL — owner = the Pilot service
// account + SYSTEM, remove inherited ACEs — and DPAPI/CNG-wrap host.key at rest
// (optionally TPM-backed). Until a Windows CI runner exists to assert that the
// key is unreadable by other principals, this stub must not be treated as
// providing confidentiality on Windows.
func secureMkdir(dir string) error {
	return os.MkdirAll(dir, 0700)
}
