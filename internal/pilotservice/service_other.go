//go:build !linux

// Stubs for non-systemd platforms. launchd (macOS) + Windows SCM are ADR 0008
// Phase 4; until then the service operations fail-closed with ErrUnsupported.
// The pure helpers (Spec, RenderEnv) live in service.go and work everywhere.
package pilotservice

// Install is unsupported off systemd in this build.
func Install(s Spec) error { return ErrUnsupported }

// Uninstall is unsupported off systemd in this build.
func Uninstall(mesh string) error { return ErrUnsupported }

// Status is unsupported off systemd in this build.
func Status(mesh string) (string, error) { return "", ErrUnsupported }
