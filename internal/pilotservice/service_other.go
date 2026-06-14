//go:build !linux && !darwin

// Stubs for platforms without a supported service manager in this build (e.g.
// Windows SCM — a later phase). The service operations fail-closed with
// ErrUnsupported; the pure helpers (Spec) live in service.go and work everywhere.
package pilotservice

// StateRoot is a placeholder on unsupported platforms (the service step fails before
// it matters; enroll still uses it to lay out the per-mesh dir).
const StateRoot = "/var/lib/pilot"

// ServiceLabel + LogHint are best-effort identifiers for messages.
func ServiceLabel(mesh string) string { return "pilot-" + mesh }
func LogHint(mesh string) string      { return "(no service manager on this platform)" }

// Install is unsupported on this platform in this build.
func Install(s Spec) error { return ErrUnsupported }

// Uninstall is unsupported on this platform in this build.
func Uninstall(mesh string) error { return ErrUnsupported }

// RemoveTemplate is unsupported on this platform in this build.
func RemoveTemplate() error { return ErrUnsupported }

// Status is unsupported on this platform in this build.
func Status(mesh string) (string, error) { return "", ErrUnsupported }
