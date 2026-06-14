// Package pilotservice installs pilot as a persistent, per-mesh OS service. The
// platform split mirrors the repo's reload_unix/reload_windows + secure_unix/
// secure_windows convention:
//
//	service_linux.go   — systemd (template unit pilot@<mesh> + EnvironmentFile)
//	service_darwin.go  — launchd (a per-mesh LaunchDaemon plist)         [ADR 0008 Phase 4]
//	service_windows.go — Windows SCM (a per-mesh auto-start Win32 service) [ADR 0008 Phase 4]
//	service_other.go   — stubs (ErrUnsupported) for everything else      [e.g. the *BSDs]
//
// Per ADR 0008 a host can join multiple meshes, so each mesh is its own service
// with its own state dir (StateRoot/<mesh>) and config. The service is keep-alive
// only — pilot supervises nebula internally (backoff) and self-updates in place
// (ADR 0003), so the OS never manages nebula restarts.
//
// Each platform file provides the same API: StateRoot, Install/Uninstall/Status/
// RemoveTemplate, Render, and ServiceLabel/LogHint (for human-facing messages).
package pilotservice

import "errors"

// ErrUnsupported is returned by the service operations on platforms without a
// supported service manager in this build.
var ErrUnsupported = errors.New("pilotservice: persistent service install is not supported on this platform in this build")

// Spec describes a per-mesh pilot service. StateDir is the per-mesh base
// (StateRoot/<Mesh>) that holds config.yml + the config-signing pin.
type Spec struct {
	Mesh       string // mesh id; the per-mesh service identity + dir name
	StateDir   string // per-mesh base dir (StateRoot/<Mesh>)
	CoreURL    string // Core API base URL over the mesh (renew/heartbeat)
	NebulaPath string // absolute path to the nebula binary the service runs
}
