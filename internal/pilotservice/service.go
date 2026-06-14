// Package pilotservice installs pilot as a persistent, per-mesh OS service. v1 is
// systemd-only (Linux); the platform split (service_linux.go vs service_other.go)
// mirrors the repo's reload_unix/reload_windows + secure_unix/secure_windows
// convention so launchd / Windows SCM slot in later (ADR 0008 Phase 4).
//
// Per ADR 0008 a host can join multiple meshes, so the unit is a systemd TEMPLATE
// (`pilot@.service`, %i = mesh id); each mesh is a separate instance `pilot@<mesh>`
// with its own state dir (/var/lib/pilot/<mesh>) and per-mesh runtime config in an
// EnvironmentFile. The template is keep-alive only — pilot supervises nebula
// internally (backoff) and self-updates in place (ADR 0003), so systemd never
// manages nebula restarts.
package pilotservice

import (
	"errors"
	"fmt"
	"path/filepath"
)

// ErrUnsupported is returned by the service operations on non-systemd platforms.
var ErrUnsupported = errors.New("pilotservice: persistent service install is only supported on linux (systemd) in this build")

// StateRoot is the parent of every per-mesh state dir. Each mesh lives at
// StateRoot/<mesh> and the systemd template references /var/lib/pilot/%i.
const StateRoot = "/var/lib/pilot"

// UnitTemplatePath is where the (single) systemd template unit is installed.
const UnitTemplatePath = "/etc/systemd/system/pilot@.service"

// Spec describes a per-mesh pilot service.
type Spec struct {
	Mesh       string // mesh id; the systemd instance (pilot@<Mesh>) and dir name
	StateDir   string // per-mesh base dir (StateRoot/<Mesh>); holds config.yml + service.env
	CoreURL    string // Core API base URL over the mesh (renew/heartbeat)
	NebulaPath string // absolute path to the nebula binary the service runs
}

// Instance is the systemd instance name for this mesh, e.g. "pilot@dev".
func (s Spec) Instance() string { return "pilot@" + s.Mesh }

// EnvFile is the per-mesh EnvironmentFile path the template unit reads.
func (s Spec) EnvFile() string { return filepath.Join(s.StateDir, "service.env") }

// RenderEnv is the per-mesh systemd EnvironmentFile contents (the only bits that
// vary per mesh; the template unit is otherwise static and %i-derived).
func RenderEnv(s Spec) string {
	nebula := s.NebulaPath
	if nebula == "" {
		nebula = "/usr/local/bin/nebula"
	}
	return fmt.Sprintf("# written by `pilot install -mesh %s` — per-mesh service runtime config\nNCP_CORE_URL=%s\nNCP_NEBULA=%s\n",
		s.Mesh, s.CoreURL, nebula)
}

// templateUnit is the static systemd TEMPLATE unit (pilot@.service). %i expands to
// the mesh id at instance start; per-mesh values come from the EnvironmentFile.
// Hardening is ported from packaging/systemd/pilot.service (M1.9). It runs as root
// in v1 (TUN needs CAP_NET_ADMIN); a dedicated-user + setcap variant is the
// documented hardening option (ADR 0008).
const templateUnit = `[Unit]
Description=Nebula Control Plane pilot — mesh %i
Documentation=https://github.com/jeks313/nebula-control-plane
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=exec
# Per-mesh runtime config (NCP_CORE_URL, NCP_NEBULA), written by ` + "`pilot install`" + `.
EnvironmentFile=-/var/lib/pilot/%i/service.env
# pilot supervises nebula (its child); systemd supervises pilot. Paths are %i-derived.
ExecStart=/usr/local/bin/pilot supervise \
    -dir /var/lib/pilot/%i \
    -config /var/lib/pilot/%i/config.yml \
    -config-pub /var/lib/pilot/%i/config-signing.pub \
    -core ${NCP_CORE_URL} \
    -nebula ${NCP_NEBULA} \
    -log-format json
# SIGHUP -> pilot hot-reloads nebula in place (firewall/lighthouse/PKI). M1.8.
ExecReload=/bin/kill -HUP $MAINPID
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=15
Restart=on-failure
RestartSec=2
# The per-mesh dir must be writable despite ProtectSystem=strict (renew rewrites cert/config).
ReadWritePaths=/var/lib/pilot/%i

# --- Least privilege (M1.9): nebula needs CAP_NET_ADMIN for the TUN; nothing else.
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=yes

# --- Filesystem / kernel / process hardening ---
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
DevicePolicy=closed
DeviceAllow=/dev/net/tun rw
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX
UMask=0077

[Install]
WantedBy=multi-user.target
`
