//go:build linux

package pilotservice

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// StateRoot is the parent of every per-mesh state dir on Linux.
const StateRoot = "/var/lib/pilot"

// UnitTemplatePath is where the (single) systemd template unit is installed.
const UnitTemplatePath = "/etc/systemd/system/pilot@.service"

// ServiceLabel is the systemd instance for a mesh (used in human-facing messages).
func ServiceLabel(mesh string) string { return "pilot@" + mesh }

// LogHint tells the operator how to tail a mesh's service logs.
func LogHint(mesh string) string { return "journalctl -u pilot@" + mesh + " -f" }

func (s Spec) envFile() string { return filepath.Join(s.StateDir, "service.env") }

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

// Install writes the systemd template unit + this mesh's EnvironmentFile, then
// enables and starts the per-mesh instance. Idempotent.
func Install(s Spec) error {
	if err := os.WriteFile(UnitTemplatePath, []byte(templateUnit), 0644); err != nil {
		return fmt.Errorf("write unit %s: %w", UnitTemplatePath, err)
	}
	if err := os.WriteFile(s.envFile(), []byte(RenderEnv(s)), 0640); err != nil {
		return fmt.Errorf("write env %s: %w", s.envFile(), err)
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	return systemctl("enable", "--now", ServiceLabel(s.Mesh))
}

// Uninstall disables + stops the per-mesh instance and clears any failed state.
// The shared template unit is left in place (other meshes may use it) — call
// RemoveTemplate once no instances remain.
func Uninstall(mesh string) error {
	if err := systemctl("disable", "--now", ServiceLabel(mesh)); err != nil {
		return err
	}
	_ = systemctl("reset-failed", ServiceLabel(mesh)) // best-effort: clear lingering failed state
	return nil
}

// RemoveTemplate removes the shared systemd template unit + reloads systemd. Call
// only when no mesh instances remain (full host cleanup); the binaries are left.
func RemoveTemplate() error {
	if err := os.Remove(UnitTemplatePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return systemctl("daemon-reload")
}

// Status returns a one-line "<active> (<enabled>)" summary for the mesh instance.
func Status(mesh string) (string, error) {
	active := systemctlOut("is-active", ServiceLabel(mesh))   // active|inactive|failed|...
	enabled := systemctlOut("is-enabled", ServiceLabel(mesh)) // enabled|disabled|...
	return fmt.Sprintf("%s (%s)", active, enabled), nil
}

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// systemctlOut runs a query subcommand whose nonzero exit is informational (e.g.
// is-active on a stopped unit) and returns the trimmed stdout regardless.
func systemctlOut(args ...string) string {
	out, _ := exec.Command("systemctl", args...).Output()
	s := strings.TrimSpace(string(out))
	if s == "" {
		return "unknown"
	}
	return s
}

// templateUnit is the static systemd TEMPLATE unit (pilot@.service). %i expands to
// the mesh id at instance start; per-mesh values come from the EnvironmentFile.
// Hardening is ported from packaging/systemd/pilot.service (M1.9). It runs as root
// in v1 (TUN needs CAP_NET_ADMIN); a dedicated-user + setcap variant is the
// documented hardening option (ADR 0008). The /var/lib/pilot path matches StateRoot.
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
