//go:build linux

package pilotservice

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// StateRoot is the parent of every per-mesh state dir on Linux.
const StateRoot = "/var/lib/pilot"

// BinDir is the writable dir (under StateRoot, included in the unit's ReadWritePaths)
// that holds the managed pilot binary; see BinPath.
const BinDir = StateRoot + "/bin"

// BinPath is the MANAGED pilot binary the service runs (ADR 0003 Phase 3). It lives in
// BinDir — writable — NOT /usr/local/bin, which ProtectSystem=strict makes read-only:
// the pilot self-update swaps this binary in place, so it must be writable by the
// service. `Install` copies the running pilot here.
const BinPath = BinDir + "/pilot"

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

// Render returns a preview (for `install -dry-run`) of the service definition this
// Spec would install: the systemd template unit + the per-mesh EnvironmentFile.
func Render(s Spec) string {
	return templateUnit + "\n# --- EnvironmentFile " + s.envFile() + " ---\n" + RenderEnv(s)
}

// Install writes the systemd template unit + this mesh's EnvironmentFile, then
// enables and starts the per-mesh instance. Idempotent.
func Install(s Spec) error {
	// Place the MANAGED pilot binary in the writable BinDir (the unit's ExecStart). The
	// service runs this copy so the Phase 3 self-update can swap it under ProtectSystem=
	// strict; the operator's install-time binary (often /usr/local/bin/pilot) stays put.
	if err := installManagedBinary(); err != nil {
		return err
	}
	if err := os.WriteFile(UnitTemplatePath, []byte(templateUnit), 0o644); err != nil {
		return fmt.Errorf("write unit %s: %w", UnitTemplatePath, err)
	}
	if err := os.WriteFile(s.envFile(), []byte(RenderEnv(s)), 0o640); err != nil {
		return fmt.Errorf("write env %s: %w", s.envFile(), err)
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	return systemctl("enable", "--now", ServiceLabel(s.Mesh))
}

// installManagedBinary copies the running pilot binary into the writable BinDir (the
// unit's ExecStart), atomically, so the service runs a binary the Phase 3 self-update
// can swap under ProtectSystem=strict. No-op when already running from BinPath. The
// rename is safe even if BinPath is a running executable (the running process keeps its
// old inode).
func installManagedBinary() error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate running pilot: %w", err)
	}
	if self == BinPath {
		return nil
	}
	if err := os.MkdirAll(BinDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", BinDir, err)
	}
	in, err := os.Open(self)
	if err != nil {
		return fmt.Errorf("open running pilot %s: %w", self, err)
	}
	defer in.Close()
	tmp := BinPath + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("copy pilot binary: %w", err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, BinPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install managed pilot %s: %w", BinPath, err)
	}
	return nil
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
# ExecStart is the MANAGED binary in the writable BinDir (ADR 0003 Phase 3), so a pilot
# self-update can swap it; ProtectSystem=strict keeps /usr read-only.
ExecStart=/var/lib/pilot/bin/pilot supervise \
    -dir /var/lib/pilot/%i \
    -config /var/lib/pilot/%i/config.yml \
    -config-pub /var/lib/pilot/%i/config-signing.pub \
    -core ${NCP_CORE_URL} \
    -nebula ${NCP_NEBULA} \
    -log-format json
# SIGHUP -> pilot hot-reloads nebula in place (firewall/lighthouse/PKI). M1.8.
ExecReload=/bin/kill -HUP $MAINPID
# KillMode=process (NOT control-group/mixed): systemd signals only pilot's main PID,
# never the cgroup. The pilot owns nebula's lifecycle (ADR 0003) — on a clean SIGTERM
# stop it stops nebula itself; on a pilot CRASH it leaves nebula running so the
# auto-restarted pilot RE-ADOPTS it (Phase 3) instead of systemd SIGKILLing the data
# plane out from under a self-update revert. (Trade-off: a pilot that hangs past
# TimeoutStopSec is SIGKILLed alone, briefly orphaning nebula until the next start.)
KillMode=process
KillSignal=SIGTERM
TimeoutStopSec=15
Restart=on-failure
RestartSec=2
# Writable despite ProtectSystem=strict: the per-mesh dir (renew rewrites cert/config)
# and the managed bin dir (the Phase 3 pilot self-update swaps its own binary there).
ReadWritePaths=/var/lib/pilot/%i /var/lib/pilot/bin

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
