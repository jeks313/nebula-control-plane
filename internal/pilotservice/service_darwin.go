//go:build darwin

// macOS launchd backend (ADR 0008 Phase 4). Each mesh is a per-mesh system
// LaunchDaemon: a plist at /Library/LaunchDaemons/<label>.plist with the
// per-mesh `pilot supervise` argv baked in (launchd plists have no
// EnvironmentFile-include like systemd, so the values are inline). Runs as root
// (the utun device + routes need it); the daemon is keep-alive on non-clean exit
// only, since pilot supervises nebula internally + self-updates in place (ADR 0003).
//
// Validated on real macOS 26 (arm64): install/status/uninstall/-purge exercise the
// full launchctl bootstrap→enable→kickstart→bootout cycle, the rendered plist passes
// `plutil -lint`, and `pilot supervise` runs as the launchd daemon (KeepAlive restarts
// it on non-clean exit). See ADR 0008 Phase 4.
package pilotservice

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// StateRoot is the parent of every per-mesh state dir on macOS (no spaces, daemon-local).
const StateRoot = "/usr/local/var/pilot"

const labelPrefix = "com.nebula-control-plane.pilot."

// ServiceLabel is the launchd label for a mesh (also the plist basename).
func ServiceLabel(mesh string) string { return labelPrefix + mesh }

// LogHint tells the operator how to tail a mesh's service logs (launchd writes the
// daemon's stdout/stderr to this file — see StandardErrorPath in the plist).
func LogHint(mesh string) string { return "tail -f " + filepath.Join(StateRoot, mesh, "pilot.log") }

func plistPath(mesh string) string {
	return filepath.Join("/Library/LaunchDaemons", ServiceLabel(mesh)+".plist")
}

// renderPlist builds the per-mesh LaunchDaemon plist. ProgramArguments mirror the
// systemd ExecStart; the per-mesh paths + core URL are baked in (no env-file include).
func renderPlist(s Spec) string {
	nebula := s.NebulaPath
	if nebula == "" {
		nebula = "/usr/local/bin/nebula"
	}
	args := []string{
		"/usr/local/bin/pilot", "supervise",
		"-dir", s.StateDir,
		"-config", filepath.Join(s.StateDir, "config.yml"),
		"-config-pub", filepath.Join(s.StateDir, "config-signing.pub"),
		"-core", s.CoreURL,
		"-nebula", nebula,
		"-log-format", "json",
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString("<plist version=\"1.0\">\n<dict>\n")
	fmt.Fprintf(&b, "  <key>Label</key><string>%s</string>\n", xmlEscape(ServiceLabel(s.Mesh)))
	b.WriteString("  <key>ProgramArguments</key>\n  <array>\n")
	for _, a := range args {
		fmt.Fprintf(&b, "    <string>%s</string>\n", xmlEscape(a))
	}
	b.WriteString("  </array>\n")
	b.WriteString("  <key>RunAtLoad</key><true/>\n")
	// Restart on a non-clean exit only (≈ systemd Restart=on-failure); a clean
	// SIGTERM stop (uninstall) must not be auto-relaunched.
	b.WriteString("  <key>KeepAlive</key>\n  <dict><key>SuccessfulExit</key><false/></dict>\n")
	// AbandonProcessGroup: don't let launchd SIGKILL nebula's process group when the
	// pilot job dies — the pilot owns nebula's lifecycle (ADR 0003), so a pilot crash
	// must leave nebula running for the auto-restarted pilot to RE-ADOPT (Phase 3),
	// not drop the data plane. The launchd analogue of systemd KillMode=process.
	b.WriteString("  <key>AbandonProcessGroup</key><true/>\n")
	fmt.Fprintf(&b, "  <key>WorkingDirectory</key><string>%s</string>\n", xmlEscape(s.StateDir))
	logPath := filepath.Join(s.StateDir, "pilot.log")
	fmt.Fprintf(&b, "  <key>StandardOutPath</key><string>%s</string>\n", xmlEscape(logPath))
	fmt.Fprintf(&b, "  <key>StandardErrorPath</key><string>%s</string>\n", xmlEscape(logPath))
	b.WriteString("  <key>ProcessType</key><string>Background</string>\n")
	b.WriteString("</dict>\n</plist>\n")
	return b.String()
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// Render returns the LaunchDaemon plist this Spec would install (for `install -dry-run`).
func Render(s Spec) string { return renderPlist(s) }

// Install writes the per-mesh LaunchDaemon plist and bootstraps it into the system
// domain (RunAtLoad starts it). Idempotent: any prior instance is booted out first.
func Install(s Spec) error {
	p := plistPath(s.Mesh)
	if err := os.WriteFile(p, []byte(renderPlist(s)), 0644); err != nil {
		return fmt.Errorf("write plist %s: %w", p, err)
	}
	label := ServiceLabel(s.Mesh)
	_ = launchctl("bootout", "system/"+label) // clear any prior instance (ignore "not loaded")
	if err := launchctl("bootstrap", "system", p); err != nil {
		return err
	}
	_ = launchctl("enable", "system/"+label)          // ensure not disabled (ignore err)
	_ = launchctl("kickstart", "-k", "system/"+label) // (re)start now (ignore err)
	return nil
}

// Uninstall boots out the per-mesh daemon and removes its plist (the launchd
// service definition). The state dir is left for re-install unless -purge.
func Uninstall(mesh string) error {
	_ = launchctl("bootout", "system/"+ServiceLabel(mesh)) // stop+unload (ignore "not loaded")
	if err := os.Remove(plistPath(mesh)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove plist: %w", err)
	}
	return nil
}

// RemoveTemplate is a no-op on launchd: there is no shared template (each mesh has
// its own plist, removed by Uninstall).
func RemoveTemplate() error { return nil }

// Status returns "running" / "loaded (not running)" / "not loaded" for the mesh.
func Status(mesh string) (string, error) {
	out, err := exec.Command("launchctl", "print", "system/"+ServiceLabel(mesh)).CombinedOutput()
	if err != nil {
		return "not loaded", nil // `print` fails when the label isn't bootstrapped
	}
	if strings.Contains(string(out), "state = running") {
		return "running", nil
	}
	return "loaded (not running)", nil
}

func launchctl(args ...string) error {
	out, err := exec.Command("launchctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
