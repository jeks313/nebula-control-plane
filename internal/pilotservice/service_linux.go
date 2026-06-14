//go:build linux

package pilotservice

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Install writes the systemd template unit + this mesh's EnvironmentFile, then
// enables and starts the per-mesh instance. Idempotent: the template is rewritten
// identically and `enable --now` is safe to repeat.
func Install(s Spec) error {
	if err := os.WriteFile(UnitTemplatePath, []byte(templateUnit), 0644); err != nil {
		return fmt.Errorf("write unit %s: %w", UnitTemplatePath, err)
	}
	if err := os.WriteFile(s.EnvFile(), []byte(RenderEnv(s)), 0640); err != nil {
		return fmt.Errorf("write env %s: %w", s.EnvFile(), err)
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	return systemctl("enable", "--now", s.Instance())
}

// Uninstall disables + stops the per-mesh instance. The shared template unit is
// left in place (other meshes may use it); identity/state removal is the caller's
// choice (pilot uninstall -purge).
func Uninstall(mesh string) error {
	return systemctl("disable", "--now", "pilot@"+mesh)
}

// Status returns a one-line "<active> (<enabled>)" summary for the mesh instance.
func Status(mesh string) (string, error) {
	inst := "pilot@" + mesh
	active := systemctlOut("is-active", inst)   // active|inactive|failed|...
	enabled := systemctlOut("is-enabled", inst) // enabled|disabled|...
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
