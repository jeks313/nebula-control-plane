//go:build windows

// Windows Service Control Manager (SCM) backend (ADR 0008 Phase 4). Each mesh is
// its own auto-start Win32 service whose command line runs `pilot supervise` for
// that mesh; the running process registers with the SCM and turns Stop/Shutdown
// into a clean nebula teardown (see cmd/pilot/supervise_windows.go). SCM access
// needs an elevated (Administrator) token — the Windows analogue of root on Linux
// / sudo on macOS — so install/uninstall/status must run from an elevated prompt.
//
// Validated on real Windows Server 2022 (EC2): install/status/uninstall/-purge
// exercise the full mgr CreateService -> Start -> Control(Stop) -> Delete cycle,
// `pilot supervise` runs as the LocalSystem service (sc qc shows the quoted argv),
// and the recovery actions take effect with FAILURE_ACTIONS_ON_NONCRASH_FAILURES
// set. See ADR 0008 Phase 4. The demo Terraform's opt-in Windows client
// (deploy/terraform/windows.tf) reproduces the test host.
package pilotservice

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// StateRoot is the parent of every per-mesh state dir. Machine-scoped service
// state lives under %ProgramData% (consistent with internal/paths.DefaultBase).
var StateRoot = filepath.Join(programData(), "NebulaControlPlane", "pilot")

func programData() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return pd
	}
	return `C:\ProgramData`
}

// ServiceLabel is the SCM service name for a mesh. Mesh ids are pre-validated to
// [A-Za-z0-9][A-Za-z0-9_-]{0,31}, so this is always a legal Windows service name.
func ServiceLabel(mesh string) string { return "nebula-pilot-" + mesh }

func displayName(mesh string) string { return "Nebula Control Plane pilot (mesh " + mesh + ")" }

// LogHint tells the operator how to tail a mesh's service log. Under the SCM pilot
// redirects its own + nebula's output to this file (a service has no console).
func LogHint(mesh string) string {
	return `Get-Content -Wait "` + filepath.Join(StateRoot, mesh, "pilot.log") + `"`
}

// serviceArgs is the `pilot supervise` argv the service runs (the exe path is
// prepended by the SCM). Mirrors the systemd ExecStart / launchd ProgramArguments.
func serviceArgs(s Spec) []string {
	nebula := s.NebulaPath
	if nebula == "" {
		nebula = `C:\Program Files\Nebula\nebula.exe`
	}
	return []string{
		"supervise",
		"-dir", s.StateDir,
		"-config", filepath.Join(s.StateDir, "config.yml"),
		"-config-pub", filepath.Join(s.StateDir, "config-signing.pub"),
		"-core", s.CoreURL,
		"-nebula", nebula,
		"-log-format", "json",
	}
}

// Render previews the service definition this Spec would install (`install -dry-run`).
func Render(s Spec) string {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = "pilot.exe"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Windows service (SCM)\n")
	fmt.Fprintf(&b, "  name        : %s\n", ServiceLabel(s.Mesh))
	fmt.Fprintf(&b, "  display     : %s\n", displayName(s.Mesh))
	fmt.Fprintf(&b, "  start type  : automatic\n")
	fmt.Fprintf(&b, "  account     : LocalSystem\n")
	fmt.Fprintf(&b, "  recovery    : restart on failure or nonzero exit (2s; reset count after 24h)\n")
	fmt.Fprintf(&b, "  binary      : %s\n", exe)
	fmt.Fprintf(&b, "  arguments   : %s\n", strings.Join(serviceArgs(s), " "))
	fmt.Fprintf(&b, "  log         : %s\n", filepath.Join(s.StateDir, "pilot.log"))
	return b.String()
}

// Install creates (or recreates) the per-mesh auto-start service and starts it.
// Idempotent: any prior instance is removed first (mirrors launchd bootout->bootstrap
// and the systemd unit overwrite). Requires an elevated token.
func Install(s Spec) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate pilot.exe: %w", err)
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service manager (run from an elevated/Administrator prompt): %w", err)
	}
	defer m.Disconnect()

	name := ServiceLabel(s.Mesh)
	if err := removeService(m, name); err != nil {
		return err
	}
	cfg := mgr.Config{
		DisplayName: displayName(s.Mesh),
		Description: "Nebula Control Plane pilot - supervises nebula for mesh " + s.Mesh + " (enroll/renew/heartbeat).",
		StartType:   mgr.StartAutomatic,
		// ServiceType defaults to SERVICE_WIN32_OWN_PROCESS; the account defaults to LocalSystem.
	}
	args := serviceArgs(s)
	// CreateService can briefly fail with ERROR_SERVICE_MARKED_FOR_DELETE if the
	// prior instance's process is still finishing its deletion (removeService waits,
	// but a wedged stop can outrun its budget) — retry until the record clears.
	var service *mgr.Service
	for i := 0; ; i++ {
		service, err = m.CreateService(name, exe, cfg, args...)
		if err == nil {
			break
		}
		if errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) && i < 50 {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		return fmt.Errorf("create service %s: %w", name, err)
	}
	defer service.Close()

	// Restart pilot on a crash OR a nonzero-exit stop — the analogue of systemd
	// Restart=on-failure / launchd KeepAlive{SuccessfulExit:false}. pilot supervises
	// nebula itself, so this only covers pilot exiting unexpectedly. The svc
	// dispatcher always reports SERVICE_STOPPED when supervise returns, so the SCM
	// would treat even a nonzero exit as a clean stop and NEVER run these actions
	// unless we also opt into failure actions on non-crash exits — without the flag
	// below, SetRecoveryActions is dead code.
	_ = service.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 2 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 2 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 2 * time.Second},
	}, 86400) // reset the failure count after a day of stability
	_ = service.SetRecoveryActionsOnNonCrashFailures(true)

	if err := service.Start(); err != nil {
		return fmt.Errorf("start service %s: %w", name, err)
	}
	return nil
}

// Uninstall stops and removes a mesh's service. Idempotent (a missing service is
// not an error). The state dir is left for re-install unless the caller purges it.
func Uninstall(mesh string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service manager (run from an elevated/Administrator prompt): %w", err)
	}
	defer m.Disconnect()
	return removeService(m, ServiceLabel(mesh))
}

// RemoveTemplate is a no-op on Windows: there is no shared/host-level artifact
// (each mesh is a standalone service, removed by Uninstall) — mirrors launchd.
func RemoveTemplate() error { return nil }

// Status reports a mesh's service state: running / stopped / start pending / stop
// pending / not loaded. Needs an elevated token (SCM access), like macOS status.
func Status(mesh string) (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", fmt.Errorf("connect to the service manager (run from an elevated/Administrator prompt): %w", err)
	}
	defer m.Disconnect()
	service, err := m.OpenService(ServiceLabel(mesh))
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return "not loaded", nil
		}
		return "", err
	}
	defer service.Close()
	st, err := service.Query()
	if err != nil {
		return "", err
	}
	switch st.State {
	case svc.Running:
		return "running", nil
	case svc.Stopped:
		return "stopped", nil
	case svc.StartPending:
		return "start pending", nil
	case svc.StopPending:
		return "stop pending", nil
	default:
		return fmt.Sprintf("state %d", uint32(st.State)), nil
	}
}

// removeService stops (if running) and deletes a service, then waits for the SCM
// to drop it. Returns nil if the service does not exist (idempotent). Service
// deletion is asynchronous — the SCM removes the record once the service is
// stopped and all handles are closed — so we poll until it is gone to keep a
// subsequent CreateService from hitting ERROR_SERVICE_MARKED_FOR_DELETE.
func removeService(m *mgr.Mgr, name string) error {
	service, err := m.OpenService(name)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		return fmt.Errorf("open service %s: %w", name, err)
	}
	if _, err := service.Control(svc.Stop); err == nil {
		waitStopped(service) // give it time to stop so Delete completes promptly
	}
	delErr := service.Delete()
	service.Close()
	if delErr != nil && !errors.Is(delErr, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return fmt.Errorf("delete service %s: %w", name, delErr)
	}
	for i := 0; i < 100; i++ { // up to ~10s for the SCM to drop the record
		s2, err := m.OpenService(name)
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		if err == nil {
			s2.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil // proceed; CreateService surfaces a still-pending deletion if any
}

// waitStopped polls until the service reports Stopped (or ~15s elapses).
func waitStopped(s *mgr.Service) {
	for i := 0; i < 75; i++ {
		st, err := s.Query()
		if err != nil || st.State == svc.Stopped {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}
