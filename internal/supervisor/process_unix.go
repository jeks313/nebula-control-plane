//go:build !windows

package supervisor

import (
	"os/exec"
	"syscall"
)

// setSysProcAttr puts the child in its own process group so we can signal the
// whole group (nebula + any children) on shutdown.
func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// terminate asks the child's process group to stop (SIGTERM to -pgid).
func terminate(cmd *exec.Cmd) error {
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
}

// forceKill hard-kills the child's process group (SIGKILL to -pgid).
func forceKill(cmd *exec.Cmd) error {
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

// signalReload sends SIGHUP to nebula itself (not the group) so it hot-reloads
// its config in place. This is the M1.8 reload path on Unix.
func signalReload(cmd *exec.Cmd) error {
	return syscall.Kill(cmd.Process.Pid, syscall.SIGHUP)
}

// processAlive reports whether pid names a live process. Signal 0 probes liveness
// without delivering a signal: nil => alive, ESRCH => gone, EPERM => alive but not
// ours (still "alive"). Used by ADOPT mode (ADR 0003 Phase 3) to monitor a nebula the
// supervisor did NOT fork and therefore cannot Wait() on — it polls instead.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

// terminatePID / forceKillPID / signalReloadPID act on a single ADOPTED pid (not a
// process group, since we didn't create its group). Signal-specific helpers so no
// syscall.Signal type has to cross the platform boundary (Windows lacks SIGHUP).
func terminatePID(pid int) error    { return syscall.Kill(pid, syscall.SIGTERM) }
func forceKillPID(pid int) error    { return syscall.Kill(pid, syscall.SIGKILL) }
func signalReloadPID(pid int) error { return syscall.Kill(pid, syscall.SIGHUP) }

// adoptSupported reports whether PID adoption (re-exec self-update, ADR 0003 Phase 3)
// works on this platform. Unix: yes (signal-0 liveness + kill-by-PID + syscall.Exec).
func adoptSupported() bool { return true }
