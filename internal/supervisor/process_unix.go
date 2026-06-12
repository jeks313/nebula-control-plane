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
