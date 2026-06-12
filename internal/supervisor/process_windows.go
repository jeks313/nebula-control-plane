//go:build windows

package supervisor

import "os/exec"

// Windows has no process groups / SIGTERM in the POSIX sense. This is a
// best-effort stub; proper Windows job-object handling lands with M1.10.
func setSysProcAttr(cmd *exec.Cmd) {}

func terminate(cmd *exec.Cmd) error { return cmd.Process.Kill() }

func forceKill(cmd *exec.Cmd) error { return cmd.Process.Kill() }

// signalReload is unsupported on Windows (no SIGHUP). The supervisor surfaces
// this as ErrReloadUnsupported so the caller falls back to a supervised restart
// (the M1.8 Windows path).
func signalReload(cmd *exec.Cmd) error { return ErrReloadUnsupported }
