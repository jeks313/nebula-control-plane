//go:build windows

package supervisor

import "os/exec"

// Windows has no process groups / SIGTERM in the POSIX sense. This is a
// best-effort stub; proper Windows job-object handling lands with M1.10.
func setSysProcAttr(cmd *exec.Cmd) {}

func terminate(cmd *exec.Cmd) error { return cmd.Process.Kill() }

func forceKill(cmd *exec.Cmd) error { return cmd.Process.Kill() }
