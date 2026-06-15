//go:build windows

package supervisor

import (
	"errors"
	"os/exec"
)

// Windows has no process groups / SIGTERM in the POSIX sense. This is a
// best-effort stub; proper Windows job-object handling lands with M1.10.
func setSysProcAttr(cmd *exec.Cmd) {}

func terminate(cmd *exec.Cmd) error { return cmd.Process.Kill() }

func forceKill(cmd *exec.Cmd) error { return cmd.Process.Kill() }

// signalReload is unsupported on Windows (no SIGHUP). The supervisor surfaces
// this as ErrReloadUnsupported so the caller falls back to a supervised restart
// (the M1.8 Windows path).
func signalReload(cmd *exec.Cmd) error { return ErrReloadUnsupported }

// PID adoption + re-exec self-update (ADR 0003 Phase 3) are Unix-only: Windows has no
// signal-0 liveness probe or syscall.Exec, so pilot self-update there degrades to an
// SCM-driven restart. These stubs keep the shared supervisor code compiling.
var errAdoptUnsupported = errors.New("supervisor: PID adoption unsupported on windows")

func processAlive(int) bool      { return false }
func terminatePID(int) error     { return errAdoptUnsupported }
func forceKillPID(int) error     { return errAdoptUnsupported }
func signalReloadPID(int) error  { return errAdoptUnsupported }
func adoptSupported() bool       { return false }
