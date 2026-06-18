//go:build !linux

package main

// findSuperviseProcOS is a no-op on non-linux platforms: the single-mesh `-dir` server
// layout (a `pilot supervise -dir /etc/nebula` deployment under systemd) is linux-only, so
// there's no portable process walk to do here. Returning a zero superviseProc keeps
// `pilot info` cross-compiling for darwin/windows while leaving the linux path
// (superviseproc_linux.go) as the only real implementation.
func findSuperviseProcOS(base string) superviseProc {
	return superviseProc{}
}
