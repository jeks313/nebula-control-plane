//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// findSuperviseProcOS walks /proc and returns the first running `pilot supervise` process
// whose argv targets base (matched by the pure parseSuperviseArgs), along with its pid and
// `-core <url>` value. Best-effort: an unreadable /proc or cmdline is simply skipped, so
// `pilot info` never fails on the process scan. The `-dir` server layout is linux-only,
// so this is the only platform with a real implementation; superviseproc_other.go stubs
// the rest.
func findSuperviseProcOS(base string) superviseProc {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return superviseProc{}
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a /proc/<pid> dir
		}
		argv := readProcCmdline(pid)
		if len(argv) == 0 {
			continue
		}
		if match, core := parseSuperviseArgs(argv, base); match {
			return superviseProc{Running: true, PID: pid, Core: core}
		}
	}
	return superviseProc{}
}

// readProcCmdline reads /proc/<pid>/cmdline (NUL-separated argv) into a string slice.
// Returns nil on any read error (the process may have exited mid-scan) or for kernel
// threads (empty cmdline).
func readProcCmdline(pid int) []string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil || len(b) == 0 {
		return nil
	}
	parts := strings.Split(string(b), "\x00")
	// /proc/<pid>/cmdline typically ends in a trailing NUL, yielding an empty final field.
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
