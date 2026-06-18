package main

import (
	"path/filepath"
	"strings"
)

// superviseproc.go introspects the running `pilot supervise` process for a single-mesh
// `-dir` deployment (e.g. `pilot supervise -dir /etc/nebula -core <url> ...` run as the
// ncp-nebula service). The multi-mesh layout uses per-mesh OS services that
// pilotservice.Status can query by label; a `-dir` deployment does NOT, so for it we
// learn liveness (and the core URL, which lives in the supervise `-core` flag rather than
// config.yml) by walking processes and matching argv. The OS process walk is split out
// per-platform (superviseproc_linux.go reads /proc; superviseproc_other.go is a no-op
// stub so `pilot info` still cross-compiles for darwin/windows — the `-dir` server layout
// is linux anyway). The argv parsing is a PURE function (parseSuperviseArgs) so it's
// unit-testable without a real process table.

// superviseProc is the result of looking for the running supervise process that targets a
// given mesh base dir. Running is false (and PID/Core empty) when none is found.
type superviseProc struct {
	Running bool
	PID     int
	Core    string // the supervise `-core <url>` value, if present in argv
}

// findSuperviseProc is the seam the rest of pilot info goes through to locate the running
// `pilot supervise` process for base. The default implementation is the per-platform OS
// process walk (findSuperviseProcOS); tests override it to inject a result without a real
// /proc. It returns a zero superviseProc (Running:false) when no match is found or the
// platform has no implementation.
var findSuperviseProc = func(base string) superviseProc {
	return findSuperviseProcOS(base)
}

// parseSuperviseArgs decides whether a process's argv is a `pilot supervise` invocation
// targeting the mesh state dir base, and if so extracts its `-core <url>` value. It is the
// PURE core of the introspection: no syscalls, just argv -> (match, core), so it can be
// unit-tested directly.
//
// A match requires the `supervise` subcommand AND the argv to target base via either
//   - `-dir <base>`              (the systemd/launchd unit form), or
//   - `-config <base>/config.yml` (the conventional config path under base).
//
// Both single- and double-dash forms and the `-flag=value` form are accepted, since Go's
// flag package treats them identically and the live unit uses single-dash `-dir`.
// Paths are compared after filepath.Clean so trailing slashes don't defeat the match.
func parseSuperviseArgs(argv []string, base string) (match bool, core string) {
	if len(argv) == 0 || base == "" {
		return false, ""
	}

	wantBase := filepath.Clean(base)
	wantConfig := filepath.Clean(filepath.Join(base, "config.yml"))

	var (
		sawSupervise bool
		sawDir       bool
		sawConfig    bool
	)

	for i := 0; i < len(argv); i++ {
		tok := argv[i]
		if tok == "supervise" {
			sawSupervise = true
			continue
		}

		name, val, hasVal := splitFlag(tok)
		// Resolve a "-flag value" pair (value is the next token) when the token didn't
		// already carry "=value".
		next := func() (string, bool) {
			if hasVal {
				return val, true
			}
			if i+1 < len(argv) {
				i++
				return argv[i], true
			}
			return "", false
		}

		switch name {
		case "dir":
			if v, ok := next(); ok && filepath.Clean(v) == wantBase {
				sawDir = true
			}
		case "config":
			if v, ok := next(); ok && filepath.Clean(v) == wantConfig {
				sawConfig = true
			}
		case "core":
			if v, ok := next(); ok {
				core = v
			}
		}
	}

	if !sawSupervise || !(sawDir || sawConfig) {
		return false, ""
	}
	return true, core
}

// splitFlag normalizes one argv token into a flag name (no leading dashes) and, when the
// `-flag=value` form is used, its inline value. A non-flag token (no leading dash) yields
// an empty name, so the caller simply ignores it.
func splitFlag(tok string) (name, val string, hasVal bool) {
	if !strings.HasPrefix(tok, "-") {
		return "", "", false
	}
	tok = strings.TrimLeft(tok, "-")
	if eq := strings.IndexByte(tok, '='); eq >= 0 {
		return tok[:eq], tok[eq+1:], true
	}
	return tok, "", false
}
