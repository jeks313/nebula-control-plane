package main

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// TestParseSuperviseArgs covers the PURE argv matcher: it matches a `pilot supervise`
// invocation on either `-dir <base>` or `-config <base>/config.yml`, extracts the
// `-core <url>` value, accepts the `-flag=value` form, and does NOT match a different dir
// or a non-supervise argv.
func TestParseSuperviseArgs(t *testing.T) {
	const base = "/etc/nebula"

	cases := []struct {
		name      string
		argv      []string
		wantMatch bool
		wantCore  string
	}{
		{
			name:      "match on -dir, extract -core",
			argv:      []string{"pilot", "supervise", "-dir", "/etc/nebula", "-config", "/etc/nebula/config.yml", "-core", "https://poc-harbor.mesh.failsafe.net:8444", "-nebula", "/usr/local/bin/nebula"},
			wantMatch: true,
			wantCore:  "https://poc-harbor.mesh.failsafe.net:8444",
		},
		{
			name:      "match on -config <base>/config.yml even without -dir",
			argv:      []string{"pilot", "supervise", "-config", "/etc/nebula/config.yml", "-core", "https://h:8444"},
			wantMatch: true,
			wantCore:  "https://h:8444",
		},
		{
			name:      "flag=value form",
			argv:      []string{"pilot", "supervise", "-dir=/etc/nebula", "-core=https://h:8444"},
			wantMatch: true,
			wantCore:  "https://h:8444",
		},
		{
			name:      "double-dash form",
			argv:      []string{"pilot", "supervise", "--dir", "/etc/nebula", "--core", "https://h:8444"},
			wantMatch: true,
			wantCore:  "https://h:8444",
		},
		{
			name:      "trailing slash on -dir still matches",
			argv:      []string{"pilot", "supervise", "-dir", "/etc/nebula/", "-core", "https://h:8444"},
			wantMatch: true,
			wantCore:  "https://h:8444",
		},
		{
			name:      "match with no -core yields empty core",
			argv:      []string{"pilot", "supervise", "-dir", "/etc/nebula"},
			wantMatch: true,
			wantCore:  "",
		},
		{
			name:      "different dir does not match",
			argv:      []string{"pilot", "supervise", "-dir", "/var/lib/pilot/other", "-config", "/var/lib/pilot/other/config.yml", "-core", "https://h:8444"},
			wantMatch: false,
			wantCore:  "",
		},
		{
			name:      "no supervise subcommand does not match",
			argv:      []string{"pilot", "info", "-dir", "/etc/nebula"},
			wantMatch: false,
			wantCore:  "",
		},
		{
			name:      "empty argv does not match",
			argv:      nil,
			wantMatch: false,
			wantCore:  "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			match, core := parseSuperviseArgs(c.argv, base)
			if match != c.wantMatch {
				t.Fatalf("match = %v, want %v (argv %v)", match, c.wantMatch, c.argv)
			}
			if core != c.wantCore {
				t.Fatalf("core = %q, want %q", core, c.wantCore)
			}
		})
	}
}

// TestParseSuperviseArgsEmptyBase: a "" base never matches (guards the auto-detect path
// when defaultMeshDir is somehow blank).
func TestParseSuperviseArgsEmptyBase(t *testing.T) {
	if match, _ := parseSuperviseArgs([]string{"pilot", "supervise", "-dir", "/etc/nebula"}, ""); match {
		t.Fatal("empty base must not match")
	}
}

// TestGatherMeshAtViaDirRunning: a `-dir` mesh whose supervise process is found
// running+with a -core yields a non-"inactive" service line (active (supervise, pid N))
// and a populated CoreURL adopted from the process, so the Harbor probe then runs. Uses
// the findSuperviseProc seam to inject the result without a real /proc.
func TestGatherMeshAtViaDirRunning(t *testing.T) {
	dir := t.TempDir()
	writeMeshDirState(t, dir, netip.MustParsePrefix("10.44.0.4/16"))

	old := findSuperviseProc
	findSuperviseProc = func(base string) superviseProc {
		if base != dir {
			t.Fatalf("findSuperviseProc called with %q, want %q", base, dir)
		}
		// No real Harbor at this URL — probeHarbor will report unreachable, which is fine;
		// the point is that CoreURL got populated so the probe runs at all.
		return superviseProc{Running: true, PID: 4242, Core: "http://127.0.0.1:1"}
	}
	t.Cleanup(func() { findSuperviseProc = old })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mi := gatherMeshAt(ctx, "nebula", dir, true)

	if strings.Contains(mi.Service, "inactive") || strings.Contains(mi.Service, "unknown") {
		t.Fatalf("viaDir running service should not be inactive/unknown: %q", mi.Service)
	}
	if !strings.Contains(mi.Service, "supervise") || !strings.Contains(mi.Service, "4242") {
		t.Fatalf("service line = %q, want active (supervise, pid 4242)", mi.Service)
	}
	if mi.CoreURL != "http://127.0.0.1:1" {
		t.Fatalf("CoreURL = %q, want the supervise -core value adopted", mi.CoreURL)
	}
	if mi.Harbor == nil {
		t.Fatalf("Harbor probe should run once CoreURL is populated; got nil")
	}
}

// TestGatherMeshAtViaDirNotRunning: a `-dir` mesh with no supervise process reports a
// "not running" service (NOT the misleading multi-mesh inactive/unknown) and, with no
// core URL discoverable, runs no Harbor probe.
func TestGatherMeshAtViaDirNotRunning(t *testing.T) {
	dir := t.TempDir()
	writeMeshDirState(t, dir, netip.MustParsePrefix("10.44.0.4/16"))

	old := findSuperviseProc
	findSuperviseProc = func(string) superviseProc { return superviseProc{} }
	t.Cleanup(func() { findSuperviseProc = old })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mi := gatherMeshAt(ctx, "nebula", dir, true)

	if !strings.Contains(mi.Service, "not running") {
		t.Fatalf("service line = %q, want a 'not running' message", mi.Service)
	}
	if mi.CoreURL != "" {
		t.Fatalf("no core URL should be discoverable, got %q", mi.CoreURL)
	}
	if mi.Harbor != nil {
		t.Fatalf("no Harbor probe without a core URL; got %+v", mi.Harbor)
	}
}
