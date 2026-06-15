package heartbeat

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/paths"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

func TestProcessKnownCommands(t *testing.T) {
	var renews, restarts, applied int
	h := Handlers{
		Renew:       func(context.Context) error { renews++; return nil },
		Restart:     func() error { restarts++; return nil },
		ApplyBundle: func(_ context.Context, v int) error { applied = v; return nil },
	}
	resp := wire.HeartbeatResponse{Commands: []wire.Command{
		{Type: wire.CmdRenew}, {Type: wire.CmdRestart}, {Type: wire.CmdApplyBundle, BundleVersion: 7},
	}}
	if err := Process(context.Background(), resp, h); err != nil {
		t.Fatal(err)
	}
	if renews != 1 || restarts != 1 || applied != 7 {
		t.Fatalf("dispatch wrong: renews=%d restarts=%d applied=%d", renews, restarts, applied)
	}
}

// TestProcessRejectsUnknown is the M4.6 acceptance: an unknown command type is
// refused and never executed.
func TestProcessRejectsUnknown(t *testing.T) {
	var ran int
	h := Handlers{Renew: func(context.Context) error { ran++; return nil }}
	resp := wire.HeartbeatResponse{Commands: []wire.Command{{Type: "exec:rm -rf /"}}}
	if err := Process(context.Background(), resp, h); err == nil {
		t.Fatal("unknown command must be rejected")
	}
	if ran != 0 {
		t.Fatal("no handler should run for an unknown command")
	}
}

// TestReporterToleratesCoreDown is part of the M4.9 P3 chaos proof: when Core is
// unreachable, heartbeats fail silently and NO command (renew/restart) is fired —
// a control-plane outage never triggers a data-plane action.
func TestReporterToleratesCoreDown(t *testing.T) {
	var renews, restarts int32
	rep := New(Config{
		CoreURL:  "http://127.0.0.1:1", // nothing listening -> connection refused
		Layout:   paths.New(t.TempDir()),
		Interval: 10 * time.Millisecond,
		Handlers: Handlers{
			Renew:   func(context.Context) error { atomic.AddInt32(&renews, 1); return nil },
			Restart: func() error { atomic.AddInt32(&restarts, 1); return nil },
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	_ = rep.Run(ctx) // must not panic, must not fire commands

	if atomic.LoadInt32(&renews) != 0 || atomic.LoadInt32(&restarts) != 0 {
		t.Fatalf("a down Core must not trigger commands: renews=%d restarts=%d", renews, restarts)
	}
}

// TestReporterReportsRunningNebula is the ADR 0003 Phase 1c convergence signal: the
// reporter sends NebulaSHAFn as nebula_sha256 (the convergence key Harbor maps to a
// generation) and NebulaVersionFn as nebula_version (fleet display).
func TestReporterReportsRunningNebula(t *testing.T) {
	var gotVer, gotSHA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req wire.HeartbeatRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		gotVer, gotSHA = req.NebulaVersion, req.NebulaSHA256
		_ = json.NewEncoder(w).Encode(wire.HeartbeatResponse{ProtocolVersion: wire.ProtocolVersion})
	}))
	defer srv.Close()

	rep := New(Config{
		CoreURL:         srv.URL,
		Layout:          paths.New(t.TempDir()),
		NebulaVersionFn: func() string { return "1.10.3" },
		NebulaSHAFn:     func() string { return "abc123" },
	})
	rep.beat(context.Background())
	if gotVer != "1.10.3" || gotSHA != "abc123" {
		t.Fatalf("reported version=%q sha=%q, want 1.10.3 / abc123", gotVer, gotSHA)
	}
}

func TestProcessStopsAtUnknown(t *testing.T) {
	var renews int
	h := Handlers{Renew: func(context.Context) error { renews++; return nil }}
	resp := wire.HeartbeatResponse{Commands: []wire.Command{
		{Type: wire.CmdRenew}, {Type: "bogus"},
	}}
	if err := Process(context.Background(), resp, h); err == nil {
		t.Fatal("must reject on the unknown command")
	}
	if renews != 1 {
		t.Fatalf("the known command before it should have run once, got %d", renews)
	}
}
