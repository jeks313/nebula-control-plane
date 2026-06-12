package heartbeat

import (
	"context"
	"testing"

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
