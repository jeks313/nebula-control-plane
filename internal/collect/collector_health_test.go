package collect

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeHealthSink struct{ calls []healthCall }

type healthCall struct {
	gateway string
	ok      bool
	fails   int
}

func (f *fakeHealthSink) Record(_ context.Context, gw string, ok bool, _ string, fails int, _ time.Time) error {
	f.calls = append(f.calls, healthCall{gw, ok, fails})
	return nil
}

// TestRecordHealthThrottleAndTransitions pins the load-bearing recorder state machine: the first
// cycle always writes, steady state throttles to one write per healthHeartbeat, an ok/fail
// transition forces an immediate write bypassing the throttle, and the persisted count is the
// absolute consecutive-failure count.
func TestRecordHealthThrottleAndTransitions(t *testing.T) {
	sink := &fakeHealthSink{}
	c := New(Config{Health: sink})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	boom := errors.New("claim: timeout")
	ctx := context.Background()

	// (a) first-ever cycle (a failure) writes immediately, count=1.
	c.recordHealth(ctx, "gw", boom)
	if len(sink.calls) != 1 || sink.calls[0].ok || sink.calls[0].fails != 1 {
		t.Fatalf("first fail: calls=%+v, want one {ok:false fails:1}", sink.calls)
	}

	// (b) still failing within the heartbeat -> throttled, no write; count climbs in memory.
	now = now.Add(5 * time.Second)
	c.recordHealth(ctx, "gw", boom)
	if len(sink.calls) != 1 {
		t.Fatalf("throttled fail wrote: calls=%+v", sink.calls)
	}

	// (c) recovery is a transition -> immediate write, count reset to 0.
	now = now.Add(1 * time.Second)
	c.recordHealth(ctx, "gw", nil)
	if len(sink.calls) != 2 || !sink.calls[1].ok || sink.calls[1].fails != 0 {
		t.Fatalf("recovery: calls=%+v, want a {ok:true fails:0} write", sink.calls)
	}

	// (d) steady success within the heartbeat -> throttled, no write.
	now = now.Add(5 * time.Second)
	c.recordHealth(ctx, "gw", nil)
	if len(sink.calls) != 2 {
		t.Fatalf("steady success wrote: calls=%+v", sink.calls)
	}

	// (e) success past the heartbeat since the last write -> heartbeat write.
	now = now.Add(healthHeartbeat + time.Second)
	c.recordHealth(ctx, "gw", nil)
	if len(sink.calls) != 3 || !sink.calls[2].ok {
		t.Fatalf("heartbeat: calls=%+v, want a 3rd ok write", sink.calls)
	}

	// (f) failure after success is a transition -> immediate write, count back to 1.
	now = now.Add(1 * time.Second)
	c.recordHealth(ctx, "gw", boom)
	if len(sink.calls) != 4 || sink.calls[3].ok || sink.calls[3].fails != 1 {
		t.Fatalf("fail-after-success: calls=%+v, want {ok:false fails:1}", sink.calls)
	}
}

// TestRecordHealthNilSinkNoPanic: recording is a no-op when no sink is configured.
func TestRecordHealthNilSinkNoPanic(t *testing.T) {
	c := New(Config{})
	c.recordHealth(context.Background(), "gw", errors.New("x")) // must not panic
}
