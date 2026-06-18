package ipam

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// staticLister is a fake NetblockLister (no DB / no netblock import) so the collector can
// be unit-tested in-package without the ipam<-netblock import cycle.
type staticLister []NamedCIDR

func (s staticLister) NetblockCIDRs(_ context.Context) ([]NamedCIDR, error) {
	return []NamedCIDR(s), nil
}

// seedHeartbeat upserts a heartbeat row keyed by overlay_ip.
func seedHeartbeat(t *testing.T, a *Allocator, ip netip.Addr, lastSeen time.Time) {
	t.Helper()
	if err := a.db.Exec(`INSERT INTO heartbeats (overlay_ip, device_name, last_seen) VALUES (?,?,?)`,
		ip.String(), "dev", lastSeen.UnixNano()).Error; err != nil {
		t.Fatal(err)
	}
}

// gauge reads one gauge series off a gatherer, matching by name + labels (0 if absent).
func gauge(t *testing.T, g prometheus.Gatherer, name string, want map[string]string) float64 {
	t.Helper()
	mfs, err := g.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			match := true
			for k, v := range want {
				if labels[k] != v {
					match = false
					break
				}
			}
			if match && m.Gauge != nil {
				return m.GetGauge().GetValue()
			}
		}
	}
	return 0
}

// TestNetblockCollectorUsedCountsOnlyFresh: with two allocations in a block — one with a
// fresh heartbeat, one stale — the collector emits used=1, allocated=2, capacity=255
// (D23). Registered on a private registry + gathered from it, exactly as /metrics would.
func TestNetblockCollectorUsedCountsOnlyFresh(t *testing.T) {
	a := newAllocator(t, Pool{Prefix: netip.MustParsePrefix("10.44.20.0/24")})
	ctx := context.Background()
	fresh := netip.MustParseAddr("10.44.20.1")
	stale := netip.MustParseAddr("10.44.20.2")
	if err := a.AllocateSpecific(ctx, "fresh", fresh, "token"); err != nil {
		t.Fatal(err)
	}
	if err := a.AllocateSpecific(ctx, "stale", stale, "token"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	seedHeartbeat(t, a, fresh, now)                      // within the 5m window → used
	seedHeartbeat(t, a, stale, now.Add(-10*time.Minute)) // outside the window → not used

	lister := staticLister{{Name: "office", CIDR: netip.MustParsePrefix("10.44.20.0/24")}}
	c := NewNetblockCollector(a.db, lister, 5*time.Minute)

	reg := prometheus.NewRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("register collector: %v", err)
	}

	lbl := map[string]string{"netblock": "office"}
	if got := gauge(t, reg, "ncp_ipam_netblock_used", lbl); got != 1 {
		t.Errorf("ncp_ipam_netblock_used = %v, want 1 (only the fresh heartbeat)", got)
	}
	if got := gauge(t, reg, "ncp_ipam_netblock_allocated", lbl); got != 2 {
		t.Errorf("ncp_ipam_netblock_allocated = %v, want 2", got)
	}
	if got := gauge(t, reg, "ncp_ipam_netblock_capacity", lbl); got != 255 {
		t.Errorf("ncp_ipam_netblock_capacity = %v, want 255 (/24 minus the network addr)", got)
	}
}

// TestNetblockCollectorUsedFreshnessBoundary pins the inequality + units at the exact
// edge of the stale window with an injected clock: a heartbeat at last_seen == now -
// StaleAfter counts as used (fresh, the cutoff is `last_seen >= now - staleAfter`), and
// one a single nanosecond older does NOT. The ±1ns gap (vs the 5m/10m margin in the
// fresh-vs-stale test) is what catches a flipped `>`/`>=` or an ns/s units regression.
func TestNetblockCollectorUsedFreshnessBoundary(t *testing.T) {
	a := newAllocator(t, Pool{Prefix: netip.MustParsePrefix("10.44.20.0/24")})
	ctx := context.Background()
	const window = 5 * time.Minute
	// Fixed now so the seeded last_seen values sit at a deterministic offset from cutoff.
	now := time.Unix(1_700_000_000, 0).UTC()

	atEdge := netip.MustParseAddr("10.44.20.1")   // last_seen == now - window  → fresh (>=)
	justOver := netip.MustParseAddr("10.44.20.2") // last_seen == now - window - 1ns → stale
	if err := a.AllocateSpecific(ctx, "at-edge", atEdge, "token"); err != nil {
		t.Fatal(err)
	}
	if err := a.AllocateSpecific(ctx, "just-over", justOver, "token"); err != nil {
		t.Fatal(err)
	}
	seedHeartbeat(t, a, atEdge, now.Add(-window))                         // exactly at the cutoff
	seedHeartbeat(t, a, justOver, now.Add(-window).Add(-time.Nanosecond)) // 1ns past the cutoff

	lister := staticLister{{Name: "office", CIDR: netip.MustParsePrefix("10.44.20.0/24")}}
	c := NewNetblockCollector(a.db, lister, window)
	c.now = func() time.Time { return now } // inject the fixed clock

	reg := prometheus.NewRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("register collector: %v", err)
	}

	lbl := map[string]string{"netblock": "office"}
	if got := gauge(t, reg, "ncp_ipam_netblock_used", lbl); got != 1 {
		t.Errorf("ncp_ipam_netblock_used = %v, want 1 (the edge heartbeat is fresh via >=; the 1ns-older one is stale)", got)
	}
	if got := gauge(t, reg, "ncp_ipam_netblock_allocated", lbl); got != 2 {
		t.Errorf("ncp_ipam_netblock_allocated = %v, want 2", got)
	}
}

// TestNetblockCollectorNilSafe: a collector with a nil store/lister emits nothing and
// does not panic on Collect (Describe/Collect must be robust to an unwired collector).
func TestNetblockCollectorNilSafe(t *testing.T) {
	c := NewNetblockCollector(nil, nil, 0)
	ch := make(chan prometheus.Metric, 8)
	c.Collect(ch) // must not panic
	close(ch)
	if n := len(ch); n != 0 {
		t.Fatalf("nil collector emitted %d metrics, want 0", n)
	}
	// A nil *NetblockCollector receiver must also not panic.
	var nilC *NetblockCollector
	ch2 := make(chan prometheus.Metric, 1)
	nilC.Collect(ch2)
	close(ch2)
}

// TestRegisterNetblockCollectorDedup: registering twice on the SAME registry must not
// panic — the once-guard makes the second call a no-op (a process that already allocates
// and re-registers stays safe).
func TestRegisterNetblockCollectorDedup(t *testing.T) {
	// Reset the package once-guard so this test is independent of registration order.
	collectorRegMu.Lock()
	collectorRegDone = false
	collectorRegMu.Unlock()
	t.Cleanup(func() {
		collectorRegMu.Lock()
		collectorRegDone = false
		collectorRegMu.Unlock()
	})

	reg := prometheus.NewRegistry()
	c := NewNetblockCollector(newStore(t).DB, staticLister{}, 0)
	if err := registerNetblockCollectorOn(reg, c); err != nil {
		t.Fatalf("first register: %v", err)
	}
	// Second call (same guard) is a no-op — must not panic or error.
	if err := registerNetblockCollectorOn(reg, c); err != nil {
		t.Fatalf("second register should be a no-op, got: %v", err)
	}
}
