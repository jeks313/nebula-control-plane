package renew

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"math"
	mrand "math/rand"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/enrollclient"
	"github.com/jeks313/nebula-control-plane/internal/paths"
	"github.com/jeks313/nebula-control-plane/internal/signer"
)

// TestScheduleSpread is the M4.4 acceptance for jitter: 1,000 hosts with the
// SAME validity window pick renewal times spread across the jitter band (not a
// spike), centered near ⅔ life.
func TestScheduleSpread(t *testing.T) {
	nb := time.Now()
	na := nb.Add(30 * 24 * time.Hour) // 30-day cert
	rnd := mrand.New(mrand.NewSource(1))

	lo, hi, sum := math.Inf(1), math.Inf(-1), 0.0
	const n = 1000
	for i := 0; i < n; i++ {
		at := Schedule(nb, na, DefaultFrac, DefaultJitterFrac, rnd)
		f := at.Sub(nb).Seconds() / na.Sub(nb).Seconds() // fraction of life
		lo, hi, sum = math.Min(lo, f), math.Max(hi, f), sum+f
		band := DefaultJitterFrac/2 + 1e-6
		if f < DefaultFrac-band || f > DefaultFrac+band {
			t.Fatalf("renewal fraction %.3f outside jitter band around %.3f", f, DefaultFrac)
		}
	}
	mean := sum / n
	if mean < DefaultFrac-0.03 || mean > DefaultFrac+0.03 {
		t.Fatalf("mean renewal fraction %.3f not ~%.3f", mean, DefaultFrac)
	}
	if hi-lo < 0.10 {
		t.Fatalf("renewals not spread: span %.3f (want a wide jitter band, not a spike)", hi-lo)
	}
}

// writeCert issues a real cert with the given window and writes it as host.crt.
func writeCert(t *testing.T, layout paths.Layout, nb, na time.Time) {
	t.Helper()
	caB, _ := signer.NewSoftwareBackend()
	pool := netip.MustParsePrefix("100.64.0.0/16")
	_, caPEM, err := signer.SelfSignCA(caB, signer.CATemplate{
		Name: "ca", Networks: []netip.Prefix{pool},
		NotBefore: nb.Add(-time.Hour), NotAfter: na.Add(10 * 365 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	sg, err := signer.New(signer.Config{
		CACertPEM: caPEM, Backend: caB,
		Policy: signer.Policy{AllowedNetwork: pool, MaxLifetime: 100 * 365 * 24 * time.Hour},
		Audit:  func(context.Context, string, string, string, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	hk, _ := ecdh.P256().GenerateKey(rand.Reader)
	_, certPEM, err := sg.Issue(context.Background(), "test", signer.Template{
		Name: "h", Networks: []netip.Prefix{netip.MustParsePrefix("100.64.0.5/16")},
		NotBefore: nb, NotAfter: na, PublicKey: hk.PublicKey().Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.HostCert(), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestManagerRenewsOnSchedule: a cert already past ⅔ life triggers an immediate
// renewal + reload.
func TestManagerRenewsOnSchedule(t *testing.T) {
	layout := paths.New(t.TempDir())
	if err := layout.Ensure(); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	// ⅔ of life is ~40min in the past — comfortably past even with +jitter, so
	// the manager renews immediately.
	writeCert(t, layout, now.Add(-3*time.Hour), now.Add(30*time.Minute))

	renewed := make(chan struct{}, 1)
	var reloads int32
	mgr := New(Config{
		Layout:     layout,
		ReArmDelay: 20 * time.Millisecond,
		RetryDelay: 20 * time.Millisecond,
		Renew: func(context.Context) (enrollclient.Result, error) {
			select {
			case renewed <- struct{}{}:
			default:
			}
			return enrollclient.Result{Status: "issued", OverlayIP: "100.64.0.5"}, nil
		},
		Reload: func() error { atomic.AddInt32(&reloads, 1); return nil },
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = mgr.Run(ctx); close(done) }()

	select {
	case <-renewed:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("expected a renewal but none happened")
	}
	cancel()
	<-done
	if atomic.LoadInt32(&reloads) < 1 {
		t.Fatal("reload was not triggered after renewal")
	}
}

// TestRenewFailureNeverReloads is part of the M4.9 P3 chaos proof: when Harbor is
// unreachable, renewal fails and is retried, but the data plane is NEVER touched
// (no reload/restart) — a control-plane outage cannot perturb the data plane.
func TestRenewFailureNeverReloads(t *testing.T) {
	layout := paths.New(t.TempDir())
	if err := layout.Ensure(); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	writeCert(t, layout, now.Add(-3*time.Hour), now.Add(30*time.Minute)) // past ⅔ -> wants to renew

	var renews, reloads int32
	mgr := New(Config{
		Layout:     layout,
		RetryDelay: 10 * time.Millisecond,
		ReArmDelay: 10 * time.Millisecond,
		Renew: func(context.Context) (enrollclient.Result, error) {
			atomic.AddInt32(&renews, 1)
			return enrollclient.Result{}, errors.New("core unreachable")
		},
		Reload: func() error { atomic.AddInt32(&reloads, 1); return nil },
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = mgr.Run(ctx)

	if atomic.LoadInt32(&renews) < 2 {
		t.Fatalf("renew should have been retried, got %d attempts", renews)
	}
	if atomic.LoadInt32(&reloads) != 0 {
		t.Fatal("a failed renewal must NEVER reload — the data plane stays untouched")
	}
}
