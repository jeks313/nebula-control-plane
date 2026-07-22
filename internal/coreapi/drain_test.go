package coreapi

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/slackhq/nebula/cert"
)

// newSignerOn builds a real software-backed signer over a fresh self-signed CA and returns it plus
// the fingerprint it currently signs with (used to satisfy the M8.3c "local signer has cut over"
// gate). Each call mints a distinct CA, so two signers never share a fingerprint.
func newSignerOn(t *testing.T) (*signer.Signer, string) {
	t.Helper()
	b, err := signer.NewSoftwareBackend()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := b.PublicKey()
	caC, err := signer.SignTBS(b, &cert.TBSCertificate{
		Version: cert.Version2, Name: "ca", IsCA: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		PublicKey: pub, Curve: cert.Curve_P256,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pem, _ := caC.MarshalPEM()
	sg, err := signer.New(signer.Config{CACertPEM: pem, Backend: b, Audit: func(context.Context, string, string, string, string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	return sg, sg.CurrentFingerprint()
}

// TestInDrainWave: the M8.3c wave gate opens buckets linearly with elapsed time — nothing before
// start, a growing fraction across the window, and every straggler once the window has elapsed.
func TestInDrainWave(t *testing.T) {
	const window = int64(time.Hour)
	start := int64(1_000_000_000)

	// Disabled / degenerate inputs never admit.
	if inDrainWave("100.64.0.5", 0, window, start) {
		t.Fatal("startedNS=0 must not admit")
	}
	if inDrainWave("100.64.0.5", start, 0, start+window) {
		t.Fatal("windowNS<=0 must not admit")
	}
	// Before start (clock skew): not admitted.
	if inDrainWave("100.64.0.5", start, window, start-1) {
		t.Fatal("elapsed<0 must not admit")
	}
	// After the window: every host is admitted (the drain must finish).
	for i := 0; i < 200; i++ {
		ip := fmt.Sprintf("100.64.1.%d", i)
		if !inDrainWave(ip, start, window, start+window) {
			t.Fatalf("%s not admitted at window end", ip)
		}
	}

	// The admitted fraction grows monotonically with elapsed time and spreads across the window
	// (not a storm at t0). Count over a fixed host set at 0/25/50/75/100%.
	const n = 500
	frac := func(pct int64) int {
		now := start + window*pct/100
		c := 0
		for i := 0; i < n; i++ {
			if inDrainWave(fmt.Sprintf("100.64.9.%d", i), start, window, now) {
				c++
			}
		}
		return c
	}
	a0, a25, a50, a75, a100 := frac(0), frac(25), frac(50), frac(75), frac(100)
	if !(a0 <= a25 && a25 <= a50 && a50 <= a75 && a75 <= a100) {
		t.Fatalf("admission not monotonic: %d,%d,%d,%d,%d", a0, a25, a50, a75, a100)
	}
	if a100 != n {
		t.Fatalf("at window end admitted %d/%d, want all", a100, n)
	}
	if a0 >= n {
		t.Fatalf("at t0 admitted %d/%d — should be a small first wave, not a storm", a0, n)
	}
	// A host admitted at 25%% stays admitted at 75%% (buckets only open, never close).
	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("100.64.9.%d", i)
		if inDrainWave(ip, start, window, start+window*25/100) && !inDrainWave(ip, start, window, start+window*75/100) {
			t.Fatalf("%s admitted at 25%% but not at 75%% — waves must not close", ip)
		}
	}
}

// fakeDrain is a canned coreapi.CADrainSource for the straggler-gating test.
type fakeDrain struct {
	active          string
	started, window int64
	accel           bool
}

func (f fakeDrain) ActiveFingerprint(context.Context) (string, error) { return f.active, nil }
func (f fakeDrain) DrainWave(context.Context, string) (int64, int64, bool, error) {
	return f.started, f.window, f.accel, nil
}

// TestForceRenewStragglerGating: forceRenewStraggler force-renews ONLY a host still chaining to a
// non-active CA that is under an active accelerated drain and whose wave has opened. A host already
// on the active CA, an empty CA fingerprint, a disabled source, or a non-accelerated CA all decline.
func TestForceRenewStragglerGating(t *testing.T) {
	ctx := context.Background()
	now := int64(1_700_000_000) * int64(time.Second) // a realistic unix-ns clock (so now-1h stays positive)
	clock := func() time.Time { return time.Unix(0, now) }

	// This process's signer HAS cut over to the active CA; the drain's active fp is that signer's.
	sg, activeFp := newSignerOn(t)
	// started far enough back that the window is complete -> every straggler is in-wave, isolating
	// the CADrain GATING logic (the wave math is covered by TestInDrainWave).
	drained := fakeDrain{active: activeFp, started: now - int64(time.Hour), window: int64(time.Minute), accel: true}

	srv := func(d CADrainSource, sig *signer.Signer) *Server {
		return &Server{cfg: Config{CADrain: d, Signer: sig, Now: clock}, now: clock}
	}

	// Straggler on draining CA "bbbb" (!= active), accelerated, in-wave, and our signer has cut over
	// -> renew.
	if !srv(drained, sg).forceRenewStraggler(ctx, "100.64.0.7", "bbbb") {
		t.Fatal("a straggler on a force-drained CA (our signer cut over, open wave) must be force-renewed")
	}
	// #3 fix: our signer has NOT cut over (still on a different CA) -> NO renew, else a forced renewal
	// re-signs the straggler under the same draining CA forever.
	otherSg, _ := newSignerOn(t)
	if srv(drained, otherSg).forceRenewStraggler(ctx, "100.64.0.7", "bbbb") {
		t.Fatal("must NOT force-renew until THIS process's signer has cut over to the active CA")
	}
	// A nil signer -> no renew.
	if srv(drained, nil).forceRenewStraggler(ctx, "100.64.0.7", "bbbb") {
		t.Fatal("a nil signer must not force-renew")
	}
	// Already on the active CA -> no renew.
	if srv(drained, sg).forceRenewStraggler(ctx, "100.64.0.7", activeFp) {
		t.Fatal("a host already on the active CA must not be force-renewed")
	}
	// Empty host CA fingerprint -> no renew.
	if srv(drained, sg).forceRenewStraggler(ctx, "100.64.0.7", "") {
		t.Fatal("an unknown host CA fingerprint must not be force-renewed")
	}
	// CADrain disabled -> no renew.
	if srv(nil, sg).forceRenewStraggler(ctx, "100.64.0.7", "bbbb") {
		t.Fatal("no CADrain source must not force-renew")
	}
	// Draining but NOT accelerated -> no renew (natural renewal only).
	notAccel := fakeDrain{active: activeFp, started: now - int64(time.Hour), window: int64(time.Minute), accel: false}
	if srv(notAccel, sg).forceRenewStraggler(ctx, "100.64.0.7", "bbbb") {
		t.Fatal("a draining CA without an active force-renew must not be force-renewed")
	}
}
