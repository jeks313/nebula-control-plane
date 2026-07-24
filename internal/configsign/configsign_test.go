package configsign

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"testing"

	"github.com/slackhq/nebula/cert"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

func mkBackend(t *testing.T) (b signer.Backend, pub *ecdsa.PublicKey, pem, fp string) {
	t.Helper()
	be, err := signer.NewSoftwareBackend()
	if err != nil {
		t.Fatalf("software backend: %v", err)
	}
	raw, err := be.PublicKey()
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	k, err := jws.ParseP256PublicPoint(raw)
	if err != nil {
		t.Fatalf("parse point: %v", err)
	}
	return be, k, string(cert.MarshalSigningPublicKeyToPEM(cert.Curve_P256, raw)), wire.PubkeyHash(raw)
}

// TestConfigSignerSwapAtomicAndFailSafe: Swap validates + recomputes the keyID from the NEW backend,
// is idempotent on the same key, and a failed Swap leaves the prior key signing (no torn state).
func TestConfigSignerSwapAtomicAndFailSafe(t *testing.T) {
	b1, _, _, fp1 := mkBackend(t)
	b2, _, _, fp2 := mkBackend(t)

	cs, err := New(b1, nil, nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if cs.CurrentFingerprint() != fp1 {
		t.Fatalf("current fp = %s, want %s", cs.CurrentFingerprint(), fp1)
	}
	// Swap to K2 recomputes the fingerprint from the new backend.
	if err := cs.Swap(b2); err != nil {
		t.Fatalf("swap: %v", err)
	}
	if cs.CurrentFingerprint() != fp2 {
		t.Fatalf("after swap fp = %s, want %s", cs.CurrentFingerprint(), fp2)
	}
	// Idempotent: swapping to the key already in use is a no-op.
	if err := cs.Swap(b2); err != nil {
		t.Fatalf("idempotent swap: %v", err)
	}
	// Fail-safe: a bad swap (nil backend) errors and the prior key keeps signing.
	if err := cs.Swap(nil); err == nil {
		t.Fatal("swap(nil) must error")
	}
	if cs.CurrentFingerprint() != fp2 {
		t.Fatalf("after failed swap fp = %s, want unchanged %s", cs.CurrentFingerprint(), fp2)
	}
}

// TestSignFollowsHotSwap: a bundle signed before the swap verifies under K1; after the swap the Kid
// matches K2 and it verifies under K2 only — never a K2-Kid-over-K1-signature tear.
func TestSignFollowsHotSwap(t *testing.T) {
	b1, k1, _, fp1 := mkBackend(t)
	b2, k2, _, fp2 := mkBackend(t)
	cs, _ := New(b1, nil, nil)

	signed1, err := cs.Sign(bundle.Bundle{Device: bundle.Device{Name: "h"}})
	if err != nil {
		t.Fatalf("sign1: %v", err)
	}
	if _, err := bundle.Verify(signed1, []*ecdsa.PublicKey{k1}); err != nil {
		t.Fatalf("signed1 must verify under K1: %v", err)
	}
	if _, err := bundle.Verify(signed1, []*ecdsa.PublicKey{k2}); err == nil {
		t.Fatal("signed1 must NOT verify under K2")
	}
	// Confirm the Kid the pilot would report.
	if kid := kidOf(t, signed1, k1); kid != fp1 {
		t.Fatalf("signed1 kid = %s, want %s", kid, fp1)
	}

	if err := cs.Swap(b2); err != nil {
		t.Fatal(err)
	}
	signed2, err := cs.Sign(bundle.Bundle{Device: bundle.Device{Name: "h"}})
	if err != nil {
		t.Fatalf("sign2: %v", err)
	}
	if _, err := bundle.Verify(signed2, []*ecdsa.PublicKey{k2}); err != nil {
		t.Fatalf("signed2 must verify under K2: %v", err)
	}
	if _, err := bundle.Verify(signed2, []*ecdsa.PublicKey{k1}); err == nil {
		t.Fatal("signed2 must NOT verify under K1")
	}
	// A pilot trusting BOTH (the overlap set) verifies either — the acceptance property.
	if _, err := bundle.Verify(signed1, []*ecdsa.PublicKey{k1, k2}); err != nil {
		t.Fatalf("overlap set must verify signed1: %v", err)
	}
	if _, err := bundle.Verify(signed2, []*ecdsa.PublicKey{k1, k2}); err != nil {
		t.Fatalf("overlap set must verify signed2: %v", err)
	}
	if kid := kidOf(t, signed2, k2); kid != fp2 {
		t.Fatalf("signed2 kid = %s, want %s", kid, fp2)
	}
}

// TestReconcileActiveConfigKey: the reconciler swaps to the registry's active key via the factory,
// is a no-op on an empty ref, and refuses a factory that builds the WRONG key (fail-safe).
func TestReconcileActiveConfigKey(t *testing.T) {
	b1, _, _, fp1 := mkBackend(t)
	b2, _, pem2, fp2 := mkBackend(t)
	cs, _ := New(b1, nil, nil)
	factory := func(_ context.Context, _ string, _ []byte) (signer.Backend, error) { return b2, nil }

	// Empty ref -> no swap.
	swapped, err := cs.ReconcileActiveConfigKey(context.Background(), func(context.Context) (ActiveConfigKeyRef, error) {
		return ActiveConfigKeyRef{}, nil
	}, factory)
	if err != nil || swapped || cs.CurrentFingerprint() != fp1 {
		t.Fatalf("empty ref: swapped=%v err=%v fp=%s", swapped, err, cs.CurrentFingerprint())
	}
	// Active K2 -> swap.
	swapped, err = cs.ReconcileActiveConfigKey(context.Background(), func(context.Context) (ActiveConfigKeyRef, error) {
		return ActiveConfigKeyRef{Fingerprint: fp2, PubPEM: pem2, KMSKeyID: "kms:2"}, nil
	}, factory)
	if err != nil || !swapped || cs.CurrentFingerprint() != fp2 {
		t.Fatalf("active K2: swapped=%v err=%v fp=%s want %s", swapped, err, cs.CurrentFingerprint(), fp2)
	}
	// A factory that returns a backend NOT matching the ref's fingerprint is refused (fail-safe: keep
	// the current key), so the reconciler never signs under a key the registry didn't activate.
	wrongFactory := func(_ context.Context, _ string, _ []byte) (signer.Backend, error) { return b1, nil }
	swapped, err = cs.ReconcileActiveConfigKey(context.Background(), func(context.Context) (ActiveConfigKeyRef, error) {
		return ActiveConfigKeyRef{Fingerprint: "SOME_OTHER_FP", PubPEM: pem2, KMSKeyID: "kms:x"}, nil
	}, wrongFactory)
	if swapped || err == nil {
		t.Fatalf("mismatched factory must be refused: swapped=%v err=%v", swapped, err)
	}
	if cs.CurrentFingerprint() != fp2 {
		t.Fatalf("after refused reconcile fp = %s, want unchanged %s", cs.CurrentFingerprint(), fp2)
	}
}

// kidOf extracts the JWS Kid the signer stamped (proving Sign uses the swapped key's id), by
// verifying the envelope with the expected key and reading the returned header.
func kidOf(t *testing.T, signed []byte, verifyKey *ecdsa.PublicKey) string {
	t.Helper()
	var env jws.Flattened
	if err := json.Unmarshal(signed, &env); err != nil {
		t.Fatalf("decode env: %v", err)
	}
	h, _, err := jws.VerifyAny(env, []*ecdsa.PublicKey{verifyKey})
	if err != nil {
		t.Fatalf("verify env: %v", err)
	}
	return h.Kid
}
