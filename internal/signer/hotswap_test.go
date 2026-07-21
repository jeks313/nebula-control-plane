package signer

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
)

// caWith self-signs a P256 CA from backend b with the given expiry and returns (PEM, lower-hex fp).
func caWith(t *testing.T, b Backend, notAfter time.Time) (pem []byte, fp string) {
	t.Helper()
	pub, err := b.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	tbs := &cert.TBSCertificate{
		Version:   cert.Version2,
		Name:      "rotca",
		IsCA:      true,
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  notAfter,
		PublicKey: pub,
		Curve:     cert.Curve_P256,
	}
	c, err := SignTBS(b, tbs, nil)
	if err != nil {
		t.Fatalf("self-sign CA: %v", err)
	}
	p, err := c.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	f, _ := c.Fingerprint()
	return p, strings.ToLower(strings.TrimSpace(f))
}

// TestSwapCAValidatesAndIsAtomic: a valid cut-over changes the signing CA; an invalid one
// (backend/cert public-key mismatch, or an expired CA) is refused and the previous CA keeps
// signing; swapping to the CA already in use is a no-op.
func TestSwapCAValidatesAndIsAtomic(t *testing.T) {
	audit := &recordingAudit{}
	s := newSigner(t, 100, audit)
	ca1fp := s.CurrentFingerprint()
	if ca1fp == "" {
		t.Fatal("boot signer has no current fingerprint")
	}

	// A fresh CA2 with its own backend -> a valid cut-over.
	b2, _ := NewSoftwareBackend()
	ca2PEM, ca2fp := caWith(t, b2, time.Now().Add(5*365*24*time.Hour))

	// Refusal 1: right cert, WRONG backend (b2's pubkey != ca1's) -> rejected, CA unchanged.
	if err := s.SwapCA(ca2PEM, s.identity.Load().backend); err == nil {
		t.Fatal("SwapCA with a mismatched backend must be refused")
	}
	if s.CurrentFingerprint() != ca1fp {
		t.Fatal("a refused swap must not change the signing CA")
	}

	// Refusal 2: an already-expired CA2 -> rejected even with the matching backend.
	bx, _ := NewSoftwareBackend()
	expPEM, _ := caWith(t, bx, time.Now().Add(-time.Minute))
	if err := s.SwapCA(expPEM, bx); err == nil {
		t.Fatal("SwapCA to an expired CA must be refused")
	}
	if s.CurrentFingerprint() != ca1fp {
		t.Fatal("a refused (expired) swap must not change the signing CA")
	}

	// Valid cut-over: CA2 with its matching backend.
	if err := s.SwapCA(ca2PEM, b2); err != nil {
		t.Fatalf("valid SwapCA: %v", err)
	}
	if s.CurrentFingerprint() != ca2fp {
		t.Fatalf("after cut-over fp = %s, want CA2 %s", s.CurrentFingerprint(), ca2fp)
	}

	// Idempotent: swapping to the CA already in use is a no-op (no error).
	if err := s.SwapCA(ca2PEM, b2); err != nil {
		t.Fatalf("idempotent SwapCA: %v", err)
	}
	if s.CurrentFingerprint() != ca2fp {
		t.Fatal("idempotent swap changed the CA")
	}
}

// TestIssueFollowsHotSwap: after a cut-over, a freshly issued leaf chains to (and verifies
// against) CA2, not CA1 — the whole point of the swap.
func TestIssueFollowsHotSwap(t *testing.T) {
	s := newSigner(t, 100, &recordingAudit{})

	b2, _ := NewSoftwareBackend()
	ca2PEM, ca2fp := caWith(t, b2, time.Now().Add(5*365*24*time.Hour))
	if err := s.SwapCA(ca2PEM, b2); err != nil {
		t.Fatalf("SwapCA: %v", err)
	}

	c, _, err := s.Issue(context.Background(), "alice", goodTemplate(t))
	if err != nil {
		t.Fatalf("Issue after swap: %v", err)
	}
	if got := strings.ToLower(strings.TrimSpace(c.Issuer())); got != ca2fp {
		t.Fatalf("issued leaf Issuer = %s, want CA2 %s", got, ca2fp)
	}
	// It verifies against CA2 (a leaf still signed by CA1 would not), confirming the swap took.
	pool2, _ := cert.NewCAPoolFromPEM(ca2PEM)
	if _, err := pool2.VerifyCertificate(time.Now(), c); err != nil {
		t.Fatalf("leaf does not verify against CA2: %v", err)
	}
}

// TestReconcileActiveCA: the reconciler swaps when the active CA changes, no-ops once converged,
// no-ops on an empty active fingerprint, and surfaces (without swapping) a factory failure.
func TestReconcileActiveCA(t *testing.T) {
	ctx := context.Background()
	s := newSigner(t, 100, &recordingAudit{})
	ca1fp := s.CurrentFingerprint()

	b2, _ := NewSoftwareBackend()
	ca2PEM, ca2fp := caWith(t, b2, time.Now().Add(5*365*24*time.Hour))

	active := func(context.Context) (ActiveCARef, error) {
		return ActiveCARef{Fingerprint: ca2fp, CertPEM: ca2PEM, KMSKeyID: "software"}, nil
	}
	factory := func(context.Context, string, []byte) (Backend, error) { return b2, nil }

	// First reconcile cuts over to CA2.
	swapped, err := s.ReconcileActiveCA(ctx, active, factory)
	if err != nil || !swapped {
		t.Fatalf("first reconcile: swapped=%v err=%v, want true/nil", swapped, err)
	}
	if s.CurrentFingerprint() != ca2fp {
		t.Fatalf("after reconcile fp = %s, want CA2 %s (was %s)", s.CurrentFingerprint(), ca2fp, ca1fp)
	}
	// Second reconcile is a no-op (already converged).
	if swapped, err := s.ReconcileActiveCA(ctx, active, factory); err != nil || swapped {
		t.Fatalf("second reconcile: swapped=%v err=%v, want false/nil", swapped, err)
	}

	// Empty active fingerprint -> keep current, no swap, no error.
	emptyActive := func(context.Context) (ActiveCARef, error) { return ActiveCARef{}, nil }
	if swapped, err := s.ReconcileActiveCA(ctx, emptyActive, factory); err != nil || swapped {
		t.Fatalf("empty-active reconcile: swapped=%v err=%v, want false/nil", swapped, err)
	}

	// A factory failure surfaces as an error WITHOUT changing the signing CA.
	b3, _ := NewSoftwareBackend()
	ca3PEM, ca3fp := caWith(t, b3, time.Now().Add(5*365*24*time.Hour))
	badActive := func(context.Context) (ActiveCARef, error) {
		return ActiveCARef{Fingerprint: ca3fp, CertPEM: ca3PEM, KMSKeyID: "software"}, nil
	}
	failFactory := func(context.Context, string, []byte) (Backend, error) {
		return nil, errors.New("cannot reach backend")
	}
	if swapped, err := s.ReconcileActiveCA(ctx, badActive, failFactory); err == nil || swapped {
		t.Fatalf("factory-fail reconcile: swapped=%v err=%v, want false/err", swapped, err)
	}
	if s.CurrentFingerprint() != ca2fp {
		t.Fatal("a failed reconcile must not change the signing CA")
	}
}
