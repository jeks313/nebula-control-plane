package ca

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/slackhq/nebula/cert"
	"gorm.io/gorm"
)

// mkCAWithBackend mints a CA and returns its PEM, fingerprint, parsed cert, and the backend
// holding its private key, so a test can sign real leaves under it (mkCA discards the backend).
func mkCAWithBackend(t *testing.T, name string) (pemStr, fp string, caCert cert.Certificate, b signer.Backend) {
	t.Helper()
	bk, err := signer.NewSoftwareBackend()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c, p, err := signer.SelfSignCA(bk, signer.CATemplate{
		Name: name, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("self-sign CA %s: %v", name, err)
	}
	f, _ := c.Fingerprint()
	return string(p), f, c, bk
}

// mkLeafPEM signs a non-CA leaf under caCert/b with the given expiry and returns its PEM. The
// leaf's Issuer() is caCert's fingerprint (byte-identical to what LiveDependents falls back to).
func mkLeafPEM(t *testing.T, caCert cert.Certificate, b signer.Backend, name string, notAfter time.Time) string {
	t.Helper()
	lb, err := signer.NewSoftwareBackend()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := lb.PublicKey()
	tbs := &cert.TBSCertificate{
		Version:   cert.Version2,
		Name:      name,
		Networks:  []netip.Prefix{netip.MustParsePrefix("100.64.0.9/32")},
		IsCA:      false,
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  notAfter,
		PublicKey: pub,
		Curve:     cert.Curve_P256,
	}
	c, err := signer.SignTBS(b, tbs, caCert)
	if err != nil {
		t.Fatalf("sign leaf %s: %v", name, err)
	}
	p, _ := c.MarshalPEM()
	return string(p)
}

// seedEnroll inserts one enrollment row with the given status, cert PEM, and (possibly empty)
// ca_fingerprint, so LiveDependents / Retire can be exercised against real rows.
func seedEnroll(t *testing.T, db *gorm.DB, eid, status, certPEM, caFP string) {
	t.Helper()
	if err := db.Table("enrollments").Create(map[string]any{
		"enrollment_id":  eid,
		"device_name":    eid,
		"pubkey_hash":    "h-" + eid,
		"pubkey":         []byte("x"),
		"method":         "test",
		"status":         status,
		"cert_pem":       []byte(certPEM),
		"ca_fingerprint": caFP,
		"created_at":     time.Now().UnixNano(),
	}).Error; err != nil {
		t.Fatalf("seed enrollment %s: %v", eid, err)
	}
}

// TestForceRenewLifecycle: an accelerated drain (M8.3c) can be started only on a DRAINING CA, is
// reflected by DrainWave, and is cleared by StopForceRenew; ActiveFingerprint tracks the signing CA.
func TestForceRenewLifecycle(t *testing.T) {
	_, r := setup(t)
	ctx := context.Background()
	pem1, fp1, _, _ := mkCAWithBackend(t, "ca-1")
	pem2, _, _, _ := mkCAWithBackend(t, "ca-2")
	ca1, _, _ := r.SeedActive(ctx, "ca-1", pem1, "software", "boot")
	ca2, _ := r.Stage(ctx, "ca-2", pem2, "kms", "op")
	if err := r.Activate(ctx, ca2.ID, "op"); err != nil { // ca-1 draining, ca-2 active
		t.Fatal(err)
	}

	// Only a draining CA can be force-drained: the active CA-2 is refused.
	if err := r.ForceRenew(ctx, ca2.ID, time.Hour, "op"); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("force-renew the active CA err = %v, want ErrIllegalTransition", err)
	}
	// A non-positive window is refused.
	if err := r.ForceRenew(ctx, ca1.ID, 0, "op"); err == nil {
		t.Fatal("force-renew with window 0 must be refused")
	}
	// The draining CA-1 accepts it, and DrainWave reflects the window.
	if err := r.ForceRenew(ctx, ca1.ID, 30*time.Minute, "op"); err != nil {
		t.Fatalf("force-renew draining CA-1: %v", err)
	}
	started, window, accel, err := r.DrainWave(ctx, fp1)
	if err != nil || !accel || window != int64(30*time.Minute) || started == 0 {
		t.Fatalf("DrainWave(ca-1) = (%d,%d,%v,%v), want accelerated with a 30m window", started, window, accel, err)
	}
	// ActiveFingerprint is CA-2; the active CA is never itself accelerated-draining.
	if af, _ := r.ActiveFingerprint(ctx); af != ca2.Fingerprint {
		t.Fatalf("ActiveFingerprint = %s, want CA-2 %s", af, ca2.Fingerprint)
	}
	if _, _, accel2, _ := r.DrainWave(ctx, ca2.Fingerprint); accel2 {
		t.Fatal("the active CA must not report an accelerated drain")
	}
	// An unknown fingerprint is simply not accelerated (no error).
	if _, _, accel3, derr := r.DrainWave(ctx, "deadbeef"); derr != nil || accel3 {
		t.Fatalf("DrainWave(unknown) = (%v,%v), want (false,nil)", accel3, derr)
	}
	// Stop reverts to natural renewal.
	if err := r.StopForceRenew(ctx, ca1.ID, "op"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if _, _, accel4, _ := r.DrainWave(ctx, fp1); accel4 {
		t.Fatal("after stop, CA-1 must not report an accelerated drain")
	}
}

// TestLiveDependents: the drain count only tallies issued, non-expired leaves that chain to the
// CA, counting them by the stored ca_fingerprint OR — when empty (a pre-8.3 row) — by the leaf's
// own Issuer(). Expired leaves, non-issued rows, other CAs' leaves, and unparseable PEMs are all
// excluded, none of them panic.
func TestLiveDependents(t *testing.T) {
	s, r := setup(t)
	ctx := context.Background()

	_, fp1, ca1, bk1 := mkCAWithBackend(t, "ca-1")
	_, fp2, ca2, bk2 := mkCAWithBackend(t, "ca-2")
	future := time.Now().Add(24 * time.Hour)
	past := time.Now().Add(-time.Hour)

	// Counted toward ca-1:
	seedEnroll(t, s.DB, "e-explicit", "issued", mkLeafPEM(t, ca1, bk1, "host-a", future), fp1) // explicit fp
	seedEnroll(t, s.DB, "e-fallback", "issued", mkLeafPEM(t, ca1, bk1, "host-b", future), "")  // Issuer() fallback
	// NOT counted toward ca-1:
	seedEnroll(t, s.DB, "e-expired", "issued", mkLeafPEM(t, ca1, bk1, "host-c", past), fp1) // expired
	seedEnroll(t, s.DB, "e-pending", "pending", mkLeafPEM(t, ca1, bk1, "host-e", future), fp1) // not issued
	seedEnroll(t, s.DB, "e-garbage", "issued", "-----BEGIN X-----\nnot pem\n-----END X-----", fp1) // unparseable
	seedEnroll(t, s.DB, "e-ca2", "issued", mkLeafPEM(t, ca2, bk2, "host-d", future), fp2) // a different CA

	n1, err := r.LiveDependents(ctx, fp1)
	if err != nil {
		t.Fatalf("LiveDependents(ca-1): %v", err)
	}
	if n1 != 2 {
		t.Fatalf("LiveDependents(ca-1) = %d, want 2 (explicit + Issuer() fallback only)", n1)
	}
	n2, err := r.LiveDependents(ctx, fp2)
	if err != nil {
		t.Fatalf("LiveDependents(ca-2): %v", err)
	}
	if n2 != 1 {
		t.Fatalf("LiveDependents(ca-2) = %d, want 1 (its own leaf, not ca-1's)", n2)
	}
	// Case-insensitive: an upper-cased query fingerprint still matches.
	if up, _ := r.LiveDependents(ctx, "ABCDEF"); up != 0 {
		t.Fatalf("LiveDependents(unknown) = %d, want 0", up)
	}
}
