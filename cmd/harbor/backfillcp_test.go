package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/genesis"
	"github.com/jeks313/nebula-control-plane/internal/revocation"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

func bfTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(filepath.Join(t.TempDir(), "bf.db"))})
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// mintCert signs a fresh leaf cert (its own ephemeral host key) with the given name,
// groups, and overlay IP, returning the PEM and its fingerprint. It mirrors how
// genesis / issue-cert mint a cert via the signer (software backend), so the test cert
// is byte-for-byte the same shape the live command parses.
func mintCert(t *testing.T, pool netip.Prefix, name string, groups []string, ip netip.Addr) (pem []byte, fingerprint string) {
	t.Helper()
	backend, err := signer.NewSoftwareBackend()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	_, caPEM, err := signer.SelfSignCA(backend, signer.CATemplate{
		Name: "harbor-ca", Networks: []netip.Prefix{pool},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	sg, err := signer.New(signer.Config{
		CACertPEM: caPEM, Backend: backend,
		Policy: signer.IssuePolicy{AllowedNetwork: pool, MaxLifetime: 365 * 24 * time.Hour},
		Audit:  func(context.Context, string, string, string, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	hk, _ := ecdh.P256().GenerateKey(rand.Reader)
	nb := now.Add(-5 * time.Minute)
	c, certPEM, err := sg.Issue(context.Background(), "operator", signer.Template{
		Name:      name,
		Networks:  []netip.Prefix{netip.PrefixFrom(ip, pool.Bits())},
		Groups:    groups,
		NotBefore: nb,
		NotAfter:  nb.Add(365 * 24 * time.Hour),
		PublicKey: hk.PublicKey().Bytes(),
	})
	if err != nil {
		t.Fatalf("mint cert: %v", err)
	}
	fp, err := c.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, fp
}

// TestBackfillCPEnrollmentProtectsControlPlane: backfilling a control-plane cert
// inserts an issued enrollments row with the reserved group + correct
// fingerprint/overlay_ip, and AFTER that revocation.Add(fp) returns
// ErrControlPlaneProtected — proving the always-on P10 guard now resolves the cert.
//
// FAIL-BEFORE (a pre-fix genesis cert has no row): protectControlPlane hits not-found
// -> ALLOW, so Add(fp) would succeed (control plane blocklistable). PASS-AFTER: the
// backfilled row makes Add(fp) refuse.
func TestBackfillCPEnrollmentProtectsControlPlane(t *testing.T) {
	s := bfTestStore(t)
	pool := netip.MustParsePrefix("10.44.0.0/16")
	central := genesis.CentralBlock(pool)
	ip := netip.MustParseAddr("10.44.0.1")
	certPEM, fp := mintCert(t, pool, "lighthouse-1", []string{"lighthouse"}, ip)

	ctx := context.Background()

	// Sanity / fail-before: with NO row, the guard ALLOWS the control plane to be
	// blocklisted. (A fresh registry on a clean store proves the not-found -> allow path.)
	if _, err := revocation.New(s.DB, nil).Add(ctx, fp, "x", "admin"); err != nil {
		t.Fatalf("pre-backfill Add should succeed (no enrollment row -> guard allows): %v", err)
	}
	// Lift it so the post-backfill Add exercises the guard, not ErrAlreadyActive.
	if err := revocation.New(s.DB, nil).Lift(ctx, fp, "admin"); err != nil {
		t.Fatalf("lift: %v", err)
	}

	res, err := backfillCPEnrollment(ctx, s.DB, certPEM, central, backfillOverrides{})
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if res.AlreadyPresent {
		t.Fatal("first backfill reported AlreadyPresent; want a fresh insert")
	}
	if res.Fingerprint != fp || res.OverlayIP != "10.44.0.1" {
		t.Fatalf("result = %+v, want fp=%s ip=10.44.0.1", res, fp)
	}

	// The issued row exists with the reserved group + correct fingerprint/overlay_ip.
	var got struct {
		Fingerprint string `gorm:"column:fingerprint"`
		Status      string `gorm:"column:status"`
		Groups      string `gorm:"column:groups"`
		OverlayIP   string `gorm:"column:overlay_ip"`
		Method      string `gorm:"column:method"`
	}
	if err := s.DB.Table("enrollments").
		Where("fingerprint = ? AND status = ?", fp, "issued").First(&got).Error; err != nil {
		t.Fatalf("issued enrollment not written: %v", err)
	}
	if got.Groups != `["lighthouse"]` || got.OverlayIP != "10.44.0.1" || got.Method != "genesis" {
		t.Fatalf("enrollment row = %+v, want groups=[lighthouse] ip=10.44.0.1 method=genesis", got)
	}

	// PASS-AFTER: the guard now resolves the fingerprint and refuses to blocklist it.
	if _, err := revocation.New(s.DB, nil).Add(ctx, fp, "x", "admin"); !errors.Is(err, revocation.ErrControlPlaneProtected) {
		t.Fatalf("post-backfill Add(fp) err = %v, want ErrControlPlaneProtected", err)
	}
}

// TestBackfillCPEnrollmentByCentralIP: a cert with NON-reserved groups but an overlay IP
// inside the central block is accepted via the central-block half of the abuse guard.
func TestBackfillCPEnrollmentByCentralIP(t *testing.T) {
	s := bfTestStore(t)
	pool := netip.MustParsePrefix("10.44.0.0/16")
	central := genesis.CentralBlock(pool)  // 10.44.0.0/27
	ip := netip.MustParseAddr("10.44.0.5") // inside central, no reserved group
	certPEM, fp := mintCert(t, pool, "backend-1", []string{"backend"}, ip)

	res, err := backfillCPEnrollment(context.Background(), s.DB, certPEM, central, backfillOverrides{})
	if err != nil {
		t.Fatalf("backfill (central IP) should be accepted: %v", err)
	}
	if res.Fingerprint != fp || res.AlreadyPresent {
		t.Fatalf("result = %+v, want fresh insert for %s", res, fp)
	}
}

// TestBackfillCPEnrollmentIdempotent: running twice leaves exactly one issued row, and
// the second run reports AlreadyPresent.
func TestBackfillCPEnrollmentIdempotent(t *testing.T) {
	s := bfTestStore(t)
	pool := netip.MustParsePrefix("10.44.0.0/16")
	central := genesis.CentralBlock(pool)
	certPEM, fp := mintCert(t, pool, "core-1", []string{"control-plane"}, netip.MustParseAddr("10.44.0.2"))

	ctx := context.Background()
	if _, err := backfillCPEnrollment(ctx, s.DB, certPEM, central, backfillOverrides{}); err != nil {
		t.Fatalf("first backfill: %v", err)
	}
	res2, err := backfillCPEnrollment(ctx, s.DB, certPEM, central, backfillOverrides{})
	if err != nil {
		t.Fatalf("second backfill: %v", err)
	}
	if !res2.AlreadyPresent {
		t.Fatal("second backfill should report AlreadyPresent (idempotent)")
	}
	var n int64
	s.DB.Table("enrollments").Where("fingerprint = ? AND status = ?", fp, "issued").Count(&n)
	if n != 1 {
		t.Fatalf("issued rows = %d, want exactly 1 (idempotent)", n)
	}
}

// TestBackfillCPEnrollmentAbuseGuard: a cert whose groups are NOT reserved and whose
// overlay IP is OUTSIDE the central block is REFUSED, and nothing is written — proving
// the command cannot forge an issued enrollment for an arbitrary host.
func TestBackfillCPEnrollmentAbuseGuard(t *testing.T) {
	s := bfTestStore(t)
	pool := netip.MustParsePrefix("10.44.0.0/16")
	central := genesis.CentralBlock(pool)    // 10.44.0.0/27
	ip := netip.MustParseAddr("10.44.99.99") // outside central
	certPEM, fp := mintCert(t, pool, "laptop-1", []string{"users"}, ip)

	ctx := context.Background()
	if _, err := backfillCPEnrollment(ctx, s.DB, certPEM, central, backfillOverrides{}); err == nil {
		t.Fatal("expected the abuse guard to REFUSE a non-control-plane cert")
	}
	var n int64
	s.DB.Table("enrollments").Where("fingerprint = ?", fp).Count(&n)
	if n != 0 {
		t.Fatalf("issued rows = %d, want 0 (refused -> nothing written)", n)
	}
}

// TestBackfillCPEnrollmentGroupsOverride: a non-reserved cert outside central is refused,
// but an operator override of -groups to a reserved group is the SANCTIONED path (the
// guard runs on the RESOLVED values). Documents that the override is honored and still
// routes through the abuse guard.
func TestBackfillCPEnrollmentGroupsOverride(t *testing.T) {
	s := bfTestStore(t)
	pool := netip.MustParsePrefix("10.44.0.0/16")
	central := genesis.CentralBlock(pool)
	ip := netip.MustParseAddr("10.44.50.50") // outside central
	certPEM, _ := mintCert(t, pool, "laptop-2", []string{"users"}, ip)

	ctx := context.Background()
	// Without override: refused.
	if _, err := backfillCPEnrollment(ctx, s.DB, certPEM, central, backfillOverrides{}); err == nil {
		t.Fatal("expected refusal without a reserved group")
	}
	// With -groups control-plane override: accepted (resolved groups are reserved).
	res, err := backfillCPEnrollment(ctx, s.DB, certPEM, central, backfillOverrides{groups: []string{"control-plane"}})
	if err != nil {
		t.Fatalf("override to reserved group should be accepted: %v", err)
	}
	if len(res.Groups) != 1 || res.Groups[0] != "control-plane" {
		t.Fatalf("resolved groups = %v, want [control-plane]", res.Groups)
	}
}
