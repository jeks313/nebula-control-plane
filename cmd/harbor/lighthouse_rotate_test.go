package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
	"github.com/slackhq/nebula/cert"
	"gorm.io/gorm"
)

// rotTestCA is a software CA the test both seeds enrollment certs with and passes to
// rotateLighthouseCert, plus the public CA PEM (so the whole flow uses one CA).
type rotTestCA struct {
	backend signer.Backend
	caPEM   []byte
	pool    netip.Prefix
}

func newRotTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(filepath.Join(t.TempDir(), "rot.db"))})
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newRotTestCA(t *testing.T, pool netip.Prefix) rotTestCA {
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
	return rotTestCA{backend: backend, caPEM: caPEM, pool: pool}
}

// seedEnrollment mints a cert (its own ephemeral host key) expiring at notAfter and inserts the
// matching issued enrollment row — the shape rotateLighthouseCert reads. Returns the host pubkey
// (which a cert-only rotation must reuse) and the original fingerprint.
func (ca rotTestCA) seedEnrollment(t *testing.T, db *gorm.DB, name string, groups []string, ip netip.Addr, notAfter time.Time) (pub []byte, origFP string) {
	t.Helper()
	sg, err := signer.New(signer.Config{
		CACertPEM: ca.caPEM, Backend: ca.backend,
		Policy: signer.IssuePolicy{AllowedNetwork: ca.pool, MaxLifetime: 10 * 365 * 24 * time.Hour},
		Audit:  func(context.Context, string, string, string, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	hk, _ := ecdh.P256().GenerateKey(rand.Reader)
	pub = hk.PublicKey().Bytes()
	c, certPEM, err := sg.Issue(context.Background(), "operator", signer.Template{
		Name:      name,
		Networks:  []netip.Prefix{netip.PrefixFrom(ip, ca.pool.Bits())},
		Groups:    groups,
		NotBefore: time.Now().Add(-5 * time.Minute), // valid now; only NotAfter drives rotate-if-within
		NotAfter:  notAfter,
		PublicKey: pub,
	})
	if err != nil {
		t.Fatalf("seed mint: %v", err)
	}
	origFP, _ = c.Fingerprint()
	gj, _ := json.Marshal(groups)
	row := enrollment.Enrollment{
		DeviceName:  name,
		Pubkey:      pub,
		Groups:      string(gj),
		Status:      enrollment.StatusIssued,
		Method:      "genesis",
		CertPEM:     certPEM,
		OverlayIP:   ip.String(),
		Fingerprint: origFP,
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("insert enrollment: %v", err)
	}
	return pub, origFP
}

// TestRotateLighthouseCertReSignsInPlace: a due cert is re-signed with the SAME key + overlay IP
// + groups, a NEW (later) expiry and fingerprint, and the enrollment row is updated to the new
// cert. The cert is valid and verifies against the CA.
func TestRotateLighthouseCertReSignsInPlace(t *testing.T) {
	s := newRotTestStore(t)
	pool := netip.MustParsePrefix("10.44.0.0/16")
	ca := newRotTestCA(t, pool)
	ip := netip.MustParseAddr("10.44.0.1")
	// Expires in 20 days -> due under a 90d window.
	pub, origFP := ca.seedEnrollment(t, s.DB, "lighthouse-1", []string{"lighthouse"}, ip, time.Now().Add(20*24*time.Hour))

	ctx := context.Background()
	audit := func(c context.Context, a, ac, tg, d string) error { _, e := s.AppendAudit(c, a, ac, tg, d); return e }
	res, err := rotateLighthouseCert(ctx, s.DB, audit, ca.backend, ca.caPEM, rotateParams{
		Name: "lighthouse-1", Pool: pool, Lifetime: 365 * 24 * time.Hour, Within: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if !res.Rotated {
		t.Fatal("expected Rotated=true for a cert expiring within the window")
	}
	if res.Fingerprint == origFP {
		t.Fatal("fingerprint unchanged — re-sign produced the same cert")
	}
	if res.OverlayIP != "10.44.0.1" {
		t.Fatalf("overlay IP = %s, want 10.44.0.1 (must be preserved)", res.OverlayIP)
	}

	// The new cert is valid, keeps the SAME key + IP + groups, and expires later.
	c, _, err := cert.UnmarshalCertificateFromPEM(res.CertPEM)
	if err != nil {
		t.Fatalf("new cert does not parse: %v", err)
	}
	if string(c.PublicKey()) != string(pub) {
		t.Fatal("cert-only rotation must reuse the existing public key")
	}
	if !c.NotAfter().After(time.Now().Add(300 * 24 * time.Hour)) {
		t.Fatalf("new NotAfter %s is not ~1y out — expiry was not extended", c.NotAfter())
	}
	gotGroups := c.Groups()
	if len(gotGroups) != 1 || gotGroups[0] != "lighthouse" {
		t.Fatalf("groups = %v, want [lighthouse]", gotGroups)
	}

	// The enrollment row now carries the new cert + fingerprint.
	var row enrollment.Enrollment
	if err := s.DB.Where("device_name = ? AND status = ?", "lighthouse-1", enrollment.StatusIssued).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Fingerprint != res.Fingerprint || string(row.CertPEM) != string(res.CertPEM) {
		t.Fatal("enrollment row was not updated to the rotated cert")
	}
}

// TestRotateLighthouseCertNotDue: a cert comfortably beyond the window is a no-op — nothing
// re-signed, nothing written (the enrollment fingerprint is unchanged). This is what makes the
// monthly timer idempotent.
func TestRotateLighthouseCertNotDue(t *testing.T) {
	s := newRotTestStore(t)
	pool := netip.MustParsePrefix("10.44.0.0/16")
	ca := newRotTestCA(t, pool)
	ip := netip.MustParseAddr("10.44.0.1")
	// Expires in 300 days -> NOT due under a 90d window.
	_, origFP := ca.seedEnrollment(t, s.DB, "lighthouse-1", []string{"lighthouse"}, ip, time.Now().Add(300*24*time.Hour))

	res, err := rotateLighthouseCert(context.Background(), s.DB, nil, ca.backend, ca.caPEM, rotateParams{
		Name: "lighthouse-1", Pool: pool, Lifetime: 365 * 24 * time.Hour, Within: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if res.Rotated {
		t.Fatal("expected Rotated=false for a cert outside the rotation window")
	}
	var row enrollment.Enrollment
	if err := s.DB.Where("device_name = ?", "lighthouse-1").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Fingerprint != origFP {
		t.Fatal("not-due rotation must NOT write a new cert/fingerprint")
	}
}

// TestRotateLighthouseCertFailsClosedOnNonLighthouse: the command refuses to re-sign an issued
// enrollment that is NOT in the lighthouse group — it can only ever rotate the lighthouse, so it
// can't be turned into a general off-API cert factory.
func TestRotateLighthouseCertFailsClosedOnNonLighthouse(t *testing.T) {
	s := newRotTestStore(t)
	pool := netip.MustParsePrefix("10.44.0.0/16")
	ca := newRotTestCA(t, pool)
	ca.seedEnrollment(t, s.DB, "laptop-1", []string{"users"}, netip.MustParseAddr("10.44.9.9"), time.Now().Add(10*24*time.Hour))

	_, err := rotateLighthouseCert(context.Background(), s.DB, nil, ca.backend, ca.caPEM, rotateParams{
		Name: "laptop-1", Pool: pool, Lifetime: 365 * 24 * time.Hour, Within: 90 * 24 * time.Hour,
	})
	if err == nil {
		t.Fatal("expected a refusal for a non-lighthouse enrollment")
	}
}

// TestRotateLighthouseCertNoEnrollment: a missing enrollment is an error, not a silent success.
func TestRotateLighthouseCertNoEnrollment(t *testing.T) {
	s := newRotTestStore(t)
	pool := netip.MustParsePrefix("10.44.0.0/16")
	ca := newRotTestCA(t, pool)

	_, err := rotateLighthouseCert(context.Background(), s.DB, nil, ca.backend, ca.caPEM, rotateParams{
		Name: "ghost", Pool: pool, Lifetime: 365 * 24 * time.Hour, Within: 0,
	})
	if err == nil {
		t.Fatal("expected an error for a lighthouse with no issued enrollment")
	}
}
