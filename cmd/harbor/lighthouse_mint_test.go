package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/slackhq/nebula/cert"
)

// newHostPubPEM generates a P256 host key and returns its public half as the PEM
// `lighthouse mint -in-pub` expects (the same shape `pilot init` emits), plus the raw bytes.
func newHostPubPEM(t *testing.T) (pem, raw []byte) {
	t.Helper()
	hk, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw = hk.PublicKey().Bytes()
	return cert.MarshalPublicKeyToPEM(cert.Curve_P256, raw), raw
}

// TestMintLighthousePinsIPAndRecordsEnrollment: mint reserves the PINNED IP, issues a cert in the
// lighthouse group from the supplied key, and records an issued enrollment — and the result is
// immediately rotate-able (proving mint produces exactly what rotate-cert reads).
func TestMintLighthousePinsIPAndRecordsEnrollment(t *testing.T) {
	s := newRotTestStore(t)
	pool := netip.MustParsePrefix("10.44.0.0/16")
	ca := newRotTestCA(t, pool)
	ip := netip.MustParseAddr("10.44.0.3") // reserved 2nd-lighthouse IP (.2 is harbor)
	pubPEM, raw := newHostPubPEM(t)

	ctx := context.Background()
	audit := func(c context.Context, a, ac, tg, d string) error { _, e := s.AppendAudit(c, a, ac, tg, d); return e }
	res, err := mintLighthouse(ctx, s, audit, ca.backend, ca.caPEM, mintParams{
		Name: "lighthouse-2", IP: ip, Pool: pool, Lifetime: 365 * 24 * time.Hour, PubPEM: pubPEM,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if res.OverlayIP != "10.44.0.3" {
		t.Fatalf("overlay IP = %s, want pinned 10.44.0.3", res.OverlayIP)
	}

	// The cert pins the IP, the lighthouse group, and the supplied key.
	c, _, err := cert.UnmarshalCertificateFromPEM(res.CertPEM)
	if err != nil {
		t.Fatalf("minted cert does not parse: %v", err)
	}
	if string(c.PublicKey()) != string(raw) {
		t.Fatal("minted cert must carry the supplied host key")
	}
	if g := c.Groups(); len(g) != 1 || g[0] != "lighthouse" {
		t.Fatalf("groups = %v, want [lighthouse]", g)
	}
	if len(c.Networks()) != 1 || c.Networks()[0].Addr() != ip {
		t.Fatalf("networks = %v, want the pinned %s", c.Networks(), ip)
	}

	// The issued enrollment row exists with the RAW pubkey + lighthouse group.
	var row enrollment.Enrollment
	if err := s.DB.Where("device_name = ? AND status = ?", "lighthouse-2", enrollment.StatusIssued).First(&row).Error; err != nil {
		t.Fatalf("issued enrollment not recorded: %v", err)
	}
	if row.OverlayIP != "10.44.0.3" || row.Groups != `["lighthouse"]` || string(row.Pubkey) != string(raw) {
		t.Fatalf("enrollment row = {ip:%s groups:%s} mismatch", row.OverlayIP, row.Groups)
	}

	// End-to-end: a freshly minted lighthouse is immediately rotate-able.
	rot, err := rotateLighthouseCert(ctx, s.DB, audit, ca.backend, ca.caPEM, rotateParams{
		Name: "lighthouse-2", Pool: pool, Lifetime: 365 * 24 * time.Hour, Within: 0,
	})
	if err != nil {
		t.Fatalf("rotate after mint: %v", err)
	}
	if !rot.Rotated || rot.OverlayIP != "10.44.0.3" || rot.Fingerprint == res.Fingerprint {
		t.Fatalf("rotate after mint did not re-sign in place: %+v", rot)
	}
}

// TestMintLighthouseRejectsBadKey: a non-parseable public key is refused (nothing minted).
func TestMintLighthouseRejectsBadKey(t *testing.T) {
	s := newRotTestStore(t)
	pool := netip.MustParsePrefix("10.44.0.0/16")
	ca := newRotTestCA(t, pool)

	_, err := mintLighthouse(context.Background(), s, nil, ca.backend, ca.caPEM, mintParams{
		Name: "lighthouse-2", IP: netip.MustParseAddr("10.44.0.3"), Pool: pool,
		Lifetime: 365 * 24 * time.Hour, PubPEM: []byte("-----BEGIN NEBULA ED25519 PUBLIC KEY-----\nnope\n-----END NEBULA ED25519 PUBLIC KEY-----\n"),
	})
	if err == nil {
		t.Fatal("expected a parse error for a bad public key")
	}
}

// TestMintLighthouseRejectsOutOfPoolIP: a pinned IP outside the pool is refused by the allocator.
func TestMintLighthouseRejectsOutOfPoolIP(t *testing.T) {
	s := newRotTestStore(t)
	pool := netip.MustParsePrefix("10.44.0.0/16")
	ca := newRotTestCA(t, pool)
	pubPEM, _ := newHostPubPEM(t)

	_, err := mintLighthouse(context.Background(), s, nil, ca.backend, ca.caPEM, mintParams{
		Name: "lighthouse-x", IP: netip.MustParseAddr("10.99.0.1"), Pool: pool, // outside 10.44.0.0/16
		Lifetime: 365 * 24 * time.Hour, PubPEM: pubPEM,
	})
	if err == nil {
		t.Fatal("expected an out-of-pool error for a pinned IP outside the pool")
	}
}
