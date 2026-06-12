package integration

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/ipam"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
	"github.com/slackhq/nebula/cert"
)

// TestIssueCertEndToEnd is the M2.8 acceptance, automated: allocate an IP, sign a
// cert v2 leaf, and confirm the leaf verifies against the CA and that the action
// is recorded in the hash-chained audit log. Uses the software backend, so it
// needs no SoftHSM or external binaries.
func TestIssueCertEndToEnd(t *testing.T) {
	dsn := store.DefaultSQLiteDSN(filepath.Join(t.TempDir(), "harbor.db"))
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}

	// CA + signer.
	backend, err := signer.NewSoftwareBackend()
	if err != nil {
		t.Fatal(err)
	}
	pool := netip.MustParsePrefix("100.64.0.0/16")
	now := time.Now()
	_, caPEM, err := signer.SelfSignCA(backend, signer.CATemplate{
		Name: "harbor-ca", Networks: []netip.Prefix{pool},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	audit := func(ctx context.Context, actor, action, target, details string) error {
		_, err := s.AppendAudit(ctx, actor, action, target, details)
		return err
	}
	sg, err := signer.New(signer.Config{
		CACertPEM: caPEM, Backend: backend,
		Policy:          signer.Policy{AllowedNetwork: pool, MaxLifetime: 30 * 24 * time.Hour},
		MaxCertsPerHour: 100, Audit: audit,
	})
	if err != nil {
		t.Fatal(err)
	}

	// IPAM + a host key (as a Pilot would generate).
	alloc, err := ipam.NewAllocator(s, ipam.Pool{Prefix: pool})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ip, err := alloc.Allocate(ctx, "web-1", "")
	if err != nil {
		t.Fatal(err)
	}
	hk, _ := ecdh.P256().GenerateKey(rand.Reader)

	nb := now.Add(-5 * time.Minute)
	c, _, err := sg.Issue(ctx, "operator", signer.Template{
		Name:      "web-1",
		Networks:  []netip.Prefix{netip.PrefixFrom(ip, pool.Bits())},
		Groups:    []string{"web"},
		NotBefore: nb,
		NotAfter:  nb.Add(30 * 24 * time.Hour),
		PublicKey: hk.PublicKey().Bytes(),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// The issued leaf verifies against the CA...
	caPool, err := cert.NewCAPoolFromPEM(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := caPool.VerifyCertificate(time.Now(), c); err != nil {
		t.Fatalf("issued cert does not verify: %v", err)
	}
	if got := c.Networks(); len(got) != 1 || got[0].Addr() != ip {
		t.Fatalf("cert networks = %v, want IP %s", got, ip)
	}

	// ...and the issuance is in the chained audit log.
	if n, err := s.VerifyAudit(ctx); err != nil {
		t.Fatalf("audit chain broken: %v", err)
	} else if n < 1 {
		t.Fatalf("expected an audit row, got %d", n)
	}
}
