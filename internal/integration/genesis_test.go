package integration

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/genesis"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
	"github.com/slackhq/nebula/cert"
)

// TestGenesisRun is the M3.1 acceptance, automated: a genesis run produces a CA,
// a config-signing key, and a first lighthouse cert that verifies against the CA;
// the keys are recorded and every step is in the chained audit log.
func TestGenesisRun(t *testing.T) {
	dsn := store.DefaultSQLiteDSN(filepath.Join(t.TempDir(), "harbor.db"))
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}

	caB, err := signer.NewSoftwareBackend()
	if err != nil {
		t.Fatal(err)
	}
	cfgB, err := signer.NewSoftwareBackend()
	if err != nil {
		t.Fatal(err)
	}

	// The lighthouse generates its own key (P1); genesis only sees the pubkey.
	hk, _ := ecdh.P256().GenerateKey(rand.Reader)
	lhPubPEM := cert.MarshalPublicKeyToPEM(cert.Curve_P256, hk.PublicKey().Bytes())

	pool := netip.MustParsePrefix("100.64.0.0/16")
	res, err := genesis.Run(context.Background(), s, caB, cfgB, genesis.Params{
		OperatorA: "alice", OperatorB: "bob", CAName: "harbor-ca", Pool: pool,
		LighthouseName: "lighthouse-1", LighthouseIP: netip.MustParseAddr("100.64.0.1"),
		LighthouseAddr: "198.51.100.1:4242", LighthousePub: lhPubPEM,
		CALifetime: 10 * 365 * 24 * time.Hour, CertLifetime: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("genesis.Run: %v", err)
	}

	// Lighthouse cert verifies against the genesis CA.
	pool2, err := cert.NewCAPoolFromPEM(res.CACertPEM)
	if err != nil {
		t.Fatal(err)
	}
	lhCert, _, err := cert.UnmarshalCertificateFromPEM(res.LighthouseCertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool2.VerifyCertificate(time.Now(), lhCert); err != nil {
		t.Fatalf("lighthouse cert does not verify against genesis CA: %v", err)
	}

	// Config-signing pubkey is a valid P256 key (pinnable by Pilot).
	if _, _, curve, err := cert.UnmarshalPublicKeyFromPEM(res.ConfigSigningPubPEM); err != nil || curve != cert.Curve_P256 {
		t.Fatalf("config-signing pub invalid: curve=%v err=%v", curve, err)
	}

	// Trust roots recorded: the CA, the config-signing key, and the SSO
	// assertion-signing public key (ADR 0004 S6 — genesis mints the dedicated keypair
	// and records only its PUBLIC half; the gateway holds the private half off-mesh).
	var keys []store.Key
	if err := s.DB.Order("id").Find(&keys).Error; err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 || keys[0].Kind != "ca" || keys[1].Kind != "config-signing" || keys[2].Kind != "sso-assertion" {
		t.Fatalf("keys = %+v, want [ca, config-signing, sso-assertion]", keys)
	}

	// Audit chain intact, with the genesis events present.
	n, err := s.VerifyAudit(context.Background())
	if err != nil {
		t.Fatalf("audit chain: %v", err)
	}
	if n < 4 { // genesis-ca, genesis-config-key, issue-cert, genesis-complete
		t.Fatalf("audit rows = %d, want >= 4", n)
	}
}
