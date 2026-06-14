package genesis

import (
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/hostkey"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(filepath.Join(t.TempDir(), "g.db"))})
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func run(t *testing.T, p Params) Result {
	t.Helper()
	caB, err := signer.NewSoftwareBackend()
	if err != nil {
		t.Fatal(err)
	}
	cfgB, err := signer.NewSoftwareBackend()
	if err != nil {
		t.Fatal(err)
	}
	if p.Pool == (netip.Prefix{}) {
		p.Pool = netip.MustParsePrefix("100.64.0.0/16")
	}
	if p.OperatorA == "" {
		p.OperatorA, p.OperatorB = "alice", "bob"
	}
	if p.CAName == "" {
		p.CAName = "harbor-ca"
	}
	if p.CALifetime == 0 {
		p.CALifetime, p.CertLifetime = 24*time.Hour, 12*time.Hour
	}
	res, err := Run(context.Background(), newStore(t), caB, cfgB, p)
	if err != nil {
		t.Fatalf("genesis: %v", err)
	}
	return res
}

func hostPub(t *testing.T) []byte {
	t.Helper()
	kp, err := hostkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return kp.PublicKeyPEM()
}

// TestGenesisIssuesCoreControlPlaneCert: with -core-pub, genesis mints Core's cert in
// group control-plane (so the firewall baseline has a host to route to), and the
// lighthouse cert deliberately does NOT carry that group.
func TestGenesisIssuesCoreControlPlaneCert(t *testing.T) {
	res := run(t, Params{
		LighthouseName: "lh1", LighthouseIP: netip.MustParseAddr("100.64.0.1"), LighthousePub: hostPub(t),
		CoreName: "core1", CoreIP: netip.MustParseAddr("100.64.0.2"), CorePub: hostPub(t),
	})
	if res.CoreCertPEM == nil {
		t.Fatal("core cert was not issued")
	}
	fp, err := VerifyControlPlaneCert(res.CoreCertPEM)
	if err != nil {
		t.Fatalf("core cert must verify as control-plane: %v", err)
	}
	if fp != res.CoreFingerprint {
		t.Errorf("fingerprint mismatch: verify=%s result=%s", fp, res.CoreFingerprint)
	}
	// The lighthouse is NOT a control-plane host.
	if _, err := VerifyControlPlaneCert(res.LighthouseCertPEM); err == nil {
		t.Error("lighthouse cert must NOT verify as control-plane")
	}
	// The manifest records the core node.
	var m manifest
	if err := json.Unmarshal(res.ManifestJSON, &m); err != nil {
		t.Fatal(err)
	}
	if m.Core == nil || m.Core.OverlayIP != "100.64.0.2" || m.Core.Fingerprint != res.CoreFingerprint {
		t.Errorf("manifest core = %+v", m.Core)
	}
}

// TestGenesisWithoutCorePubSkipsCore: back-compat — no -core-pub means no Core cert
// and no error (the operator must issue it out-of-band).
func TestGenesisWithoutCorePubSkipsCore(t *testing.T) {
	res := run(t, Params{
		LighthouseName: "lh1", LighthouseIP: netip.MustParseAddr("100.64.0.1"), LighthousePub: hostPub(t),
	})
	if res.CoreCertPEM != nil {
		t.Error("core cert should be skipped without CorePub")
	}
	var m manifest
	_ = json.Unmarshal(res.ManifestJSON, &m)
	if m.Core != nil {
		t.Errorf("manifest must omit core when not issued, got %+v", m.Core)
	}
}

func TestGenesisCoreRequiresValidIP(t *testing.T) {
	caB, _ := signer.NewSoftwareBackend()
	cfgB, _ := signer.NewSoftwareBackend()
	_, err := Run(context.Background(), newStore(t), caB, cfgB, Params{
		OperatorA: "a", OperatorB: "b", CAName: "ca", Pool: netip.MustParsePrefix("100.64.0.0/16"),
		LighthouseName: "lh1", LighthouseIP: netip.MustParseAddr("100.64.0.1"), LighthousePub: hostPub(t),
		CorePub: hostPub(t), // CoreIP intentionally unset
		CALifetime: 24 * time.Hour, CertLifetime: 12 * time.Hour,
	})
	if err == nil {
		t.Fatal("expected an error when -core-pub is set without a core IP")
	}
}

func TestVerifyControlPlaneCertRejectsGarbage(t *testing.T) {
	if _, err := VerifyControlPlaneCert([]byte("-----BEGIN NEBULA CERTIFICATE-----\nnope\n-----END NEBULA CERTIFICATE-----")); err == nil {
		t.Error("garbage must not verify")
	}
	if _, err := VerifyControlPlaneCert(nil); err == nil {
		t.Error("nil must not verify")
	}
}
