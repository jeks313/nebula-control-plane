package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/signer"
)

// mkStagedCA mints a fresh self-signed P256 CA (a would-be "CA2") and returns its PEM.
func mkStagedCA(t *testing.T, name string) string {
	t.Helper()
	b, _ := signer.NewSoftwareBackend()
	now := time.Now()
	_, pem, err := signer.SelfSignCA(b, signer.CATemplate{
		Name: name, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(5 * 365 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("self-sign %s: %v", name, err)
	}
	return string(pem)
}

// deliveredBundle rebuilds + verifies the signed bundle an issued enrollment would ship,
// using the CURRENT trust set (so callers snapshot ca_bundle at the right moment).
func (e enrollEnv) deliveredBundle(t *testing.T, enrollmentID string) bundle.Bundle {
	t.Helper()
	status, jws, _, ok, err := e.cons.BuildDeliverable(context.Background(), enrollmentID)
	if err != nil || !ok || status != "issued" {
		t.Fatalf("deliverable %s: status=%s ok=%v err=%v", enrollmentID, status, ok, err)
	}
	b, err := bundle.Verify(jws, e.pinned)
	if err != nil {
		t.Fatalf("verify bundle %s: %v", enrollmentID, err)
	}
	return b
}

// TestEnrollBundleCarriesStagedCA is the M8.1 "trust before you sign" acceptance: once a
// second CA is STAGED, every newly issued bundle's ca_bundle carries BOTH the active CA and
// the staged one, so the fleet trusts CA2 before it ever signs a leaf. The host cert is
// still signed by (and verifies against) the ACTIVE CA — staging changes trust, not signing.
func TestEnrollBundleCarriesStagedCA(t *testing.T) {
	e := setupEnroll(t) // seeds the current CA as active + wires CABundleSource
	ctx := context.Background()

	secret, _, _ := joinkey.Create(ctx, e.store, joinkey.Params{Name: "k1", Groups: []string{"web"}, MaxUses: 0, AutoIssue: true}, time.Now())

	// Before staging: the bundle trusts exactly the one (active) CA.
	if res, err := e.cons.Process(ctx, e.candidate(t, secret, "host-pre")); err != nil || res.Status != "issued" {
		t.Fatalf("pre-stage enroll: %v %s", err, res.Status)
	}
	if b := e.deliveredBundle(t, "eid-host-pre"); len(b.CABundle) != 1 || b.CABundle[0] != string(e.caPEM) {
		t.Fatalf("pre-stage ca_bundle = %v, want just the active CA", b.CABundle)
	}

	// Stage CA2. It is now trusted fleet-wide but not yet signing.
	ca2 := mkStagedCA(t, "ca-2")
	if _, err := e.caReg.Stage(ctx, "ca-2", ca2, "kms:ca2-arn", "op"); err != nil {
		t.Fatalf("stage CA2: %v", err)
	}
	if act, _ := e.caReg.Active(ctx); act.Name != "test-ca" {
		t.Fatalf("active CA after stage = %q, want the original (staging must NOT change signing)", act.Name)
	}

	// A new enrollment's bundle now carries BOTH CAs (trust before you sign)...
	res2, err := e.cons.Process(ctx, e.candidate(t, secret, "host-post"))
	if err != nil || res2.Status != "issued" {
		t.Fatalf("post-stage enroll: %v %s", err, res2.Status)
	}
	b := e.deliveredBundle(t, "eid-host-post")
	if len(b.CABundle) != 2 {
		t.Fatalf("post-stage ca_bundle = %d entries, want 2 (active + staged)", len(b.CABundle))
	}
	if got := map[string]bool{b.CABundle[0]: true, b.CABundle[1]: true}; !got[string(e.caPEM)] || !got[ca2] {
		t.Fatal("post-stage ca_bundle missing the active or the staged CA")
	}
	// ...but the freshly issued host cert is still signed by (and verifies against) the ACTIVE CA.
	e.verifyCert(t, res2.CertPEM)

	// Abandon CA2 -> it leaves the trust bundle again.
	rows, _ := e.caReg.List(ctx)
	var ca2ID int64
	for _, r := range rows {
		if r.Name == "ca-2" {
			ca2ID = r.ID
		}
	}
	if err := e.caReg.Abandon(ctx, ca2ID, "op"); err != nil {
		t.Fatalf("abandon CA2: %v", err)
	}
	if tb, _ := e.caReg.TrustBundle(ctx); len(tb) != 1 {
		t.Fatalf("after abandon, trust bundle = %d, want 1 (only the active CA)", len(tb))
	}
}
