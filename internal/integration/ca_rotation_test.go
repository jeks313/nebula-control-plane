package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/wire"
	"github.com/slackhq/nebula/cert"
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

// issuerFP is the normalized signing-CA fingerprint of a leaf PEM (its cert.Issuer()).
func issuerFP(t *testing.T, certPEM []byte) string {
	t.Helper()
	c, _, err := cert.UnmarshalCertificateFromPEM(certPEM)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return strings.ToLower(strings.TrimSpace(c.Issuer()))
}

// TestCAFingerprintStampedAndRestamped is the M8.3a drain-tracking acceptance: the CA that
// signed a host's CURRENT leaf is recorded on the enrollment row (its cert.Issuer(), byte-
// identical to the active CA's registry fingerprint) at issue AND re-stamped on every renewal,
// so ca.LiveDependents can count live leaves per CA and Retire can gate on a real drain count.
func TestCAFingerprintStampedAndRestamped(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	api := e.coreAPI()

	act, err := e.caReg.Active(ctx) // the seeded genesis CA that signs today
	if err != nil {
		t.Fatalf("active CA: %v", err)
	}

	// Enroll a host -> the issued row records the signing CA's fingerprint.
	secret, _, _ := joinkey.Create(ctx, e.store, joinkey.Params{Name: "k", Groups: []string{"web"}, MaxUses: 0, AutoIssue: true}, time.Now())
	res, err := e.cons.Process(ctx, e.candidate(t, secret, "host-drain"))
	if err != nil || res.Status != "issued" {
		t.Fatalf("enroll: %v %s", err, res.Status)
	}
	ip := res.OverlayIP
	row := issuedRow(t, e, ip)
	if row.CAFingerprint == "" {
		t.Fatal("issued enrollment did not stamp ca_fingerprint")
	}
	if row.CAFingerprint != act.Fingerprint || row.CAFingerprint != issuerFP(t, res.CertPEM) {
		t.Fatalf("stamped ca_fingerprint = %s, want the active CA %s (= leaf Issuer %s)",
			row.CAFingerprint, act.Fingerprint, issuerFP(t, res.CertPEM))
	}

	// The end-to-end drain count now sees this live leaf under the active CA.
	if n, err := e.caReg.LiveDependents(ctx, act.Fingerprint); err != nil || n < 1 {
		t.Fatalf("LiveDependents(active) = %d err=%v, want >= 1", n, err)
	}

	// Renew (rotates the key) -> ca_fingerprint is re-stamped and still tracks the signing CA.
	body, _ := signRenew(t)
	rec := renewReq(t, api, body, ip)
	if rec.Code != http.StatusOK {
		t.Fatalf("renew status = %d; %s", rec.Code, rec.Body)
	}
	var rr wire.RenewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &rr); err != nil {
		t.Fatal(err)
	}
	post := issuedRow(t, e, ip)
	if post.CAFingerprint == "" || post.CAFingerprint != issuerFP(t, []byte(mustBundleCert(t, rr.Bundle, e))) {
		t.Fatalf("renew did not re-stamp ca_fingerprint (got %s)", post.CAFingerprint)
	}
}

// mustBundleCert extracts the leaf PEM from a verified renew bundle.
func mustBundleCert(t *testing.T, jws []byte, e enrollEnv) string {
	t.Helper()
	b, err := bundle.Verify(jws, e.pinned)
	if err != nil {
		t.Fatalf("verify renew bundle: %v", err)
	}
	return b.Certificate
}

// TestHeartbeatDrivesCAAdoption is the M8.1 end-to-end acceptance across the full
// wire -> coreapi -> query path: a host's heartbeat-reported trusted CA set is stored, and
// ca.AdoptionStatus walks from 0% to 100% as the host starts reporting trust of a staged CA.
func TestHeartbeatDrivesCAAdoption(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	api := e.coreAPI()

	ip, _ := enrolledHost(t, e, "host-adopt")
	act, _ := e.caReg.Active(ctx) // the seeded CA1

	// Stage CA2 (trusted, not yet signing).
	ca2row, err := e.caReg.Stage(ctx, "ca-2", mkStagedCA(t, "ca-2"), "kms", "op")
	if err != nil {
		t.Fatalf("stage CA2: %v", err)
	}

	// The host heartbeats trusting only CA1 -> CA2 is NOT adopted.
	heartbeatReq(t, api, ip, wire.HeartbeatRequest{
		ProtocolVersion: wire.ProtocolVersion, Type: "heartbeat", Health: "ok",
		TrustedCAFingerprints: []string{act.Fingerprint},
	})
	ad, err := e.caReg.AdoptionStatus(ctx, ca2row.Fingerprint, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if ad.Live != 1 || ad.Adopted != 0 || ad.FullyAdopted() {
		t.Fatalf("pre-adoption: %+v (want 1 live, 0 adopted, not full)", ad)
	}

	// Now the host reports trusting CA2 too -> fully adopted (the upsert must UPDATE the row).
	heartbeatReq(t, api, ip, wire.HeartbeatRequest{
		ProtocolVersion: wire.ProtocolVersion, Type: "heartbeat", Health: "ok",
		TrustedCAFingerprints: []string{act.Fingerprint, ca2row.Fingerprint},
	})
	ad, _ = e.caReg.AdoptionStatus(ctx, ca2row.Fingerprint, 5*time.Minute)
	if ad.Live != 1 || ad.Adopted != 1 || !ad.FullyAdopted() {
		t.Fatalf("post-adoption: %+v (want 1 live, 1 adopted, full — did the upsert update trusted_cas?)", ad)
	}
}
