package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/wire"
	"github.com/slackhq/nebula/cert"
)

// TestFullRotationDrillBothRoots is the M8.7-style staging drill run in the local harness (the "drill
// on BOTH" — the user-chosen harness-first phase): a single host is carried through a full rotation of
// BOTH trust roots — the CA (leaf-signing) AND the config-signing key (bundle-signing) — and at every
// step the host's leaf still verifies against a CA in its delivered bundle AND the bundle JWS still
// verifies against the host's trusted config-key set. Zero rejections, zero data-plane discontinuity.
// The two rotations are independent axes and compose: CA1->CA2 changes who signs the LEAF; K1->K2
// changes who signs the BUNDLE. Findings: both drain to 0 and both old roots retire cleanly.
func TestFullRotationDrillBothRoots(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	api := e.coreAPI()

	pin := e.pinned
	trustPath := filepath.Join(t.TempDir(), "config-signing-trust.json")

	// learnTrust mirrors the pilot's CONFIG-ONLY apply (writeConfigArtifacts, GET /v1/config): the
	// bundle JWS must verify against the live config-key trust set (pin UNION learned), then the
	// learned keys are persisted. The cert is deliberately NOT applied on this path (a renewed host
	// keeps its own fresh cert), so the leaf is not checked here. A JWS-verify failure is a rejection.
	learnTrust := func(t *testing.T, label string, jwsBytes []byte) bundle.Bundle {
		t.Helper()
		b, err := bundle.Verify(jwsBytes, bundle.TrustedSet(pin, trustPath))
		if err != nil {
			t.Fatalf("[%s] bundle JWS rejected (config-key trust broke): %v", label, err)
		}
		if err := bundle.PersistTrustFile(trustPath, b.ConfigKeyVersion, b.ConfigSigningKeys); err != nil {
			t.Fatalf("[%s] persist trust: %v", label, err)
		}
		return b
	}
	// applyFull mirrors the pilot's enroll/renew apply (writeArtifacts): learnTrust PLUS the leaf must
	// verify against a CA in the delivered ca_bundle (the cert IS applied on this path, so the
	// data-plane depends on the host trusting the CA that signed this fresh leaf).
	applyFull := func(t *testing.T, label string, jwsBytes []byte) bundle.Bundle {
		t.Helper()
		b := learnTrust(t, label, jwsBytes)
		leafVerifiesAgainstBundle(t, label, b)
		return b
	}
	deliver := func(t *testing.T, eid string) []byte {
		t.Helper()
		status, jws, _, ok, err := e.cons.BuildDeliverable(ctx, eid)
		if err != nil || !ok || status != "issued" {
			t.Fatalf("deliverable %s: %s ok=%v err=%v", eid, status, ok, err)
		}
		return jws
	}
	renew := func(t *testing.T, label, ip string) bundle.Bundle {
		t.Helper()
		body, _ := signRenew(t)
		rec := renewReq(t, api, body, ip)
		if rec.Code != http.StatusOK {
			t.Fatalf("[%s] renew: %d %s", label, rec.Code, rec.Body)
		}
		var rr wire.RenewResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &rr); err != nil {
			t.Fatal(err)
		}
		return applyFull(t, label, rr.Bundle)
	}

	// --- t0: enroll under CA1 + config-K1 ---
	secret, _, _ := joinkey.Create(ctx, e.store, joinkey.Params{Name: "k", Groups: []string{"web"}, MaxUses: 0, AutoIssue: true}, time.Now())
	res, err := e.cons.Process(ctx, e.candidate(t, secret, "drill-host"))
	if err != nil || res.Status != "issued" {
		t.Fatalf("enroll: %v %s", err, res.Status)
	}
	ip := res.OverlayIP
	applyFull(t, "enroll", deliver(t, "eid-drill-host"))
	ca1, _ := e.caReg.Active(ctx)
	cfg1fp := e.configKeyID

	// ================= ROTATION 1: the CA (leaf-signing) =================
	ca2PEM, ca2backend := mkStagedCAWithBackend(t, "ca-2")
	ca2row, err := e.caReg.Stage(ctx, "ca-2", ca2PEM, "software", "op")
	if err != nil {
		t.Fatal(err)
	}
	// Trust before you sign: the host picks up [CA1,CA2] and still verifies.
	learnTrust(t, "ca:staged", deliver(t, "eid-drill-host"))
	// Adoption (CA path): the host reports trusting both CAs.
	heartbeatReq(t, api, ip, wire.HeartbeatRequest{
		ProtocolVersion: wire.ProtocolVersion, Type: "heartbeat", Health: "ok",
		TrustedCAFingerprints: []string{ca1.Fingerprint, ca2row.Fingerprint},
	})
	if ad, _ := e.caReg.AdoptionStatus(ctx, ca2row.Fingerprint, 5*time.Minute); !ad.FullyAdopted() {
		t.Fatalf("CA2 not fully adopted: %+v", ad)
	}
	// Cut over: activate CA2 and hot-swap the LEAF signer.
	if err := e.caReg.Activate(ctx, ca2row.ID, "op"); err != nil {
		t.Fatal(err)
	}
	if err := e.sg.SwapCA([]byte(ca2PEM), ca2backend); err != nil {
		t.Fatal(err)
	}
	// Renew: the fresh leaf is signed by CA2, and still verifies against the delivered bundle.
	bCA := renew(t, "ca:renewed", ip)
	if issuerFP(t, []byte(bCA.Certificate)) != ca2row.Fingerprint {
		t.Fatalf("post-CA-rotation leaf Issuer = %s, want CA2 %s", issuerFP(t, []byte(bCA.Certificate)), ca2row.Fingerprint)
	}
	// Drain + retire CA1 (0 live dependents now the host is on CA2).
	if n, _ := e.caReg.LiveDependents(ctx, ca1.Fingerprint); n != 0 {
		t.Fatalf("CA1 live dependents = %d after drain, want 0", n)
	}
	if err := e.caReg.Retire(ctx, ca1.ID, "op"); err != nil {
		t.Fatalf("retire CA1: %v", err)
	}

	// ================= ROTATION 2: the config-signing key (bundle-signing) =================
	k2PEM, k2kid, k2backend := mkConfigKeyWithBackend(t)
	ck2row, err := e.ckReg.Stage(ctx, "config-2", k2PEM, "software", "op")
	if err != nil {
		t.Fatal(err)
	}
	// Trust before you sign: the host learns cfgK2 from a still-K1-signed bundle.
	learnTrust(t, "ck:staged", deliver(t, "eid-drill-host"))
	// Adoption (config-key path): reported from the trust file the pilot actually verifies with.
	heartbeatReq(t, api, ip, wire.HeartbeatRequest{
		ProtocolVersion: wire.ProtocolVersion, Type: "heartbeat", Health: "ok",
		TrustedConfigKeyFingerprints: []string{cfg1fp, k2kid},
	})
	if ad, _ := e.ckReg.AdoptionStatus(ctx, ck2row.Fingerprint, 5*time.Minute); !ad.FullyAdopted() {
		t.Fatalf("cfgK2 not fully adopted: %+v", ad)
	}
	// Cut over: activate cfgK2 and hot-swap the BUNDLE signer.
	if err := e.ckReg.Activate(ctx, ck2row.ID, "op"); err != nil {
		t.Fatal(err)
	}
	if err := e.configSigner.Swap(k2backend); err != nil {
		t.Fatal(err)
	}
	// Renew: the bundle is now signed by cfgK2; the host (trusting {cfgK1,cfgK2}) still verifies it.
	renew(t, "ck:renewed", ip)
	// Prove the bundle cut over: a cfgK2-signed bundle must NOT verify under the pin alone.
	if raw := deliver(t, "eid-drill-host"); func() bool { _, err := bundle.Verify(raw, pin); return err == nil }() {
		t.Fatal("post-cut-over bundle verified under the config pin alone — bundle signer did not cut over")
	}
	// Drain + retire cfgK1 (the live fleet fully trusts the active cfgK2).
	ck1id := configKeyID(t, e, cfg1fp)
	if err := e.ckReg.Retire(ctx, ck1id, 5*time.Minute, "op"); err != nil {
		t.Fatalf("retire cfgK1: %v", err)
	}

	// --- final: after BOTH roots rotated + retired, the host still verifies a fresh bundle end-to-end ---
	final := renew(t, "final", ip)
	if len(final.CABundle) != 1 || len(final.ConfigSigningKeys) != 1 {
		t.Fatalf("post-drill trust sets = ca:%d cfg:%d, want 1 each (only the new active roots)", len(final.CABundle), len(final.ConfigSigningKeys))
	}
	if issuerFP(t, []byte(final.Certificate)) != ca2row.Fingerprint {
		t.Fatal("final leaf not on CA2")
	}
}

// leafVerifiesAgainstBundle asserts the bundle's leaf cert verifies against SOME CA in its ca_bundle
// (the data-plane continuity check — a host must always trust the CA that signed its own cert).
func leafVerifiesAgainstBundle(t *testing.T, label string, b bundle.Bundle) {
	t.Helper()
	leaf, _, err := cert.UnmarshalCertificateFromPEM([]byte(b.Certificate))
	if err != nil {
		t.Fatalf("[%s] parse leaf: %v", label, err)
	}
	for _, caPEM := range b.CABundle {
		pool, perr := cert.NewCAPoolFromPEM([]byte(caPEM))
		if perr != nil {
			continue
		}
		if _, verr := pool.VerifyCertificate(time.Now(), leaf); verr == nil {
			return
		}
	}
	t.Fatalf("[%s] leaf does not verify against any CA in the delivered ca_bundle (data-plane would break)", label)
}
