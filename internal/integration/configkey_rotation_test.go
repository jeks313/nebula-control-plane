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
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/wire"
	"github.com/slackhq/nebula/cert"
)

// mkConfigKeyWithBackend mints a fresh P256 config-signing key ("K2") and returns its public-key PEM,
// fingerprint (= JWS Kid), and the backend holding its key, so a test can stage it AND hot-swap the
// live ConfigSigner to it (the software cut-over the cmd/harbor factory refuses, driven directly here).
func mkConfigKeyWithBackend(t *testing.T) (pubPEM, kid string, backend signer.Backend) {
	t.Helper()
	b, err := signer.NewSoftwareBackend()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := b.PublicKey()
	return string(cert.MarshalSigningPublicKeyToPEM(cert.Curve_P256, raw)), wire.PubkeyHash(raw), b
}

// TestConfigKeyOverlapVerifiesNoRejection is the M8.5 "done when" acceptance (design §4.6/§4.8):
// a host enrolled under config key K1 keeps verifying every delivered bundle with ZERO Pilot
// rejections across a full K1->K2 config-signing-key rotation — stage K2, adopt it fleet-wide,
// activate + hot-swap signing to K2, renew (now signed by K2), and retire K1 — because the pilot
// verifies against its trusted SET (pin UNION the keys learned from its last verified bundle).
func TestConfigKeyOverlapVerifiesNoRejection(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	api := e.coreAPI()

	// The pilot pins K1 (the genesis config key). Its learned-trust file starts absent.
	pin := e.pinned // []*ecdsa.PublicKey{K1}
	trustPath := filepath.Join(t.TempDir(), "config-signing-trust.json")

	// applyBundle simulates the pilot verifying + applying a delivered bundle: verify against the live
	// trusted set (pin UNION learned trust-file), then persist the advertised keys — exactly what
	// enrollclient.writeArtifacts/writeConfigArtifacts do. A verify failure here IS a "Pilot rejection".
	applyBundle := func(t *testing.T, label string, jwsBytes []byte) bundle.Bundle {
		t.Helper()
		trusted := bundle.TrustedSet(pin, trustPath)
		b, err := bundle.Verify(jwsBytes, trusted)
		if err != nil {
			t.Fatalf("PILOT REJECTED the %s bundle across the K1->K2 overlap: %v", label, err)
		}
		if err := bundle.PersistTrustFile(trustPath, b.ConfigKeyVersion, b.ConfigSigningKeys); err != nil {
			t.Fatalf("persist learned trust (%s): %v", label, err)
		}
		return b
	}
	deliverable := func(t *testing.T, eid string) []byte {
		t.Helper()
		status, jws, _, ok, err := e.cons.BuildDeliverable(ctx, eid)
		if err != nil || !ok || status != "issued" {
			t.Fatalf("deliverable %s: status=%s ok=%v err=%v", eid, status, ok, err)
		}
		return jws
	}

	// 1. Enroll a host under K1. Its first bundle is signed by K1 and advertises only K1.
	secret, _, _ := joinkey.Create(ctx, e.store, joinkey.Params{Name: "k", Groups: []string{"web"}, MaxUses: 0, AutoIssue: true}, time.Now())
	res, err := e.cons.Process(ctx, e.candidate(t, secret, "host-ck"))
	if err != nil || res.Status != "issued" {
		t.Fatalf("enroll: %v %s", err, res.Status)
	}
	ip := res.OverlayIP
	b1 := applyBundle(t, "enroll (K1)", deliverable(t, "eid-host-ck"))
	if len(b1.ConfigSigningKeys) != 1 {
		t.Fatalf("enroll bundle config_signing_keys = %d, want 1 (just K1)", len(b1.ConfigSigningKeys))
	}
	genV := b1.ConfigKeyVersion

	// 2. Stage K2 — now trusted fleet-wide (advertised) but not yet signing.
	k2PEM, k2kid, k2backend := mkConfigKeyWithBackend(t)
	k2row, err := e.ckReg.Stage(ctx, "config-2", k2PEM, "software", "op")
	if err != nil {
		t.Fatalf("stage K2: %v", err)
	}

	// 3. The host re-fetches its bundle (still signed by K1, now advertising [K1, K2]) and applies it,
	//    LEARNING K2 into its local trust set — the "trust before you sign" step, with no rejection.
	b2 := applyBundle(t, "post-stage (K1, advertising K2)", deliverable(t, "eid-host-ck"))
	if len(b2.ConfigSigningKeys) != 2 {
		t.Fatalf("post-stage config_signing_keys = %d, want 2 (K1 + K2)", len(b2.ConfigSigningKeys))
	}
	if b2.ConfigKeyVersion <= genV {
		t.Fatalf("ConfigKeyVersion did not advance after staging K2 (%d <= %d)", b2.ConfigKeyVersion, genV)
	}
	// The pilot now trusts BOTH keys (pin K1 UNION learned {K1,K2}).
	if got := bundle.TrustedSet(pin, trustPath); len(got) != 2 {
		t.Fatalf("pilot trusted set = %d, want 2 after learning K2", len(got))
	}

	// 4. The host reports its trusted config keys on heartbeat -> AdoptionStatus(K2) hits 100%.
	heartbeatReq(t, api, ip, wire.HeartbeatRequest{
		ProtocolVersion: wire.ProtocolVersion, Type: "heartbeat", Health: "ok",
		TrustedConfigKeyFingerprints: []string{e.configKeyID, k2kid},
	})
	ad, err := e.ckReg.AdoptionStatus(ctx, k2row.Fingerprint, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if ad.Live != 1 || ad.Adopted != 1 || !ad.FullyAdopted() {
		t.Fatalf("adoption of K2 = %+v, want 1 live / 1 adopted / full", ad)
	}

	// 5. Activate K2 (gate satisfied) and hot-swap the SHARED config signer to it (the reconciler's
	//    job; driven directly because the cmd/harbor factory refuses a software cut-over).
	if err := e.ckReg.Activate(ctx, k2row.ID, "op"); err != nil {
		t.Fatalf("activate K2: %v", err)
	}
	if err := e.configSigner.Swap(k2backend); err != nil {
		t.Fatalf("hot-swap to K2: %v", err)
	}
	if e.configSigner.CurrentFingerprint() != k2kid {
		t.Fatalf("after swap fp = %s, want K2 %s", e.configSigner.CurrentFingerprint(), k2kid)
	}

	// 6. THE ACCEPTANCE: the host renews; the renew bundle is now signed by K2, and the pilot (which
	//    learned K2 in step 3) verifies it with ZERO rejection.
	body, _ := signRenew(t)
	rec := renewReq(t, api, body, ip)
	if rec.Code != http.StatusOK {
		t.Fatalf("renew: %d %s", rec.Code, rec.Body)
	}
	var rr wire.RenewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &rr); err != nil {
		t.Fatal(err)
	}
	bRenew := applyBundle(t, "renew (K2)", rr.Bundle)
	// Prove the cut-over really happened: the K2-signed bundle must NOT verify against the pin alone.
	if _, err := bundle.Verify(rr.Bundle, pin); err == nil {
		t.Fatal("post-cut-over bundle verified under the pin K1 alone — the signer did not cut over to K2")
	}
	_ = bRenew

	// 7. Retire K1 — gated fail-closed on the live fleet fully trusting the ACTIVE key (K2). It does.
	k1id := configKeyID(t, e, e.configKeyID)
	if err := e.ckReg.Retire(ctx, k1id, 5*time.Minute, "op"); err != nil {
		t.Fatalf("retire K1: %v", err)
	}
	// Post-retire: bundles advertise only K2; the host (still trusting K2) verifies with no rejection.
	b3 := applyBundle(t, "post-retire (K2 only)", deliverable(t, "eid-host-ck"))
	if len(b3.ConfigSigningKeys) != 1 {
		t.Fatalf("post-retire config_signing_keys = %d, want 1 (just K2)", len(b3.ConfigSigningKeys))
	}
}

// configKeyID returns the registry row id of the config key with the given fingerprint.
func configKeyID(t *testing.T, e enrollEnv, fp string) int64 {
	t.Helper()
	rows, err := e.ckReg.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Fingerprint == fp {
			return r.ID
		}
	}
	t.Fatalf("no config key with fingerprint %s", fp)
	return 0
}
