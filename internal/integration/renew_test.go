package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/coreapi"
	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
	"github.com/jeks313/nebula-control-plane/internal/wire"
	"github.com/slackhq/nebula/cert"
)

func (e enrollEnv) coreAPI() http.Handler {
	return coreapi.New(coreapi.Config{
		Store: e.store, Signer: e.sg, ConfigBackend: e.cfgB, ConfigKeyID: e.configKeyID,
		CABundlePEM: e.caPEM, Pool: e.pool, CertLifetime: 24 * time.Hour,
		Lighthouses:     []bundle.Lighthouse{{OverlayIP: "100.64.0.1", PublicAddrs: []string{"1.2.3.4:4242"}}},
		BlocklistSource: e.rev.ActiveFingerprints,
		CABundleSource:  e.caReg.TrustBundle, // M8: renew/config bundles carry the live trust bundle
		Revocation:      e.rev,               // renew must refuse a revoked host (M7.1 durability)
		Rollout:         rollout.New(e.store.DB, nil),
	}).Handler()
}

// signRenew builds a renew request signed by a fresh (rotated-in) key.
func signRenew(t *testing.T) (body []byte, newPubBytes []byte) {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ek, _ := priv.PublicKey.ECDH()
	pub := ek.Bytes()
	pkh := wire.PubkeyHash(pub)
	req := wire.RenewRequest{
		ProtocolVersion: wire.ProtocolVersion, Type: "renew",
		IssuedAt: time.Now().UTC().Format(time.RFC3339),
		CSR:      wire.CSR{Curve: "P256", PublicKey: base64.RawURLEncoding.EncodeToString(pub)},
	}
	payload, _ := json.Marshal(req)
	env, err := jws.SignES256(priv, jws.Header{Typ: wire.TypRenewRequest, Ver: 1, Kid: pkh}, payload)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(env)
	return b, pub
}

func renewReq(t *testing.T, h http.Handler, body []byte, srcIP string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/v1/certs/renew", strings.NewReader(string(body)))
	r.RemoteAddr = srcIP + ":40000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// TestRenewSameIdentity is the M4.2/4.3 acceptance: a host on its overlay IP can
// renew (new key) and gets a fresh cert with the SAME identity (IP, name,
// groups); a request from a different source IP is rejected.
func TestRenewSameIdentity(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	api := e.coreAPI()

	// First, enroll a host so it has an issued identity at an overlay IP.
	secret, _, _ := joinkey.Create(ctx, e.store, joinkey.Params{Name: "k", Groups: []string{"web"}, MaxUses: 0, AutoIssue: true}, time.Now())
	res, err := e.cons.Process(ctx, e.candidate(t, secret, "host-a"))
	if err != nil || res.Status != "issued" {
		t.Fatalf("enroll: %v %s", err, res.Status)
	}
	ip := res.OverlayIP

	// Renew from the host's overlay IP with a fresh key.
	body, newPub := signRenew(t)
	rec := renewReq(t, api, body, ip)
	if rec.Code != http.StatusOK {
		t.Fatalf("renew status = %d; %s", rec.Code, rec.Body)
	}
	var rr wire.RenewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &rr); err != nil {
		t.Fatal(err)
	}
	b, err := bundle.Verify(rr.Bundle, e.pinned)
	if err != nil {
		t.Fatalf("renew bundle verify: %v", err)
	}
	// Same identity.
	if b.Device.OverlayIP != ip || b.Device.Name != "host-a" || b.Device.Groups[0] != "web" {
		t.Fatalf("renewed identity changed: %+v", b.Device)
	}
	// Fresh cert, bound to the NEW key, verifies against the CA.
	pool, _ := cert.NewCAPoolFromPEM([]byte(b.CABundle[0]))
	c, _, _ := cert.UnmarshalCertificateFromPEM([]byte(b.Certificate))
	if _, err := pool.VerifyCertificate(time.Now(), c); err != nil {
		t.Fatalf("renewed cert does not verify: %v", err)
	}
	if string(c.PublicKey()) != string(newPub) {
		t.Fatal("renewed cert not bound to the new key")
	}
}

// TestRenewBundleCarriesBlocklist is the M7.1 acceptance (data path): a revoked
// peer's fingerprint rides inside the signed config bundle a host pulls at renew,
// so every OTHER host refuses it PEER-SIDE (§4.7) — the target need not cooperate.
// It also proves the blocklist is sorted (deterministic; no false drift), is
// tamper-evident (signed), and that the host's own fingerprint is persisted and
// re-stamped on renewal so it can later be targeted by overlay IP (7.1/7.3).
func TestRenewBundleCarriesBlocklist(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	api := e.coreAPI()

	// Enroll host-a so it has an issued identity to renew.
	secret, _, _ := joinkey.Create(ctx, e.store, joinkey.Params{Name: "k", Groups: []string{"web"}, MaxUses: 0, AutoIssue: true}, time.Now())
	res, err := e.cons.Process(ctx, e.candidate(t, secret, "host-a"))
	if err != nil || res.Status != "issued" {
		t.Fatalf("enroll: %v %s", err, res.Status)
	}
	ip := res.OverlayIP

	// The host's issued fingerprint was persisted (so it can be blocklisted by
	// overlay IP later — 7.1 -device / 7.3 decommission).
	row := issuedRow(t, e, ip)
	if row.Fingerprint == "" {
		t.Fatal("issued enrollment did not persist a cert fingerprint")
	}
	preRenewFP := row.Fingerprint

	// Blocklist three peer fingerprints, added OUT OF ORDER (to prove the bundle is sorted).
	hi, mid, lo := strings.Repeat("f", 64), strings.Repeat("a", 64), strings.Repeat("0", 64)
	for _, fp := range []string{hi, mid, lo} {
		if _, err := e.rev.Add(ctx, fp, "compromised", "admin"); err != nil {
			t.Fatalf("blocklist %s: %v", fp, err)
		}
	}

	// Renew (host pulls a fresh signed bundle) — it must carry the blocklist.
	body, _ := signRenew(t)
	rec := renewReq(t, api, body, ip)
	if rec.Code != http.StatusOK {
		t.Fatalf("renew status = %d; %s", rec.Code, rec.Body)
	}
	var rr wire.RenewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &rr); err != nil {
		t.Fatal(err)
	}
	b, err := bundle.Verify(rr.Bundle, e.pinned)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Rides INSIDE the signed payload, sorted ascending (deterministic; no false drift).
	if got, want := strings.Join(b.Blocklist, ","), strings.Join([]string{lo, mid, hi}, ","); got != want {
		t.Fatalf("bundle blocklist = %v, want sorted [lo mid hi]", b.Blocklist)
	}
	// And it renders into nebula's pki.blocklist.
	cfg, err := bundle.RenderNebulaConfig(b, "/ca.crt", "/host.crt", "/host.key")
	if err != nil {
		t.Fatal(err)
	}
	s := string(cfg)
	if !strings.Contains(s, "blocklist:") {
		t.Fatalf("rendered config has no pki.blocklist:\n%s", s)
	}
	for _, fp := range []string{lo, mid, hi} {
		if !strings.Contains(s, fp) {
			t.Fatalf("rendered config missing fingerprint %s:\n%s", fp, s)
		}
	}

	// Tamper-evidence: the blocklist is signed, so flipping a byte is refused.
	tampered := make([]byte, len(rr.Bundle))
	copy(tampered, rr.Bundle)
	tampered[len(tampered)/2] ^= 0x01
	if _, err := bundle.Verify(tampered, e.pinned); err == nil {
		t.Fatal("tampered renew bundle (incl. blocklist) must be refused")
	}

	// Renew rotates the key -> the persisted fingerprint must be re-stamped.
	if post := issuedRow(t, e, ip).Fingerprint; post == "" || post == preRenewFP {
		t.Fatalf("renew did not update the persisted fingerprint (pre=%s post=%s)", preRenewFP, post)
	}
}

// issuedRow reloads the authoritative issued enrollment at an overlay IP.
func issuedRow(t *testing.T, e enrollEnv, ip string) enrollment.Enrollment {
	t.Helper()
	var row enrollment.Enrollment
	if err := e.store.DB.Where("overlay_ip = ? AND status = ?", ip, enrollment.StatusIssued).
		Order("id DESC").First(&row).Error; err != nil {
		t.Fatalf("reload issued enrollment at %s: %v", ip, err)
	}
	return row
}

// TestRenewRefusedForRevokedHost is the M7.1-durability fix: once a host's CURRENT
// fingerprint is blocklisted, coreapi.handleRenew refuses to re-sign it — so a revoked
// host cannot rotate to a fresh, un-blocklisted fingerprint and evade revocation. (Before
// the fix, renew authenticated by source IP + status='issued' only and never consulted
// the revocation registry, so this returned 200 with a new cert.)
func TestRenewRefusedForRevokedHost(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	api := e.coreAPI()

	// Enroll an ordinary 'web' host -> issued at an overlay IP with a persisted fingerprint.
	secret, _, _ := joinkey.Create(ctx, e.store, joinkey.Params{Name: "k", Groups: []string{"web"}, MaxUses: 0, AutoIssue: true}, time.Now())
	res, err := e.cons.Process(ctx, e.candidate(t, secret, "target"))
	if err != nil || res.Status != "issued" {
		t.Fatalf("enroll: %v %s", err, res.Status)
	}
	ip := res.OverlayIP
	fp := issuedRow(t, e, ip).Fingerprint

	// A renew BEFORE revocation succeeds (baseline).
	body, _ := signRenew(t)
	if rec := renewReq(t, api, body, ip); rec.Code != http.StatusOK {
		t.Fatalf("pre-revocation renew status = %d; %s", rec.Code, rec.Body)
	}
	// The renew rotated the fingerprint; blocklist the NEW current one.
	fp = issuedRow(t, e, ip).Fingerprint
	if _, err := e.rev.Add(ctx, fp, "compromised — REVOKE", "operator"); err != nil {
		t.Fatalf("blocklist add: %v", err)
	}

	// Now renew must be REFUSED (403 account_not_allowed) — the revoked host cannot mint a
	// fresh cert. And no new fingerprint was stamped (the device row is unchanged).
	body2, _ := signRenew(t)
	rec := renewReq(t, api, body2, ip)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("revoked renew status = %d, want 403; body=%s", rec.Code, rec.Body)
	}
	if post := issuedRow(t, e, ip).Fingerprint; post != fp {
		t.Fatalf("revoked renew rotated the fingerprint (%s -> %s) — it must not re-sign", fp, post)
	}
}

func TestRenewFromWrongIPRejected(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	api := e.coreAPI()
	secret, _, _ := joinkey.Create(ctx, e.store, joinkey.Params{Name: "k", Groups: []string{"web"}, MaxUses: 0, AutoIssue: true}, time.Now())
	if _, err := e.cons.Process(ctx, e.candidate(t, secret, "host-b")); err != nil {
		t.Fatal(err)
	}
	body, _ := signRenew(t)
	// A source IP with no enrolled device must be rejected (tunnel-identity auth).
	rec := renewReq(t, api, body, "100.64.7.7")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for unknown overlay IP", rec.Code)
	}
}
