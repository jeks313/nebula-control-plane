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
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/wire"
	"github.com/slackhq/nebula/cert"
)

func (e enrollEnv) coreAPI() http.Handler {
	return coreapi.New(coreapi.Config{
		Store: e.store, Signer: e.sg, ConfigBackend: e.cfgB, ConfigKeyID: e.configKeyID,
		CABundlePEM: e.caPEM, Pool: e.pool, CertLifetime: 24 * time.Hour,
		Lighthouses: []bundle.Lighthouse{{OverlayIP: "100.64.0.1", PublicAddrs: []string{"1.2.3.4:4242"}}},
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
