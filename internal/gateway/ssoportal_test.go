package gateway

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/adminauth"
	"github.com/jeks313/nebula-control-plane/internal/adminauth/samlmock"
	"github.com/jeks313/nebula-control-plane/internal/nonce"
	"github.com/jeks313/nebula-control-plane/internal/queue"
	"github.com/jeks313/nebula-control-plane/internal/ssoassert"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

// ── test scaffolding (mirrors internal/adminauth/saml_test.go) ──────────────────

func genKeyCert(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

var (
	reAction   = regexp.MustCompile(`action="([^"]*)"`)
	reSAMLResp = regexp.MustCompile(`name="SAMLResponse" value="([^"]*)"`)
	reRelay    = regexp.MustCompile(`name="RelayState" value="([^"]*)"`)
)

func parseSAMLForm(t *testing.T, body string) (action, samlResp, relay string) {
	t.Helper()
	sub := func(re *regexp.Regexp) string {
		m := re.FindStringSubmatch(body)
		if len(m) < 2 {
			return ""
		}
		return html.UnescapeString(m[1])
	}
	action, samlResp, relay = sub(reAction), sub(reSAMLResp), sub(reRelay)
	if action == "" || samlResp == "" {
		t.Fatalf("could not parse SAML auto-POST form from IdP response:\n%s", body)
	}
	return action, samlResp, relay
}

func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// portalFixture wires a gateway with the SSO portal enabled against an in-process mock
// SAML IdP, exactly the way adminauth's SAML test wires its SP.
type portalFixture struct {
	gwSrv    *httptest.Server
	idpSrv   *httptest.Server
	ring     *nonce.Keyring
	signPriv *ecdsa.PrivateKey
	signPub  *ecdsa.PublicKey
}

func newPortalFixture(t *testing.T, sso *SSOConfig, nonceKey []byte) *portalFixture {
	t.Helper()
	idpKey, idpCert := genKeyCert(t)
	spKey, spCert := genKeyCert(t)

	var idpHandler http.Handler
	idpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idpHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(idpSrv.Close)

	mock, err := samlmock.New(idpSrv.URL, idpKey, idpCert, map[string]samlmock.User{
		"engineer": {Email: "dev@corp.test", Name: "Dev Eng", Groups: []string{"corp-eng"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	idpHandler = mock.Handler()

	var gwHandler http.Handler
	gwSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gwHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(gwSrv.Close)

	samlAuth, err := adminauth.NewSAML(adminauth.SAMLOptions{
		BaseURL: gwSrv.URL, IDPMetadata: mock.Metadata(),
		Key: spKey, Certificate: spCert, GroupsAttr: "groups",
		// The SP's declared ACS is the portal's route, so the IdP auto-POSTs there.
		ACSPath: "/v1/sso/acs", MetadataPath: "/v1/sso/metadata",
	})
	if err != nil {
		t.Fatalf("new saml: %v", err)
	}
	mock.SetSP(samlAuth.SPMetadata())

	signPriv, err := ssoassert.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	if len(nonceKey) == 0 {
		nonceKey = make([]byte, 32)
	}
	ring, err := nonce.NewKeyring([][]byte{nonceKey}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	if sso != nil {
		if sso.SAML == nil {
			sso.SAML = samlAuth
		}
		if sso.SigningKey == nil {
			sso.SigningKey = signPriv
		}
	}
	gw := New(Config{Nonces: ring, Queue: queue.NewMemory(), SSO: sso})
	gwHandler = gw.Handler()

	return &portalFixture{
		gwSrv: gwSrv, idpSrv: idpSrv, ring: ring,
		signPriv: signPriv, signPub: &signPriv.PublicKey,
	}
}

// driveSAML carries an SSO-start through the mock IdP and returns the auto-POST form
// fields (ACS action, signed SAMLResponse, RelayState) the IdP would have the browser
// POST back to the gateway ACS.
func (f *portalFixture) driveSAML(t *testing.T, hc *http.Client, startURL string) (samlResp, relay string) {
	t.Helper()
	resp := mustGet(t, hc, startURL)
	if resp.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("start status = %d, want 302; body=%s", resp.StatusCode, b)
	}
	ssoURL := resp.Header.Get("Location")
	resp.Body.Close()
	if !strings.HasPrefix(ssoURL, f.idpSrv.URL) {
		t.Fatalf("start did not redirect to the IdP: %s", ssoURL)
	}
	resp = mustGet(t, hc, ssoURL+"&login_as=engineer")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("IdP SSO status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	_, samlResp, relay = parseSAMLForm(t, string(body))
	return samlResp, relay
}

func mustGet(t *testing.T, hc *http.Client, u string) *http.Response {
	t.Helper()
	resp, err := hc.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// respCode extracts the wire error code from a live *http.Response body.
func respCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	var b struct {
		Error wire.Error `json:"error"`
	}
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &b)
	return b.Error.Code
}

// startURL builds a /v1/sso/start URL for a freshly-minted nonce bound to pubkeyHash.
func (f *portalFixture) startURL(pubkeyHash, redirect string) string {
	n, _ := f.ring.Mint([]byte(pubkeyHash))
	v := url.Values{"pubkey_hash": {pubkeyHash}, "nonce": {n}, "redirect": {redirect}}
	return f.gwSrv.URL + "/v1/sso/start?" + v.Encode()
}

// acsPost POSTs a SAMLResponse + RelayState to the gateway ACS.
func acsPost(t *testing.T, hc *http.Client, acsURL, samlResp, relay string) *http.Response {
	t.Helper()
	form := url.Values{"SAMLResponse": {samlResp}, "RelayState": {relay}}
	req, _ := http.NewRequest(http.MethodPost, acsURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// ── tests ───────────────────────────────────────────────────────────────────────

// TestSSOPortalRoundTrip drives the full SAML loopback flow and verifies the gateway
// hands back a correctly-bound, signed assertion: start (binds pubkey+nonce) → mock IdP
// → ACS → 302 to the loopback redirect carrying the assertion → ssoassert.Verify with
// the pinned public key confirms PubkeyHash/Nonce/Groups/Issuer match the session.
func TestSSOPortalRoundTrip(t *testing.T) {
	f := newPortalFixture(t, &SSOConfig{Issuer: "corp"}, nil)
	hc := noRedirect()

	const pkh = "pkh-device-1"
	const redirect = "http://127.0.0.1:53120/callback"
	su := f.startURL(pkh, redirect)
	// Recover the nonce we minted so we can assert it round-trips into the assertion.
	startQuery, _ := url.Parse(su)
	wantNonce := startQuery.Query().Get("nonce")

	samlResp, relay := f.driveSAML(t, hc, su)

	resp := acsPost(t, hc, f.gwSrv.URL+"/v1/sso/acs", samlResp, relay)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("ACS status = %d, want 302; body=%s", resp.StatusCode, b)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Scheme != "http" || loc.Hostname() != "127.0.0.1" || loc.Port() != "53120" || loc.Path != "/callback" {
		t.Fatalf("ACS did not redirect to the loopback redirect: %s", loc)
	}
	if got := loc.Query().Get("state"); got != relay {
		t.Fatalf("loopback state = %q, want the RelayState %q", got, relay)
	}
	token := loc.Query().Get("assertion")
	if token == "" {
		t.Fatal("no assertion handed to the loopback redirect")
	}

	a, err := ssoassert.Verify(f.signPub, []byte(token), time.Now())
	if err != nil {
		t.Fatalf("ssoassert.Verify with the pinned public key failed: %v", err)
	}
	if a.PubkeyHash != pkh {
		t.Errorf("assertion PubkeyHash = %q, want the session's %q", a.PubkeyHash, pkh)
	}
	if a.Nonce != wantNonce {
		t.Errorf("assertion Nonce = %q, want the session's %q", a.Nonce, wantNonce)
	}
	if a.Issuer != "corp" {
		t.Errorf("assertion Issuer = %q, want corp", a.Issuer)
	}
	if a.Email != "dev@corp.test" {
		t.Errorf("assertion Email = %q, want dev@corp.test", a.Email)
	}
	if len(a.IdPGroups) != 1 || a.IdPGroups[0] != "corp-eng" {
		t.Errorf("assertion IdPGroups = %v, want [corp-eng]", a.IdPGroups)
	}
	if a.ExpiresAt <= a.IssuedAt || a.ExpiresAt-a.IssuedAt > int64((10*time.Minute).Seconds()) {
		t.Errorf("assertion window iat=%d exp=%d not a short forward window", a.IssuedAt, a.ExpiresAt)
	}
}

// TestSSOPortalStartBindsPubkeyNonce checks the start route validates the nonce binding:
// a nonce minted for a different pubkey is rejected, and a missing redirect is rejected,
// so no session can be created that isn't bound to a fresh, pubkey-bound nonce.
func TestSSOPortalStartBindsPubkeyNonce(t *testing.T) {
	f := newPortalFixture(t, &SSOConfig{}, nil)
	hc := noRedirect()

	// Nonce minted for someone else, spliced onto our pubkey_hash → invalid nonce.
	otherNonce, _ := f.ring.Mint([]byte("some-other-device"))
	v := url.Values{"pubkey_hash": {"pkh-1"}, "nonce": {otherNonce}, "redirect": {"http://127.0.0.1:9/cb"}}
	resp := mustGet(t, hc, f.gwSrv.URL+"/v1/sso/start?"+v.Encode())
	code := respCode(t, resp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || code != wire.CodeInvalidNonce {
		t.Fatalf("mismatched-nonce start: status=%d code=%s, want 401 %s", resp.StatusCode, code, wire.CodeInvalidNonce)
	}

	// Missing redirect → invalid request (no session minted).
	n, _ := f.ring.Mint([]byte("pkh-1"))
	v2 := url.Values{"pubkey_hash": {"pkh-1"}, "nonce": {n}}
	resp2 := mustGet(t, hc, f.gwSrv.URL+"/v1/sso/start?"+v2.Encode())
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing-redirect start: status=%d, want 400", resp2.StatusCode)
	}
}

// TestSSOPortalRejectsUsedAndUnknownSession proves the session is single-use and that an
// unknown/forged RelayState is rejected: replaying the same SAMLResponse a second time
// finds no session and is denied.
func TestSSOPortalRejectsUsedAndUnknownSession(t *testing.T) {
	f := newPortalFixture(t, &SSOConfig{}, nil)
	hc := noRedirect()

	samlResp, relay := f.driveSAML(t, hc, f.startURL("pkh-dev", "http://localhost:7777/cb"))

	// First ACS succeeds (consumes the session).
	resp := acsPost(t, hc, f.gwSrv.URL+"/v1/sso/acs", samlResp, relay)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("first ACS status = %d, want 302", resp.StatusCode)
	}
	// Replay with the SAME RelayState → session already consumed → rejected.
	resp2 := acsPost(t, hc, f.gwSrv.URL+"/v1/sso/acs", samlResp, relay)
	defer resp2.Body.Close()
	if resp2.StatusCode == http.StatusFound {
		t.Fatal("ACS accepted a replay of an already-used session")
	}

	// A forged/unknown RelayState (no server-side session) is rejected.
	resp3 := acsPost(t, hc, f.gwSrv.URL+"/v1/sso/acs", samlResp, "totally-made-up-state")
	defer resp3.Body.Close()
	if resp3.StatusCode == http.StatusFound {
		t.Fatal("ACS accepted an unknown RelayState (no bound session)")
	}
}

// TestSSOPortalRejectsExpiredSession proves an expired session is rejected at the ACS
// even with an otherwise-valid SAMLResponse.
func TestSSOPortalRejectsExpiredSession(t *testing.T) {
	// 1ns session TTL so the session is dead by the time the IdP round-trip returns.
	f := newPortalFixture(t, &SSOConfig{SessionTTL: time.Nanosecond}, nil)
	hc := noRedirect()

	samlResp, relay := f.driveSAML(t, hc, f.startURL("pkh-dev", "http://127.0.0.1:8080/cb"))
	resp := acsPost(t, hc, f.gwSrv.URL+"/v1/sso/acs", samlResp, relay)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		t.Fatal("ACS accepted an expired session")
	}
}

// TestSSOPortalRejectsNonLoopbackRedirect proves the start route refuses any redirect
// that does not target loopback — the open-redirect / assertion-exfil guard.
func TestSSOPortalRejectsNonLoopbackRedirect(t *testing.T) {
	f := newPortalFixture(t, &SSOConfig{}, nil)
	hc := noRedirect()

	bad := []string{
		"http://evil.example.com/cb",
		"https://10.0.0.5/cb",
		"http://127.0.0.1.evil.com/cb",
		"ftp://127.0.0.1/cb",
		"http://user:pass@127.0.0.1/cb",
		"/cb",
		"not-a-url-%zz",
	}
	for _, redirect := range bad {
		n, _ := f.ring.Mint([]byte("pkh-1"))
		v := url.Values{"pubkey_hash": {"pkh-1"}, "nonce": {n}, "redirect": {redirect}}
		resp := mustGet(t, hc, f.gwSrv.URL+"/v1/sso/start?"+v.Encode())
		got := resp.StatusCode
		resp.Body.Close()
		if got == http.StatusFound {
			t.Errorf("start accepted a non-loopback redirect %q", redirect)
		}
	}
}

// TestSSOPortalDisabledWhenUnconfigured proves the portal routes return 404 "SSO not
// enabled" when SSO is not configured, and that the rest of the gateway still works.
func TestSSOPortalDisabledWhenUnconfigured(t *testing.T) {
	h, _, _ := newTest(t) // no SSO config at all
	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodGet, "/v1/sso/start?pubkey_hash=x&nonce=y&redirect=http://127.0.0.1/cb"},
		{http.MethodPost, "/v1/sso/acs"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s status = %d, want 404 (SSO disabled)", tc.method, tc.path, rec.Code)
		}
	}
	// Sanity: the unrelated nonce route is unaffected.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/nonce?binding=abc", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("nonce route should be unaffected by SSO config; status=%d", rec.Code)
	}
}

// TestSSOPortalPartialConfigDisabled proves SSO stays disabled if only one of the two
// required pieces (SAML SP / signing key) is supplied — fail closed.
func TestSSOPortalPartialConfigDisabled(t *testing.T) {
	signPriv, err := ssoassert.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ring, err := nonce.NewKeyring([][]byte{make([]byte, 32)}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Signing key but no SAML SP.
	gw := New(Config{Nonces: ring, Queue: queue.NewMemory(), SSO: &SSOConfig{SigningKey: signPriv}})
	rec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/sso/acs", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("partial SSO config (no SAML) should be disabled; status=%d", rec.Code)
	}
}
