package adminauth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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

	"github.com/jeks313/nebula-control-plane/internal/adminapi"
	"github.com/jeks313/nebula-control-plane/internal/adminauth"
	"github.com/jeks313/nebula-control-plane/internal/adminauth/samlmock"
)

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

var reAction = regexp.MustCompile(`action="([^"]*)"`)
var reSAMLResp = regexp.MustCompile(`name="SAMLResponse" value="([^"]*)"`)
var reRelay = regexp.MustCompile(`name="RelayState" value="([^"]*)"`)

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

// TestSAMLLoginEndToEnd drives the full SP-initiated SAML flow against the
// in-process mock IdP: AuthnRequest redirect → IdP signs a real assertion → the
// SP's ACS validates it (signature/conditions/audience/InResponseTo) → session →
// an authenticated /me carrying the NameID principal + the attribute-mapped roles.
func TestSAMLLoginEndToEnd(t *testing.T) {
	st := newStore(t)
	idpKey, idpCert := genKeyCert(t)
	spKey, spCert := genKeyCert(t)

	// Mock SAML IdP (handler set after we know the server URL).
	var idpHandler http.Handler
	idpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idpHandler.ServeHTTP(w, r)
	}))
	defer idpSrv.Close()
	mock, err := samlmock.New(idpSrv.URL, idpKey, idpCert, map[string]samlmock.User{
		"admin":  {Email: "ada@harbor.test", Name: "Ada Admin", Groups: []string{"harbor-admins"}},
		"viewer": {Email: "vera@harbor.test", Name: "Vera Viewer", Groups: []string{"harbor-viewers"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	idpHandler = mock.Handler()

	// Harbor side (handler set after we know its own URL — ACS must be absolute).
	var handler http.Handler
	harbor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	defer harbor.Close()

	samlAuth, err := adminauth.NewSAML(adminauth.SAMLOptions{
		BaseURL: harbor.URL, IDPMetadata: mock.Metadata(),
		Key: spKey, Certificate: spCert, GroupsAttr: "groups",
	})
	if err != nil {
		t.Fatalf("new saml: %v", err)
	}
	mock.SetSP(samlAuth.SPMetadata()) // the IdP now trusts + targets this SP

	svc, svcErr := adminauth.New(adminauth.Config{
		Store:              adminauth.NewSessionStore(st.DB, nil),
		FlowAuthenticators: []adminauth.FlowAuthenticator{samlAuth},
		RoleMapper:         defaultRoleMapper(),
	})
	if svcErr != nil {
		t.Fatal(svcErr)
	}
	api := adminapi.New(adminapi.Config{Store: st, Identity: svc.Provider()})
	mux := http.NewServeMux()
	mux.Handle("/admin/v1/auth/", svc.Handler())
	mux.Handle("/", svc.CSRF(api.Handler()))
	handler = mux

	hc := noRedirect()

	// 1. Start SAML login → 302 to the IdP SSO endpoint; capture the login cookie.
	resp := mustGet(t, hc, harbor.URL+"/admin/v1/auth/login?provider=saml&return_to=/dash", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d, want 302", resp.StatusCode)
	}
	samlCookie := cookieByName(resp, "harbor_saml_login_saml")
	if samlCookie == nil {
		t.Fatal("no SAML login cookie set")
	}
	ssoURL := resp.Header.Get("Location")
	if !strings.HasPrefix(ssoURL, idpSrv.URL) {
		t.Fatalf("login did not redirect to the IdP: %s", ssoURL)
	}

	// 2. Authenticate at the IdP as admin → an auto-POST form targeting the ACS.
	resp = mustGet(t, hc, ssoURL+"&login_as=admin", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("IdP SSO status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	action, samlResp, relay := parseSAMLForm(t, string(body))
	if !strings.HasPrefix(action, harbor.URL) {
		t.Fatalf("ACS action %q is not the SP", action)
	}

	// 3. POST the signed assertion to the ACS (carry the login cookie) → session.
	form := url.Values{"SAMLResponse": {samlResp}, "RelayState": {relay}}
	req, _ := http.NewRequest(http.MethodPost, action, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(samlCookie)
	resp, err = hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("ACS status = %d, want 302; body: %s", resp.StatusCode, b)
	}
	if loc := resp.Header.Get("Location"); loc != "/dash" {
		t.Fatalf("ACS return_to = %q, want /dash", loc)
	}
	sess := cookieByName(resp, "harbor_session")
	if sess == nil || sess.Value == "" {
		t.Fatal("no session cookie after SAML login")
	}

	// 4. The session authenticates /me with the SAML identity + mapped roles.
	resp = mustGet(t, hc, harbor.URL+"/admin/v1/me", []*http.Cookie{sess})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/me status = %d, want 200", resp.StatusCode)
	}
	var me struct {
		Principal string   `json:"principal"`
		Roles     []string `json:"roles"`
	}
	decodeJSON(t, resp, &me)
	if me.Principal != "ada@harbor.test" {
		t.Fatalf("principal = %q, want the SAML NameID", me.Principal)
	}
	if !contains(me.Roles, adminapi.RoleAdmin) {
		t.Fatalf("roles = %v, want admin (from the groups attribute)", me.Roles)
	}

	// 5. A replay of the same assertion is rejected (InResponseTo no longer valid:
	//    the login cookie was single-use and is now cleared).
	req2, _ := http.NewRequest(http.MethodPost, action, strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp2, err := hc.Do(req2) // no login cookie this time
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusFound {
		t.Fatal("ACS accepted a SAML POST with no login state — replay/forgery not rejected")
	}

	// 6. A FORGED login cookie is rejected. The login cookie is HMAC-signed, so an
	//    attacker-crafted {id:"",...} (which would otherwise neutralize InResponseTo
	//    and admit unsolicited assertions) fails verification → no session.
	forgedPayload, _ := json.Marshal(map[string]string{"id": "", "rs": relay, "r": "/"})
	forged := base64.RawURLEncoding.EncodeToString(forgedPayload) + ".Ym9ndXM" // bogus MAC
	req3, _ := http.NewRequest(http.MethodPost, action, strings.NewReader(form.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req3.AddCookie(&http.Cookie{Name: "harbor_saml_login_saml", Value: forged})
	resp3, err := hc.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode == http.StatusFound {
		t.Fatal("ACS accepted a FORGED (unsigned) login cookie — tamper-evidence broken")
	}
}

func decodeJSON(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}
