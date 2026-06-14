package adminauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/adminapi"
	"github.com/jeks313/nebula-control-plane/internal/adminauth"
	"github.com/jeks313/nebula-control-plane/internal/adminauth/mockidp"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
	"golang.org/x/oauth2"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(t.TempDir() + "/auth.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	return s
}

func defaultRoleMapper() *adminauth.RoleMapper {
	return &adminauth.RoleMapper{
		GroupRoles: map[string][]string{
			"harbor-admins":    {adminapi.RoleAdmin},
			"harbor-operators": {adminapi.RoleOperator},
			"harbor-viewers":   {adminapi.RoleViewer},
		},
		DefaultRoles: []string{adminapi.RoleViewer},
	}
}

// noRedirect is an http.Client that surfaces 3xx instead of following them, so the
// test drives each hop of the OAuth dance explicitly.
func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func cookieByName(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestOIDCLoginEndToEnd drives the full browser flow against the in-process mock
// OIDC IdP: login redirect → IdP authorize → callback → session cookie → an
// authenticated /me carrying the mapped roles and MFA state. This exercises the
// REAL production OIDC authenticator (discovery, PKCE, JWKS verification, nonce).
func TestOIDCLoginEndToEnd(t *testing.T) {
	st := newStore(t)

	// Mock IdP.
	idp, err := mockidp.New(mockidp.DefaultUsers(), nil)
	if err != nil {
		t.Fatal(err)
	}
	idpSrv := httptest.NewServer(idp)
	defer idpSrv.Close()
	idp.SetIssuer(idpSrv.URL)

	// Harbor side: a server whose handler we set AFTER we know its own URL (the
	// OIDC redirect_uri must be absolute).
	var handler http.Handler
	harbor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	defer harbor.Close()

	oidc, err := adminauth.NewOIDC(context.Background(), adminauth.OIDCOptions{
		Issuer: idpSrv.URL, ClientID: "harbor-test", ClientSecret: "secret",
		RedirectURL: harbor.URL + "/admin/v1/auth/callback",
	})
	if err != nil {
		t.Fatalf("new oidc: %v", err)
	}
	svc := adminauth.New(adminauth.Config{
		Store:          adminauth.NewSessionStore(st.DB, nil),
		Authenticators: []adminauth.Authenticator{oidc},
		RoleMapper:     defaultRoleMapper(),
	})
	api := adminapi.New(adminapi.Config{Store: st, Identity: svc.Provider()})
	mux := http.NewServeMux()
	mux.Handle("/admin/v1/auth/", svc.Handler())
	mux.Handle("/", svc.CSRF(api.Handler()))
	handler = mux

	hc := noRedirect()

	// 1. Start login → 302 to the IdP authorize endpoint; capture the login cookie.
	resp := mustGet(t, hc, harbor.URL+"/admin/v1/auth/login?provider=oidc&return_to=/dashboard", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d, want 302", resp.StatusCode)
	}
	loginCookie := cookieByName(resp, "harbor_login")
	if loginCookie == nil {
		t.Fatal("no harbor_login cookie set")
	}
	authorizeURL := resp.Header.Get("Location")
	if !strings.HasPrefix(authorizeURL, idpSrv.URL) {
		t.Fatalf("login did not redirect to the IdP: %s", authorizeURL)
	}

	// 2. Authorize at the IdP as the admin user → 302 back to Harbor's callback.
	resp = mustGet(t, hc, authorizeURL+"&login_as=admin", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", resp.StatusCode)
	}
	callbackURL := resp.Header.Get("Location")
	if !strings.HasPrefix(callbackURL, harbor.URL) {
		t.Fatalf("authorize did not redirect to Harbor callback: %s", callbackURL)
	}

	// 3. Callback (carry the login cookie) → 302 to return_to, sets session+csrf.
	resp = mustGet(t, hc, callbackURL, []*http.Cookie{loginCookie})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status = %d, want 302; body hint: %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if loc := resp.Header.Get("Location"); loc != "/dashboard" {
		t.Fatalf("callback return_to = %q, want /dashboard", loc)
	}
	sess := cookieByName(resp, "harbor_session")
	csrf := cookieByName(resp, "harbor_csrf")
	if sess == nil || sess.Value == "" || !sess.HttpOnly {
		t.Fatalf("session cookie missing or not httpOnly: %+v", sess)
	}
	if csrf == nil || csrf.Value == "" || csrf.HttpOnly {
		t.Fatalf("csrf cookie missing or httpOnly (must be JS-readable): %+v", csrf)
	}

	// 4. The session authenticates /me with the mapped roles + MFA.
	resp = mustGet(t, hc, harbor.URL+"/admin/v1/me", []*http.Cookie{sess})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/me status = %d, want 200", resp.StatusCode)
	}
	var me struct {
		Principal string     `json:"principal"`
		Roles     []string   `json:"roles"`
		MFAAt     *time.Time `json:"mfa_satisfied_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if me.Principal != "ada.admin@harbor.test" {
		t.Fatalf("principal = %q", me.Principal)
	}
	if !contains(me.Roles, adminapi.RoleAdmin) {
		t.Fatalf("roles = %v, want admin", me.Roles)
	}
	if me.MFAAt == nil {
		t.Fatal("admin user asserted MFA but mfa_satisfied_at is nil")
	}

	// 5. No session → 401.
	resp = mustGet(t, hc, harbor.URL+"/admin/v1/me", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/me without session = %d, want 401", resp.StatusCode)
	}

	// 6. Logout revokes the session.
	logout, _ := http.NewRequest(http.MethodPost, harbor.URL+"/admin/v1/auth/logout", nil)
	logout.AddCookie(sess)
	lresp, err := hc.Do(logout)
	if err != nil {
		t.Fatal(err)
	}
	lresp.Body.Close()
	resp = mustGet(t, hc, harbor.URL+"/admin/v1/me", []*http.Cookie{sess})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/me after logout = %d, want 401", resp.StatusCode)
	}
}

// TestSessionStore covers mint → lookup → expiry → revoke.
func TestSessionStore(t *testing.T) {
	st := newStore(t)
	now := time.Unix(1_700_000_000, 0)
	ss := adminauth.NewSessionStore(st.DB, func() time.Time { return now })
	subj := adminauth.Subject{ID: "u1", Email: "u1@x.test", Name: "U One"}

	token, csrf, err := ss.Mint(context.Background(), subj, "mock", []string{"admin"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || csrf == "" || token == csrf {
		t.Fatal("token/csrf must be distinct non-empty secrets")
	}
	got, err := ss.Lookup(context.Background(), token)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got.Principal != "u1@x.test" || got.CSRFToken != csrf {
		t.Fatalf("session mismatch: %+v", got)
	}
	// A made-up token never resolves.
	if _, err := ss.Lookup(context.Background(), "not-a-real-token"); !errors.Is(err, adminauth.ErrNoSession) {
		t.Fatalf("bogus token err = %v, want ErrNoSession", err)
	}
	// Past expiry → ErrNoSession.
	now = now.Add(2 * time.Hour)
	if _, err := ss.Lookup(context.Background(), token); !errors.Is(err, adminauth.ErrNoSession) {
		t.Fatalf("expired lookup err = %v, want ErrNoSession", err)
	}
	// Revoke is idempotent.
	if err := ss.Revoke(context.Background(), token); err != nil {
		t.Fatalf("revoke: %v", err)
	}
}

// TestRoleMapper checks group→role mapping + the read-only default + dedup.
func TestRoleMapper(t *testing.T) {
	m := defaultRoleMapper()
	roles := m.Roles([]string{"harbor-admins", "unmapped-group"})
	if !contains(roles, "admin") || !contains(roles, "viewer") {
		t.Fatalf("admin group → %v, want admin + default viewer", roles)
	}
	// An authenticated user in no mapped group still gets the read-only default.
	if got := m.Roles(nil); len(got) != 1 || got[0] != "viewer" {
		t.Fatalf("no groups → %v, want [viewer]", got)
	}
	// A fail-closed mapper with no default grants nothing.
	empty := &adminauth.RoleMapper{}
	if got := empty.Roles([]string{"harbor-admins"}); len(got) != 0 {
		t.Fatalf("empty mapper → %v, want none", got)
	}
}

// TestGitHubExchange stubs the GitHub token + API and checks identity + org/team
// groups (GitHub is OAuth2, identity via the API — not an ID token).
func TestGitHubExchange(t *testing.T) {
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"gho_test","token_type":"bearer"}`))
		case "/user":
			// Note: /user.email here is the unverified profile email — must be ignored.
			_, _ = w.Write([]byte(`{"login":"octocat","id":583231,"name":"The Octocat","email":"spoofed@evil.test"}`))
		case "/user/emails":
			_, _ = w.Write([]byte(`[{"email":"unverified@x.test","primary":false,"verified":false},{"email":"octo@github.test","primary":true,"verified":true}]`))
		case "/user/teams":
			_, _ = w.Write([]byte(`[{"slug":"harbor-admins","organization":{"login":"acme"}}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer gh.Close()

	auth := adminauth.NewGitHub(adminauth.GitHubOptions{
		ClientID: "id", ClientSecret: "secret", RedirectURL: "http://h/cb",
		APIBase:  gh.URL,
		Endpoint: oauth2.Endpoint{AuthURL: gh.URL + "/login/oauth/authorize", TokenURL: gh.URL + "/login/oauth/access_token"},
	})
	subj, err := auth.Exchange(context.Background(), "code123", "", "")
	if err != nil {
		t.Fatalf("github exchange: %v", err)
	}
	// Identity uses the immutable numeric id; Email is the VERIFIED primary from
	// /user/emails, never the spoofable /user.email.
	if subj.ID != "github:583231" {
		t.Fatalf("subject id = %q", subj.ID)
	}
	if subj.Email != "octo@github.test" {
		t.Fatalf("email = %q, want the verified primary (not the /user profile email)", subj.Email)
	}
	if !contains(subj.Groups, "acme/harbor-admins") || !contains(subj.Groups, "acme") {
		t.Fatalf("groups = %v, want org + org/team", subj.Groups)
	}
	// GitHub groups are org-prefixed ("org" and "org/team"), so they map via
	// GitHub-shaped entries — mapping a whole org, or a specific team.
	ghMapper := &adminauth.RoleMapper{
		GroupRoles:   map[string][]string{"acme/harbor-admins": {adminapi.RoleAdmin}},
		DefaultRoles: []string{adminapi.RoleViewer},
	}
	if roles := ghMapper.Roles(subj.Groups); !contains(roles, "admin") {
		t.Fatalf("github admin team → roles %v, want admin", roles)
	}
}

// TestCSRF: the session-bound double-submit guard rejects mutations unless the
// X-CSRF-Token header matches the caller's SESSION token (not merely a cookie).
func TestCSRF(t *testing.T) {
	st := newStore(t)
	ss := adminauth.NewSessionStore(st.DB, nil)
	svc := adminauth.New(adminauth.Config{Store: ss, RoleMapper: defaultRoleMapper()})
	token, csrf, err := ss.Mint(context.Background(), adminauth.Subject{ID: "u1", Email: "u1@x.test"}, "mock", []string{"admin"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessCookie := &http.Cookie{Name: "harbor_session", Value: token}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := svc.CSRF(next)

	post := func(cookies []*http.Cookie, header string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		if header != "" {
			req.Header.Set("X-CSRF-Token", header)
		}
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// GET passes (safe method).
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("GET blocked: %d", rec.Code)
	}
	// POST, valid session + matching session token → passes.
	if code := post([]*http.Cookie{sessCookie}, csrf); code != http.StatusTeapot {
		t.Fatalf("POST with valid session token = %d, want 418", code)
	}
	// POST with no session → 403.
	if code := post(nil, csrf); code != http.StatusForbidden {
		t.Fatalf("POST without session = %d, want 403", code)
	}
	// POST with session but no header → 403.
	if code := post([]*http.Cookie{sessCookie}, ""); code != http.StatusForbidden {
		t.Fatalf("POST without header = %d, want 403", code)
	}
	// POST with a forged (cookie-injected) token that doesn't match the session → 403.
	if code := post([]*http.Cookie{sessCookie}, "forged-token"); code != http.StatusForbidden {
		t.Fatalf("POST with forged token = %d, want 403", code)
	}
}

// TestOIDCStepUpAuthURL: step-up login forces a fresh authentication
// (prompt=login + max_age=0) so the IdP re-applies its MFA policy; a normal login
// does not.
func TestOIDCStepUpAuthURL(t *testing.T) {
	idp, err := mockidp.New(mockidp.DefaultUsers(), nil)
	if err != nil {
		t.Fatal(err)
	}
	idpSrv := httptest.NewServer(idp)
	defer idpSrv.Close()
	idp.SetIssuer(idpSrv.URL)

	oidc, err := adminauth.NewOIDC(context.Background(), adminauth.OIDCOptions{
		Issuer: idpSrv.URL, ClientID: "c", ClientSecret: "s", RedirectURL: "http://h/admin/v1/auth/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	normal := oidc.AuthURL("st", "no", "vf", false)
	if strings.Contains(normal, "prompt=login") || strings.Contains(normal, "max_age=0") {
		t.Fatalf("normal login must not force re-auth: %s", normal)
	}
	stepUp := oidc.AuthURL("st", "no", "vf", true)
	if !strings.Contains(stepUp, "prompt=login") || !strings.Contains(stepUp, "max_age=0") {
		t.Fatalf("step-up login must force re-auth (prompt=login&max_age=0): %s", stepUp)
	}
}

func mustGet(t *testing.T, hc *http.Client, url string, cookies []*http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
