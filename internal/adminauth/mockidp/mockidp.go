// Package mockidp is a minimal but REAL OpenID Connect provider for dev and tests.
// It implements discovery, JWKS, /authorize, and /token, signs genuine ES256 ID
// tokens, and verifies PKCE — so Harbor's production OIDC authenticator
// (internal/adminauth) is exercised end-to-end against it, with no external IdP.
//
// It is a stand-in for a real IdP (Entra, Okta, AD FS, Keycloak), NOT a security
// component: it trusts whoever clicks a user on its login page. It must only be
// run for local development and CI, exactly like the -dev-auth seam.
package mockidp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// User is a seeded mock identity selectable on the login page.
type User struct {
	Key    string   // selector key (the button)
	Sub    string   // OIDC subject
	Email  string   // email claim
	Name   string   // name claim
	Groups []string // groups claim (mapped to Harbor roles by the RP)
	MFA    bool     // assert amr:[pwd,mfa] (exercises MFA detection)
}

// DefaultUsers are seeded so the mesh's RoleMapper can map them to admin/operator/
// viewer out of the box.
func DefaultUsers() []User {
	return []User{
		{Key: "admin", Sub: "u-admin", Email: "ada.admin@harbor.test", Name: "Ada Admin", Groups: []string{"harbor-admins"}, MFA: true},
		{Key: "operator", Sub: "u-op", Email: "otto.operator@harbor.test", Name: "Otto Operator", Groups: []string{"harbor-operators"}, MFA: true},
		{Key: "viewer", Sub: "u-view", Email: "vera.viewer@harbor.test", Name: "Vera Viewer", Groups: []string{"harbor-viewers"}, MFA: false},
	}
}

// Provider is the mock OIDC server (an http.Handler).
type Provider struct {
	issuer string
	users  map[string]User
	order  []string
	priv   *ecdsa.PrivateKey
	signer jose.Signer
	kid    string
	now    func() time.Time
}

// New builds a Provider with a fresh signing key. Call SetIssuer once the listen
// URL is known (it must equal the issuer the RP discovers).
func New(users []User, now func() time.Time) (*Provider, error) {
	if now == nil {
		now = time.Now
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mockidp: keygen: %w", err)
	}
	kid := "mock-1"
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: priv, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return nil, fmt.Errorf("mockidp: signer: %w", err)
	}
	p := &Provider{users: map[string]User{}, priv: priv, signer: signer, kid: kid, now: now}
	for _, u := range users {
		p.users[u.Key] = u
		p.order = append(p.order, u.Key)
	}
	return p, nil
}

// SetIssuer pins the external base URL (e.g. the httptest server URL). Discovery
// advertises this exact string, which the RP must use as its issuer.
func (p *Provider) SetIssuer(base string) { p.issuer = base }

// Handler routes the OIDC endpoints.
func (p *Provider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	return mux
}

// ServeHTTP lets the Provider be used directly as a handler.
func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) { p.Handler().ServeHTTP(w, r) }

func (p *Provider) discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                p.issuer,
		"authorization_endpoint":                p.issuer + "/authorize",
		"token_endpoint":                        p.issuer + "/token",
		"jwks_uri":                              p.issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
		"claims_supported":                      []string{"sub", "email", "name", "groups", "aud", "iss", "exp", "iat", "nonce", "amr", "auth_time"},
	})
}

func (p *Provider) jwks(w http.ResponseWriter, r *http.Request) {
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: p.priv.Public(), KeyID: p.kid, Algorithm: "ES256", Use: "sig",
	}}}
	writeJSON(w, set)
}

// authCode is the stateless authorization code: it carries the chosen user, the
// RP nonce, and the PKCE challenge so /token can verify without server state.
type authCode struct {
	User      string `json:"u"`
	Nonce     string `json:"n"`
	Challenge string `json:"c"`
	Aud       string `json:"a"`
}

// authorize shows a login page; once a user is chosen (login_as) it issues a code
// and redirects back to the RP.
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	loginAs := q.Get("login_as")
	if loginAs == "" {
		p.loginPage(w, r)
		return
	}
	u, ok := p.users[loginAs]
	if !ok {
		http.Error(w, "unknown user", http.StatusBadRequest)
		return
	}
	code, err := encodeCode(authCode{User: u.Key, Nonce: q.Get("nonce"), Challenge: q.Get("code_challenge"), Aud: q.Get("client_id")})
	if err != nil {
		http.Error(w, "encode code", http.StatusInternalServerError)
		return
	}
	dest, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	rq := dest.Query()
	rq.Set("code", code)
	rq.Set("state", state)
	dest.RawQuery = rq.Encode()
	http.Redirect(w, r, dest.String(), http.StatusFound)
}

// loginPage renders the user picker, preserving the RP's authorize params.
func (p *Provider) loginPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>Mock IdP — Harbor</title>`+
		`<style>body{font:16px system-ui;margin:3rem auto;max-width:30rem}a{display:block;padding:.8rem 1rem;margin:.5rem 0;border:1px solid #ccc;border-radius:.5rem;text-decoration:none;color:#111}a:hover{background:#f3f4f6}small{color:#666}</style>`+
		`</head><body><h1>Mock IdP</h1><p><small>Dev/CI only — pick an identity to sign in to Harbor.</small></p>`)
	for _, key := range p.order {
		u := p.users[key]
		nq := url.Values{}
		for k, vs := range q {
			for _, v := range vs {
				nq.Add(k, v)
			}
		}
		nq.Set("login_as", key)
		mfa := ""
		if u.MFA {
			mfa = " · MFA"
		}
		fmt.Fprintf(w, `<a href="/authorize?%s"><b>%s</b><br><small>%s — groups: %v%s</small></a>`,
			nq.Encode(), htmlEscape(u.Name), htmlEscape(u.Email), u.Groups, mfa)
	}
	fmt.Fprint(w, `</body></html>`)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, "invalid_request")
		return
	}
	ac, err := decodeCode(r.Form.Get("code"))
	if err != nil {
		tokenError(w, "invalid_grant")
		return
	}
	// Verify PKCE if the RP used it (Harbor's OIDC authenticator always does).
	if ac.Challenge != "" {
		if !verifyPKCE(r.Form.Get("code_verifier"), ac.Challenge) {
			tokenError(w, "invalid_grant")
			return
		}
	}
	u, ok := p.users[ac.User]
	if !ok {
		tokenError(w, "invalid_grant")
		return
	}
	idToken, err := p.signIDToken(u, ac)
	if err != nil {
		tokenError(w, "server_error")
		return
	}
	writeJSON(w, map[string]any{
		"access_token": "mock-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func (p *Provider) signIDToken(u User, ac authCode) (string, error) {
	now := p.now()
	amr := []string{"pwd"}
	var authTime int64
	if u.MFA {
		amr = []string{"pwd", "mfa"}
		authTime = now.Unix()
	}
	claims := map[string]any{
		"iss":    p.issuer,
		"aud":    ac.Aud,
		"sub":    u.Sub,
		"email":  u.Email,
		"name":   u.Name,
		"groups": u.Groups,
		"nonce":  ac.Nonce,
		"iat":    now.Unix(),
		"exp":    now.Add(5 * time.Minute).Unix(),
		"amr":    amr,
	}
	if authTime > 0 {
		claims["auth_time"] = authTime
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	obj, err := p.signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

// ── helpers ───────────────────────────────────────────────────────────────────

func encodeCode(ac authCode) (string, error) {
	b, err := json.Marshal(ac)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func decodeCode(s string) (authCode, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return authCode{}, err
	}
	var ac authCode
	if err := json.Unmarshal(raw, &ac); err != nil {
		return authCode{}, err
	}
	return ac, nil
}

func verifyPKCE(verifier, challenge string) bool {
	if verifier == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func tokenError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func htmlEscape(s string) string {
	r := []rune{}
	for _, c := range s {
		switch c {
		case '<':
			r = append(r, []rune("&lt;")...)
		case '>':
			r = append(r, []rune("&gt;")...)
		case '&':
			r = append(r, []rune("&amp;")...)
		case '"':
			r = append(r, []rune("&quot;")...)
		default:
			r = append(r, c)
		}
	}
	return string(r)
}
