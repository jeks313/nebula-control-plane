package adminauth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/adminapi"
)

// Subject is the normalized result of any IdP login. Groups are provider-specific
// identifiers (OIDC group-claim values; GitHub "org/team" slugs; mock-issued
// groups) that the RoleMapper turns into Harbor roles. Subject carries identity
// only — never authority; roles are decided server-side.
type Subject struct {
	ID     string     // the IdP's stable subject id
	Name   string     // display name (optional)
	Email  string     // email (optional)
	Groups []string   // provider-specific group identifiers
	MFAAt  *time.Time // when the IdP asserted MFA, if known
}

// Principal is the human-readable identity bound to sign-offs and the audit log.
// Prefer email (stable, recognizable); fall back to name, then the raw subject.
func (s Subject) Principal() string {
	switch {
	case s.Email != "":
		return s.Email
	case s.Name != "":
		return s.Name
	default:
		return s.ID
	}
}

// Authenticator is the bring-your-own-IdP seam. It runs ONLY at login: AuthURL
// builds the IdP redirect for one attempt, and Exchange consumes the callback and
// returns the authenticated Subject. The Service owns the per-attempt secrets
// (state/nonce/PKCE verifier) and the login-state cookie, so authenticators stay
// stateless and a new protocol (SAML next) is a small, self-contained addition.
type Authenticator interface {
	Name() string
	// AuthURL returns the IdP authorization redirect for this attempt. nonce and
	// PKCE verifier are provided by the Service; providers that don't use them
	// (GitHub has no ID token) ignore them. forceReauth requests a fresh
	// authentication (step-up MFA) rather than a silent SSO.
	AuthURL(state, nonce, verifier string, forceReauth bool) string
	// Exchange consumes the callback (the authorization code) and returns the
	// Subject. nonce + verifier from the login-state cookie are passed back for
	// ID-token / PKCE verification.
	Exchange(ctx context.Context, code, nonce, verifier string) (Subject, error)
}

// FlowAuthenticator is a login provider whose protocol does NOT fit the OAuth
// authorization-code shape (a GET callback carrying ?code=). SAML is the first:
// the IdP returns a signed XML assertion by HTTP-POST to a provider-specific ACS
// endpoint. Such a provider owns its own login redirect and its own callback
// route(s) and finishes by calling the supplied CompleteFunc — so session policy
// (role mapping, minting, cookies) stays centralized in the Service.
type FlowAuthenticator interface {
	Name() string
	// StartLogin begins an SP-initiated login: it sets its own short-lived login
	// cookie and redirects the browser to the IdP. forceReauth requests a fresh
	// authentication (step-up MFA, e.g. SAML ForceAuthn).
	StartLogin(w http.ResponseWriter, r *http.Request, returnTo string, forceReauth bool)
	// Register mounts the provider's callback route(s) (e.g. saml/acs, saml/metadata)
	// onto the shared auth mux. complete finishes a successful login.
	Register(mux *http.ServeMux, complete CompleteFunc)
}

// CompleteFunc maps a Subject to roles, mints a session + cookies, and redirects
// to returnTo. FlowAuthenticators call it from their callback route.
type CompleteFunc func(w http.ResponseWriter, r *http.Request, idp string, subj Subject, returnTo string)

// Config builds the auth Service.
type Config struct {
	Store              *SessionStore
	Authenticators     []Authenticator     // OAuth code-flow providers (OIDC, GitHub, mock)
	FlowAuthenticators []FlowAuthenticator // non-code-flow providers (SAML)
	RoleMapper         *RoleMapper
	SessionTTL         time.Duration // absolute session cap (default 12h)
	Secure             bool          // set Secure on cookies (true in prod/https)
	Now                func() time.Time
	Logger             *slog.Logger
}

// Service drives the login/callback/logout flow and yields the SessionProvider
// the admin API authenticates against.
type Service struct {
	cfg       Config
	byName    map[string]Authenticator
	flows     map[string]FlowAuthenticator
	providers []string     // ordered provider names (the first is the default)
	signer    cookieSigner // signs the login-state cookie (tamper-evident)
}

// New builds the auth Service. Returns an error (rather than panicking) if the
// cookie signer can't be initialized, matching the NewOIDC/NewSAML siblings and
// letting the caller decide how to fail.
func New(cfg Config) (*Service, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.RoleMapper == nil {
		cfg.RoleMapper = &RoleMapper{} // fail-closed: no groups map to roles
	}
	signer, err := newCookieSigner()
	if err != nil {
		return nil, fmt.Errorf("adminauth: init cookie signer: %w", err)
	}
	s := &Service{
		cfg:    cfg,
		byName: make(map[string]Authenticator, len(cfg.Authenticators)),
		flows:  make(map[string]FlowAuthenticator, len(cfg.FlowAuthenticators)),
		signer: signer,
	}
	for _, a := range cfg.Authenticators {
		s.byName[a.Name()] = a
		s.providers = append(s.providers, a.Name())
	}
	for _, f := range cfg.FlowAuthenticators {
		s.flows[f.Name()] = f
		s.providers = append(s.providers, f.Name())
	}
	return s, nil
}

// Provider returns the per-request IdentityProvider the admin API plugs in.
func (s *Service) Provider() *SessionProvider { return &SessionProvider{store: s.cfg.Store} }

// loginState is the per-attempt secret set during login and consumed at callback.
// It lives in a short-lived httpOnly, SameSite cookie — never readable by JS and
// not replayable cross-site; the state value also defeats OAuth login CSRF.
type loginState struct {
	Provider string `json:"p"`
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	ReturnTo string `json:"r"`
}

const loginCookie = "harbor_login"

// Handler mounts the auth routes. They are UNAUTHENTICATED (you can't require a
// session to log in) — mount this subtree alongside the authed admin API.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/v1/auth/login", s.handleLogin)
	mux.HandleFunc("GET /admin/v1/auth/callback", s.handleCallback)
	mux.HandleFunc("POST /admin/v1/auth/logout", s.handleLogout)
	mux.HandleFunc("GET /admin/v1/auth/providers", s.handleProviders)
	for _, f := range s.cfg.FlowAuthenticators {
		f.Register(mux, s.CompleteLogin) // e.g. POST saml/acs, GET saml/metadata
	}
	return mux
}

// GET /admin/v1/auth/providers — the configured login providers (so the SPA can
// render a "Sign in with …" button per provider without hard-coding them).
func (s *Service) handleProviders(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"providers": s.providers})
}

// GET /admin/v1/auth/login?provider=oidc&return_to=/ — start a login. A SAML (flow)
// provider owns its own redirect; OAuth providers use the shared code flow.
func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("provider")
	if name == "" && len(s.providers) > 0 {
		name = s.providers[0]
	}
	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))
	// step_up forces a fresh authentication (MFA re-prompt) for privileged actions.
	forceReauth := r.URL.Query().Get("step_up") == "1" || r.URL.Query().Get("step_up") == "true"
	if f := s.flows[name]; f != nil {
		f.StartLogin(w, r, returnTo, forceReauth)
		return
	}
	auth := s.byName[name]
	if auth == nil {
		problem(w, http.StatusBadRequest, "unknown provider", "no such login provider")
		return
	}
	state, err1 := randToken()
	nonce, err2 := randToken()
	verifier, err3 := randToken()
	if err1 != nil || err2 != nil || err3 != nil {
		s.fail(w, "login: generate state", firstErr(err1, err2, err3))
		return
	}
	ls := loginState{
		Provider: auth.Name(), State: state, Nonce: nonce, Verifier: verifier,
		ReturnTo: returnTo,
	}
	s.setLoginCookie(w, ls)
	http.Redirect(w, r, auth.AuthURL(state, nonce, verifier, forceReauth), http.StatusFound)
}

// GET /admin/v1/auth/callback — finish a login: verify state, exchange the code,
// map roles, mint the session, set cookies, and return to the app.
func (s *Service) handleCallback(w http.ResponseWriter, r *http.Request) {
	ls, ok := s.readLoginCookie(r)
	s.clearCookie(w, loginCookie)
	if !ok {
		problem(w, http.StatusBadRequest, "no login in progress", "missing or invalid login state")
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		problem(w, http.StatusUnauthorized, "login failed", "the identity provider returned: "+e)
		return
	}
	// Constant-ish state check: the callback's state must equal the one we set.
	if st := r.URL.Query().Get("state"); st == "" || st != ls.State {
		problem(w, http.StatusBadRequest, "bad state", "login state mismatch (possible CSRF)")
		return
	}
	auth := s.byName[ls.Provider]
	if auth == nil {
		problem(w, http.StatusBadRequest, "unknown provider", "no such login provider")
		return
	}
	subj, err := auth.Exchange(r.Context(), r.URL.Query().Get("code"), ls.Nonce, ls.Verifier)
	if err != nil {
		s.cfg.Logger.Warn("adminauth: exchange failed", "provider", ls.Provider, "err", err)
		problem(w, http.StatusUnauthorized, "login failed", "could not complete authentication")
		return
	}
	s.CompleteLogin(w, r, auth.Name(), subj, ls.ReturnTo)
}

// CompleteLogin is the shared tail of every login flow (OAuth and SAML): map the
// Subject's groups to roles, mint a session + cookies, and redirect to returnTo
// (re-validated same-origin). FlowAuthenticators call this from their callback.
func (s *Service) CompleteLogin(w http.ResponseWriter, r *http.Request, idp string, subj Subject, returnTo string) {
	roles := s.cfg.RoleMapper.Roles(subj.Groups)
	// Audit every console login at the one place IdP group membership becomes authority: who, via
	// which IdP, the RAW IdP groups the assertion carried, and the Harbor roles they mapped to. This
	// is the record for "why am I only a viewer?" (groups that matched no -role-map entry) and for
	// admin-access auditing. Groups are identifiers (Entra group GUIDs / OIDC claims), not secrets.
	s.cfg.Logger.Info("console login",
		"idp", idp,
		"principal", subj.Principal(),
		"subject_id", subj.ID,
		"groups", subj.Groups,
		"roles", roles,
		"mfa", subj.MFAAt != nil,
	)
	token, csrf, err := s.cfg.Store.Mint(r.Context(), subj, idp, roles, s.cfg.SessionTTL)
	if err != nil {
		s.fail(w, "login: mint session", err)
		return
	}
	s.setSessionCookies(w, token, csrf)
	http.Redirect(w, r, safeReturnTo(returnTo), http.StatusFound)
}

// POST /admin/v1/auth/logout — revoke the session and clear cookies.
func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookie); err == nil {
		_ = s.cfg.Store.Revoke(r.Context(), c.Value)
	}
	s.clearCookie(w, SessionCookie)
	s.clearCookie(w, CSRFCookie)
	w.WriteHeader(http.StatusNoContent)
}

// ── cookies ───────────────────────────────────────────────────────────────────

func (s *Service) setSessionCookies(w http.ResponseWriter, token, csrf string) {
	exp := s.cfg.Now().Add(s.cfg.SessionTTL)
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: token, Path: "/", Expires: exp,
		HttpOnly: true, Secure: s.cfg.Secure, SameSite: http.SameSiteLaxMode,
	})
	// CSRF cookie is intentionally NOT httpOnly: the SPA reads it and echoes it in
	// the X-CSRF-Token header on mutations (double-submit; see CSRF middleware).
	http.SetCookie(w, &http.Cookie{
		Name: CSRFCookie, Value: csrf, Path: "/", Expires: exp,
		HttpOnly: false, Secure: s.cfg.Secure, SameSite: http.SameSiteLaxMode,
	})
}

func (s *Service) setLoginCookie(w http.ResponseWriter, ls loginState) {
	val, err := s.signer.encode(ls) // signed: the nonce/PKCE verifier must not be forgeable
	if err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: loginCookie, Value: val, Path: "/admin/v1/auth/",
		MaxAge: 600, HttpOnly: true, Secure: s.cfg.Secure, SameSite: http.SameSiteLaxMode,
	})
}

func (s *Service) readLoginCookie(r *http.Request) (loginState, bool) {
	c, err := r.Cookie(loginCookie)
	if err != nil {
		return loginState{}, false
	}
	var ls loginState
	if !s.signer.decode(c.Value, &ls) {
		return loginState{}, false
	}
	return ls, true
}

func (s *Service) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.cfg.Secure, SameSite: http.SameSiteLaxMode,
	})
}

func (s *Service) fail(w http.ResponseWriter, msg string, err error) {
	s.cfg.Logger.Error("adminauth: "+msg, "err", err)
	problem(w, http.StatusInternalServerError, "internal error", "login could not be completed")
}

// safeReturnTo only permits same-site absolute paths, defeating open-redirect via
// return_to. It must start with a single "/" and must NOT be protocol-relative.
// Browsers normalize backslashes to slashes for http(s), so "/\\evil.com" parses
// as "//evil.com" (external) — we reject any backslash and any control char, then
// parse and require an empty scheme + host so only a same-origin path can survive.
func safeReturnTo(p string) string {
	if p == "" || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return "/"
	}
	if strings.ContainsAny(p, "\\\x00\t\n\r") {
		return "/" // backslash + control chars browsers fold into host/path confusion
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return p
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func problem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"title": title, "status": status, "detail": detail})
}

// mfaPtr converts a stored unix-ns MFA timestamp to the optional API field.
func mfaPtr(ns int64) *time.Time {
	if ns == 0 {
		return nil
	}
	t := time.Unix(0, ns).UTC()
	return &t
}

// compile-time: SessionProvider satisfies the admin API seam.
var _ adminapi.IdentityProvider = (*SessionProvider)(nil)
