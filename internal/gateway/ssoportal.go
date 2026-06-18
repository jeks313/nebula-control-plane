package gateway

import (
	"crypto/ecdsa"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/adminauth"
	"github.com/jeks313/nebula-control-plane/internal/ssoassert"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

// The SSO enrollment portal (ADR 0004 + decisions S5/S7/S9) runs the IdP browser flow
// on the off-mesh gateway and hands the laptop a short-lived, device-bound assertion it
// can submit to the EXISTING /v1/enroll path. The gateway holds NO CA (ADR 0009): it can
// only sign "the IdP said this about this device", never issue a cert. Core pulls the
// candidate and re-verifies the assertion + binding + policy before issuing.
//
// Flow (SAML, loopback authorization-code style, S9):
//
//  1. pilot → GET  /v1/sso/start?pubkey_hash=&nonce=&redirect=http://127.0.0.1:PORT/cb
//     The gateway mints a server-side session binding {pubkey_hash, nonce,
//     loopback_redirect, SAML requestID} keyed by an unguessable state token, then
//     redirects the browser to the IdP AuthnRequest with RelayState = the state token.
//  2. IdP → POST /v1/sso/acs  (RelayState + SAMLResponse)
//     The gateway validates the assertion via adminauth (signature/audience/conditions/
//     InResponseTo/XSW), recovers the session by RelayState, builds + signs an
//     ssoassert.Assertion bound to {pubkey_hash, nonce}, and 302s the browser to the
//     pilot loopback redirect with ?assertion=<compact-jws>&state=<state>.
//  3. pilot then POSTs the EXISTING EnrollRequest{method:oidc, credential:{assertion}}
//     to /v1/enroll (unchanged — MethodOIDC is already accepted).

const (
	defaultSSOSessionTTL  = 5 * time.Minute
	defaultAssertionTTL   = 3 * time.Minute
	maxPubkeyHashLen      = 128
	maxLoopbackRedirect   = 512
	ssoSessionStateLen    = 32 // bytes of randomness in the state token (256-bit)
	ssoSessionStateMaxLen = 128
)

// SSOConfig enables the SSO enrollment portal. It is OPTIONAL: when SAML or SigningKey
// is nil, New leaves the portal disabled and its routes answer 404 "SSO not enabled" —
// the rest of the gateway is unaffected (the gateway never gains a CA either way).
type SSOConfig struct {
	// SAML is the adminauth SAML authenticator (reused for AuthnRequest generation and
	// the full ACS assertion validation — we never hand-roll SAML parsing).
	SAML *adminauth.SAMLAuthenticator
	// SigningKey is the gateway's DEDICATED assertion-signing private key (ECDSA P-256,
	// decision S6), distinct from any CA. Core pins the matching public half.
	SigningKey *ecdsa.PrivateKey
	// Issuer is the realm string stamped into the assertion's `iss` (fed to Core's
	// usertrust.Match). Empty falls back to the SAML provider name.
	Issuer string
	// SessionTTL bounds how long a started SSO session may sit awaiting the ACS POST
	// (<=0 -> default). The state token is single-use regardless.
	SessionTTL time.Duration
	// AssertionTTL is the validity window stamped into signed assertions (<=0 ->
	// default; kept short, S5).
	AssertionTTL time.Duration
}

// enabled reports whether the portal has the two required pieces of config.
func (c *SSOConfig) enabled() bool {
	return c != nil && c.SAML != nil && c.SigningKey != nil
}

// ssoSession is the short-TTL, single-use server-side state of one portal attempt. It is
// the trust anchor of the device binding: the browser/user never sees pubkey_hash, nonce
// or requestID, and cannot substitute another device — RelayState is just the opaque
// lookup key into this record.
type ssoSession struct {
	pubkeyHash string
	nonce      string
	redirect   string // validated loopback redirect
	requestID  string // SAML AuthnRequest ID; the only accepted InResponseTo
	expires    time.Time
}

// ssoSessions is an in-memory, TTL'd, single-use session store. Lives only on the
// gateway; loses everything on restart (in-flight enrolls just retry), which is fine.
type ssoSessions struct {
	mu  sync.Mutex
	m   map[string]ssoSession
	ttl time.Duration
	now func() time.Time
}

func newSSOSessions(ttl time.Duration, now func() time.Time) *ssoSessions {
	if ttl <= 0 {
		ttl = defaultSSOSessionTTL
	}
	if now == nil {
		now = time.Now
	}
	return &ssoSessions{m: make(map[string]ssoSession), ttl: ttl, now: now}
}

// put stores sess under state with the configured TTL.
func (s *ssoSessions) put(state string, sess ssoSession) {
	sess.expires = s.now().Add(s.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	s.m[state] = sess
}

// take atomically removes and returns the session for state (single-use). It returns
// ok=false if the state is unknown or the session has expired.
func (s *ssoSessions) take(state string) (ssoSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[state]
	if !ok {
		return ssoSession{}, false
	}
	delete(s.m, state) // single-use even on expiry
	if s.now().After(sess.expires) {
		return ssoSession{}, false
	}
	return sess, true
}

// gcLocked drops expired sessions; cheap, bounded by the live set. Caller holds mu.
func (s *ssoSessions) gcLocked() {
	now := s.now()
	for k, v := range s.m {
		if now.After(v.expires) {
			delete(s.m, k)
		}
	}
}

// handleSSOStart implements GET /v1/sso/start (step 1). It mints a server-side session
// binding the device facts, then redirects to the IdP AuthnRequest with RelayState =
// state token. pilot supplies its pubkey_hash, the pubkey-bound nonce it already minted
// at /v1/nonce, and its loopback redirect URL.
func (s *Server) handleSSOStart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.ssoEnabled() {
		wire.WriteError(w, wire.CodeNotFound, "SSO not enabled")
		return
	}
	q := r.URL.Query()
	pubkeyHash := q.Get("pubkey_hash")
	nonceVal := q.Get("nonce")
	redirect := q.Get("redirect")

	if pubkeyHash == "" || len(pubkeyHash) > maxPubkeyHashLen {
		wire.WriteError(w, wire.CodeInvalidRequest, "missing or oversized 'pubkey_hash'")
		return
	}
	if nonceVal == "" {
		wire.WriteError(w, wire.CodeInvalidRequest, "missing 'nonce'")
		return
	}
	if len(redirect) == 0 || len(redirect) > maxLoopbackRedirect {
		wire.WriteError(w, wire.CodeInvalidRequest, "missing or oversized 'redirect'")
		return
	}
	if !isLoopbackRedirect(redirect) {
		wire.WriteError(w, wire.CodeInvalidRequest, "redirect must target loopback (127.0.0.1/::1/localhost)")
		return
	}
	// Re-prove the nonce is fresh + bound to this pubkey before we burn a SAML round
	// trip on it (the same keyring check /v1/enroll uses). Core re-checks single-use.
	if err := s.nonces.Verify(nonceVal, []byte(pubkeyHash)); err != nil {
		wire.WriteError(w, wire.CodeInvalidNonce, "invalid or expired nonce")
		return
	}

	state := randToken(ssoSessionStateLen)
	redirectURL, requestID, err := s.sso.SAML.AuthnRedirect(state)
	if err != nil {
		wire.WriteError(w, wire.CodeInternal, "could not start SSO")
		return
	}
	s.ssoSessions.put(state, ssoSession{
		pubkeyHash: pubkeyHash,
		nonce:      nonceVal,
		redirect:   redirect,
		requestID:  requestID,
	})
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// handleSSOACS implements POST /v1/sso/acs (step 2): the IdP HTTP-POST callback. It
// validates the assertion (adminauth → crewjam), recovers the session by RelayState,
// signs a device-bound ssoassert.Assertion, and redirects to the pilot loopback.
func (s *Server) handleSSOACS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.ssoEnabled() {
		wire.WriteError(w, wire.CodeNotFound, "SSO not enabled")
		return
	}
	if err := r.ParseForm(); err != nil {
		wire.WriteError(w, wire.CodeInvalidRequest, "could not parse SAML response")
		return
	}
	state := r.PostFormValue("RelayState")
	if state == "" || len(state) > ssoSessionStateMaxLen {
		wire.WriteError(w, wire.CodeInvalidRequest, "missing RelayState")
		return
	}
	// Recover (and consume) the session FIRST — RelayState is the only key, and it is
	// single-use + bound server-side to the device. A stale/forged/replayed RelayState
	// has no session and is rejected before any SAML work.
	sess, ok := s.ssoSessions.take(state)
	if !ok {
		wire.WriteError(w, wire.CodeInvalidRequest, "unknown, expired, or already-used SSO session")
		return
	}
	// Validate the assertion against the session's AuthnRequest ID (InResponseTo). All
	// SAML crypto + XSW/audience/conditions/InResponseTo checks live in adminauth.
	subj, err := s.sso.SAML.ValidateACS(r, sess.requestID)
	if err != nil {
		wire.WriteError(w, wire.CodeInvalidSignature, "SAML assertion did not verify")
		return
	}

	now := s.now()
	issuer := s.sso.Issuer
	if issuer == "" {
		issuer = s.sso.SAML.Name()
	}
	a := ssoassert.Assertion{
		Subject:    subj.ID,
		Email:      subj.Email,
		Issuer:     issuer,
		IdPGroups:  subj.Groups,
		PubkeyHash: sess.pubkeyHash,
		Nonce:      sess.nonce,
		IssuedAt:   now.Unix(),
		ExpiresAt:  now.Add(s.assertionTTL).Unix(),
	}
	token, err := ssoassert.Sign(s.sso.SigningKey, a)
	if err != nil {
		wire.WriteError(w, wire.CodeInternal, "could not sign assertion")
		return
	}

	// Hand off to the pilot loopback. The assertion is integrity-protected (ES256),
	// short-lived (S5), and bound to {pubkey_hash, nonce}, so putting it in the redirect
	// query is safe: a different device cannot use it. state is echoed so pilot can
	// match the response to the session it started.
	loc, err := url.Parse(sess.redirect)
	if err != nil {
		wire.WriteError(w, wire.CodeInternal, "invalid loopback redirect")
		return
	}
	qv := loc.Query()
	qv.Set("assertion", string(token))
	qv.Set("state", state)
	loc.RawQuery = qv.Encode()
	http.Redirect(w, r, loc.String(), http.StatusFound)
}

// ssoEnabled reports whether the portal is configured + wired on this server.
func (s *Server) ssoEnabled() bool { return s.sso.enabled() }

// isLoopbackRedirect accepts only http(s) URLs whose host is a loopback target
// (127.0.0.0/8, ::1, or the literal "localhost"), with no userinfo. This is the
// open-redirect / token-exfil guard: the signed assertion is only ever handed to a
// process on the same machine as pilot, never to an attacker-chosen host.
func isLoopbackRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if u.User != nil {
		return false
	}
	host := u.Hostname() // strips any :port and [] brackets
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
