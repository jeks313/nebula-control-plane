package enrollclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/paths"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

// fakeGateway is a minimal in-process stand-in for the enrollment gateway + IdP that
// EnrollSSO drives, with NO real browser/SAML/IdP. It serves:
//   - GET  /v1/nonce          -> a fixed nonce bound to the pubkey_hash
//   - GET  /v1/sso/start      -> 302 to /idp (carrying the loopback redirect)
//   - GET  /idp               -> 302 to the loopback /callback?assertion=…&state=…
//   - POST /v1/enroll         -> 202 ticket; records the decoded EnrollRequest
//   - GET  /v1/enroll/{id}    -> the configured poll status (default: pending)
type fakeGateway struct {
	srv *httptest.Server

	nonce     string // nonce handed out at /v1/nonce
	assertion string // assertion the fake IdP delivers to the loopback /callback
	pollBody  func() (int, []byte)

	mu        sync.Mutex
	gotNonce  bool
	gotStart  url.Values          // query the start route received
	gotEnroll *wire.EnrollRequest // the decoded enroll request body
}

func newFakeGateway(t *testing.T) *fakeGateway {
	t.Helper()
	g := &fakeGateway{nonce: "nonce-from-gateway", assertion: "compact.jws.assertion"}
	// Default poll outcome: pending (the SSO common case, S8).
	g.pollBody = func() (int, []byte) {
		b, _ := json.Marshal(wire.PollResponse{Status: "pending", PollAfterMs: 1})
		return http.StatusAccepted, b
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/nonce", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.gotNonce = true
		g.mu.Unlock()
		wire.WriteJSON(w, http.StatusOK, wire.NonceResponse{
			ProtocolVersion: wire.ProtocolVersion, Nonce: g.nonce,
			ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
		})
	})
	mux.HandleFunc("GET /v1/sso/start", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.gotStart = r.URL.Query()
		g.mu.Unlock()
		// Carry the loopback redirect through to the fake IdP so it can complete the
		// hand-off, exactly as the real RelayState-bound session would. The real gateway
		// 302s to an ABSOLUTE IdP URL, so do the same (the client reads Location and hands
		// it to the user's browser, which can't follow a relative URL).
		q := url.Values{
			"redirect": {r.URL.Query().Get("redirect")},
			"state":    {"state-token"},
		}
		http.Redirect(w, r, g.srv.URL+"/idp?"+q.Encode(), http.StatusFound)
	})
	mux.HandleFunc("GET /idp", func(w http.ResponseWriter, r *http.Request) {
		// The "IdP" immediately redirects the browser back to the pilot loopback with
		// the gateway-signed assertion + the echoed state.
		loc, _ := url.Parse(r.URL.Query().Get("redirect"))
		q := loc.Query()
		q.Set("assertion", g.assertion)
		q.Set("state", r.URL.Query().Get("state"))
		loc.RawQuery = q.Encode()
		http.Redirect(w, r, loc.String(), http.StatusFound)
	})
	mux.HandleFunc("POST /v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		var env jws.Flattened
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			http.Error(w, "bad env", http.StatusBadRequest)
			return
		}
		payload, err := base64.RawURLEncoding.DecodeString(env.Payload)
		if err != nil {
			http.Error(w, "bad payload", http.StatusBadRequest)
			return
		}
		var req wire.EnrollRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		g.mu.Lock()
		g.gotEnroll = &req
		g.mu.Unlock()
		wire.WriteJSON(w, http.StatusAccepted, wire.EnrollAccepted{
			ProtocolVersion: wire.ProtocolVersion, EnrollmentID: "enr-1",
			RetrievalSecret: "secret-1", PollAfterMs: 1,
		})
	})
	mux.HandleFunc("GET /v1/enroll/{id}", func(w http.ResponseWriter, r *http.Request) {
		code, body := g.pollBody()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write(body)
	})

	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGateway) enrollReq() *wire.EnrollRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.gotEnroll
}

// browserGET is an OpenBrowser stub: instead of launching a real browser, it just GETs
// the authorize URL (following redirects), which drives the fake IdP → loopback hand-off.
func browserGET(t *testing.T) func(string) error {
	t.Helper()
	return func(target string) error {
		go func() {
			resp, err := http.Get(target) //nolint:noctx // test-only browser stand-in
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
		return nil
	}
}

func ssoTestParams(t *testing.T, g *fakeGateway) SSOParams {
	t.Helper()
	dir := t.TempDir()
	return SSOParams{
		GatewayURL:      g.srv.URL,
		Layout:          paths.New(dir),
		RequestedName:   "laptop-1",
		RequestedGroups: []string{"eng"},
		PinnedConfigPub: dummyPinnedKey(t),
		SSOWait:         5 * time.Second,
		PollTimeout:     2 * time.Second,
		OpenBrowser:     browserGET(t),
	}
}

// dummyPinnedKey is a throwaway P256 key — EnrollSSO only requires a non-nil pinned key
// up front; in the pending-poll path it is never used to verify a bundle.
func dummyPinnedKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &k.PublicKey
}

// TestEnrollSSOLoopbackPending drives the whole loopback flow against the fake gateway:
// the browser stub GETs the authorize URL, the fake IdP bounces the assertion back to
// the loopback /callback, pilot submits the enroll request, and the (pending) poll is
// handled cleanly. It asserts the loopback captured the assertion and the enroll request
// carries method=oidc + the {"assertion":…} envelope + the same nonce/pubkey.
func TestEnrollSSOLoopbackPending(t *testing.T) {
	g := newFakeGateway(t)
	p := ssoTestParams(t, g)

	res, err := EnrollSSO(context.Background(), p)
	if err != nil {
		t.Fatalf("EnrollSSO: %v", err)
	}
	if res.Status != "pending" {
		t.Fatalf("Status = %q, want pending (SSO defaults to PENDING; not an error)", res.Status)
	}

	req := g.enrollReq()
	if req == nil {
		t.Fatal("gateway never received the enroll request (the loopback did not deliver the assertion)")
	}
	if req.Method != wire.MethodOIDC {
		t.Errorf("enroll method = %q, want %q", req.Method, wire.MethodOIDC)
	}
	// Credential envelope must be exactly {"assertion":"<jws>"} (B5).
	var cred struct {
		Assertion string `json:"assertion"`
	}
	if err := json.Unmarshal(req.Credential, &cred); err != nil {
		t.Fatalf("credential is not a JSON envelope: %v (%s)", err, req.Credential)
	}
	if cred.Assertion != g.assertion {
		t.Errorf("credential assertion = %q, want the captured assertion %q", cred.Assertion, g.assertion)
	}
	// Same nonce the gateway handed out at /v1/nonce.
	if req.Nonce != g.nonce {
		t.Errorf("enroll nonce = %q, want the gateway nonce %q", req.Nonce, g.nonce)
	}
	// The pubkey_hash carried into start must match the CSR's pubkey.
	pub, err := base64.RawURLEncoding.DecodeString(req.CSR.PublicKey)
	if err != nil {
		t.Fatalf("CSR public key not base64url: %v", err)
	}
	wantPKH := wire.PubkeyHash(pub)
	if got := g.gotStart.Get("pubkey_hash"); got != wantPKH {
		t.Errorf("start pubkey_hash = %q, want the CSR-derived %q", got, wantPKH)
	}
	if got := g.gotStart.Get("nonce"); got != g.nonce {
		t.Errorf("start nonce = %q, want %q", got, g.nonce)
	}
	// The start redirect must be a loopback /callback URL.
	red := g.gotStart.Get("redirect")
	u, err := url.Parse(red)
	if err != nil || u.Hostname() != "127.0.0.1" || u.Path != "/callback" {
		t.Errorf("start redirect = %q, want a loopback /callback URL", red)
	}
	// A pending SSO host keeps its ticket so a re-run resumes straight to the poll.
	if _, resumed := loadTicket(p.Layout.EnrollTicket()); !resumed {
		t.Error("pending SSO enrollment should persist a resumable ticket")
	}
}

// TestEnrollSSOResumesPendingTicket: a host left PENDING re-runs `pilot enroll --sso`
// and goes straight to the poll — no second browser round-trip and no second nonce.
func TestEnrollSSOResumesPendingTicket(t *testing.T) {
	g := newFakeGateway(t)
	p := ssoTestParams(t, g)
	// Pre-seed a ticket as if a prior run left this host pending.
	if err := p.Layout.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := saveTicket(p.Layout.EnrollTicket(), wire.EnrollAccepted{EnrollmentID: "enr-9", RetrievalSecret: "sec-9", PollAfterMs: 1}); err != nil {
		t.Fatal(err)
	}
	// Browser must NOT be opened on the resume path.
	p.OpenBrowser = func(string) error { t.Fatal("resume path must not open a browser"); return nil }

	res, err := EnrollSSO(context.Background(), p)
	if err != nil {
		t.Fatalf("EnrollSSO resume: %v", err)
	}
	if res.Status != "pending" {
		t.Fatalf("Status = %q, want pending", res.Status)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.gotNonce {
		t.Error("resume path should not fetch a fresh nonce")
	}
	if g.gotStart != nil {
		t.Error("resume path should not call /v1/sso/start")
	}
}

// TestEnrollSSODeniedClearsTicket: a denied result is terminal and removes the ticket.
func TestEnrollSSODeniedClearsTicket(t *testing.T) {
	g := newFakeGateway(t)
	g.pollBody = func() (int, []byte) {
		b, _ := json.Marshal(wire.PollResponse{Status: "denied", Reason: "not in a trusted group"})
		return http.StatusOK, b
	}
	p := ssoTestParams(t, g)

	res, err := EnrollSSO(context.Background(), p)
	if err != nil {
		t.Fatalf("EnrollSSO: %v", err)
	}
	if res.Status != "denied" || res.Reason == "" {
		t.Fatalf("res = %+v, want denied with a reason", res)
	}
	if _, resumed := loadTicket(p.Layout.EnrollTicket()); resumed {
		t.Error("a denied enrollment must not leave a resumable ticket")
	}
}

// TestEnrollSSOLoopbackTimeout: if the browser never delivers an assertion to the
// loopback, EnrollSSO times out on the wait (it does not hang, and never submits).
func TestEnrollSSOLoopbackTimeout(t *testing.T) {
	g := newFakeGateway(t)
	p := ssoTestParams(t, g)
	p.SSOWait = 50 * time.Millisecond
	// Stub a browser that never completes the round-trip.
	p.OpenBrowser = func(string) error { return nil }

	_, err := EnrollSSO(context.Background(), p)
	if err == nil {
		t.Fatal("expected a timeout error when the browser never delivers the assertion")
	}
	if g.enrollReq() != nil {
		t.Error("no enroll request should be submitted when the loopback times out")
	}
}

// TestEnrollSSOStartNotEnabled: a gateway whose /v1/sso/start answers 404 (SSO not
// configured) surfaces a clear error before any browser is opened.
func TestEnrollSSOStartNotEnabled(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/nonce", func(w http.ResponseWriter, r *http.Request) {
		wire.WriteJSON(w, http.StatusOK, wire.NonceResponse{ProtocolVersion: 1, Nonce: "n"})
	})
	mux.HandleFunc("GET /v1/sso/start", func(w http.ResponseWriter, r *http.Request) {
		wire.WriteError(w, wire.CodeNotFound, "SSO not enabled")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	opened := false
	_, err := EnrollSSO(context.Background(), SSOParams{
		GatewayURL: srv.URL, Layout: paths.New(t.TempDir()),
		PinnedConfigPub: dummyPinnedKey(t), SSOWait: time.Second,
		OpenBrowser: func(string) error { opened = true; return nil },
	})
	if err == nil {
		t.Fatal("expected an error when the gateway has SSO disabled")
	}
	if opened {
		t.Error("the browser should not be opened when sso/start fails")
	}
}
