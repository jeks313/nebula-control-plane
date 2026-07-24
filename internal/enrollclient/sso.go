package enrollclient

// SSO enrollment (ADR 0004, decisions S5/S7/S8/S9). The loopback authorization-code
// flow: pilot mints/loads its host key, fetches a pubkey-bound nonce, starts a local
// loopback listener, asks the gateway portal to begin an IdP SSO session bound to that
// {pubkey_hash, nonce, loopback redirect}, opens the user's browser to the IdP, and
// waits for the browser to deliver a gateway-signed assertion back to the loopback
// `/callback`. The assertion is then submitted on the EXISTING /v1/enroll path inside
// the standard `{"assertion":"<compact-jws>"}` credential envelope (B5) — only the way
// the credential is obtained differs from the join-key path; submit + poll are shared.
//
// SSO admission defaults to PENDING (S8): Core issues nothing automatically, an admin
// approves in the existing queue. EnrollSSO therefore treats "pending" as a normal,
// non-error outcome — it returns Status "pending" and the CLI tells the user the
// enrollment was submitted and the bundle will arrive after approval (re-run to fetch).

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/paths"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

// defaultSSOWait bounds how long EnrollSSO waits for the browser to complete the IdP
// round-trip and deliver the assertion to the loopback /callback. Generous enough for
// a human to authenticate (and MFA), ctx-cancelable.
const defaultSSOWait = 3 * time.Minute

// SSOParams configures an SSO enrollment run (loopback authorization-code, S9). It
// mirrors Params minus the credential source: SSO obtains the credential from a browser
// IdP round-trip rather than a join key or instance role.
type SSOParams struct {
	GatewayURL      string
	Layout          paths.Layout
	RequestedName   string
	RequestedGroups []string
	PinnedConfigPub []*ecdsa.PublicKey // the config-signing key set Pilot trusts (pin UNION learned, M8.5)
	HTTPClient      *http.Client
	PollTimeout     time.Duration // bounds the poll-for-bundle wait (after submit)
	SSOWait         time.Duration // bounds the browser/IdP round-trip wait (<=0 -> default)
	Now             func() time.Time

	// OpenBrowser opens the user's default browser at the IdP authorize URL. It is a
	// thin, injectable best-effort step so tests can drive the flow without a real
	// browser; nil falls back to the cross-platform openBrowser helper.
	OpenBrowser func(url string) error
}

// EnrollSSO runs the SSO loopback enrollment flow and returns its outcome. A "pending"
// Result is the normal SSO path (S8), not an error: the request is queued for admin
// approval and the bundle arrives once approved (re-run EnrollSSO to fetch it).
func EnrollSSO(ctx context.Context, p SSOParams) (Result, error) {
	if p.HTTPClient == nil {
		p.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if p.PollTimeout <= 0 {
		p.PollTimeout = 60 * time.Second
	}
	if p.SSOWait <= 0 {
		p.SSOWait = defaultSSOWait
	}
	if p.Now == nil {
		p.Now = time.Now
	}
	if p.OpenBrowser == nil {
		p.OpenBrowser = openBrowser
	}
	if p.PinnedConfigPub == nil {
		return Result{}, fmt.Errorf("enrollclient: a pinned config-signing key is required")
	}
	if err := p.Layout.Ensure(); err != nil {
		return Result{}, err
	}

	// The submit + poll + write machinery is shared with the join-key path; only the
	// credential acquisition differs. Adapt SSOParams onto the shared Params helpers.
	base := Params{
		GatewayURL: p.GatewayURL, Layout: p.Layout,
		RequestedName: p.RequestedName, RequestedGroups: p.RequestedGroups,
		PinnedConfigPub: p.PinnedConfigPub, HTTPClient: p.HTTPClient,
		PollTimeout: p.PollTimeout, Now: p.Now,
	}

	// 1. Host key (generate once, reuse on retry — P1).
	kp, err := loadOrGenerate(p.Layout)
	if err != nil {
		return Result{}, err
	}
	pubBytes := kp.PublicKeyBytes()
	pubkeyHash := wire.PubkeyHash(pubBytes)

	// Resume an existing ticket if we have one (host was left PENDING). An SSO host
	// awaiting approval re-runs `pilot enroll --sso` and goes straight to the poll —
	// no second browser round-trip, no second nonce.
	ticketPath := p.Layout.EnrollTicket()
	if acc, resumed := loadTicket(ticketPath); resumed {
		return base.finishEnroll(ctx, pubBytes, acc, ticketPath)
	}

	// 2. Pubkey-bound nonce (the same /v1/nonce the join-key path uses).
	nonce, err := base.fetchNonce(ctx, pubkeyHash)
	if err != nil {
		return Result{}, err
	}

	// 3. Loopback listener + one-shot /callback handler.
	lb, err := newLoopback()
	if err != nil {
		return Result{}, err
	}
	defer lb.close()

	// 4. Ask the gateway portal to begin an IdP session bound to {pubkey_hash, nonce,
	// loopback redirect}; obtain the IdP authorize URL it would redirect the browser to
	// (observe the 302 Location WITHOUT auto-following into the IdP).
	authorizeURL, err := p.startSSO(ctx, pubkeyHash, nonce, lb.redirectURL())
	if err != nil {
		return Result{}, err
	}

	// 5. Open the user's browser to the IdP (best-effort). Always also print the URL so
	// the user can complete the flow even if the open fails.
	fmt.Printf("enroll --sso: opening your browser to sign in:\n  %s\n", authorizeURL)
	if err := p.OpenBrowser(authorizeURL); err != nil {
		fmt.Printf("enroll --sso: could not open a browser automatically (%v).\n  Open this URL to continue: %s\n", err, authorizeURL)
	}

	// 6. Wait for the browser to deliver the gateway-signed assertion to /callback.
	assertion, err := lb.wait(ctx, p.SSOWait)
	if err != nil {
		return Result{}, err
	}

	// 7. Submit the standard EnrollRequest carrying the SSO credential envelope (B5).
	credential, _ := json.Marshal(map[string]string{"assertion": assertion})
	acc, err := base.submitEnroll(ctx, kp, pubBytes, pubkeyHash, nonce, wire.MethodOIDC, credential)
	if err != nil {
		return Result{}, err
	}

	// 8. Poll for the bundle. SSO defaults to PENDING (S8): a "pending" Result is
	// returned cleanly (not an error); the CLI surfaces it as "awaiting approval".
	return base.finishEnroll(ctx, pubBytes, acc, ticketPath)
}

// startSSO calls GET /v1/sso/start with the device binding + loopback redirect and
// returns the IdP authorize URL the gateway would 302 the browser to. It does NOT
// auto-follow the redirect into the IdP — it reads the Location off the 302 so pilot
// can hand the URL to the user's own browser (cookies, MFA, SSO session all live
// there, not in this client).
func (p SSOParams) startSSO(ctx context.Context, pubkeyHash, nonce, redirect string) (string, error) {
	v := url.Values{
		"pubkey_hash": {pubkeyHash},
		"nonce":       {nonce},
		"redirect":    {redirect},
	}
	reqURL := p.GatewayURL + "/v1/sso/start?" + v.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
	if err != nil {
		return "", err
	}
	// Don't auto-follow: capture the 302 Location (the IdP authorize URL) ourselves.
	noFollow := &http.Client{
		Timeout:       p.HTTPClient.Timeout,
		Transport:     p.HTTPClient.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := noFollow.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		// 404 = SSO not enabled on this gateway; 4xx = bad nonce/redirect, etc.
		return "", fmt.Errorf("enrollclient: sso/start -> %d (SSO may not be enabled on this gateway)", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", fmt.Errorf("enrollclient: sso/start returned no redirect location")
	}
	return loc, nil
}

// loopback is the one-shot local HTTP listener that catches the gateway's redirect to
// http://127.0.0.1:<port>/callback?assertion=<jws>&state=<state>.
type loopback struct {
	ln   net.Listener
	srv  *http.Server
	done chan string // receives the captured assertion (closed/zero on shutdown)
}

// newLoopback binds an ephemeral loopback port and mounts the one-shot /callback.
func newLoopback() (*loopback, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("enrollclient: bind loopback listener: %w", err)
	}
	lb := &loopback{ln: ln, done: make(chan string, 1)}
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		assertion := r.URL.Query().Get("assertion")
		if assertion == "" {
			http.Error(w, "missing assertion", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(callbackHTML))
		// Deliver once; a duplicate/late hit is harmless (buffered, non-blocking).
		select {
		case lb.done <- assertion:
		default:
		}
	})
	lb.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = lb.srv.Serve(ln) }()
	return lb, nil
}

// redirectURL is the loopback /callback URL handed to the gateway as the SSO redirect.
func (lb *loopback) redirectURL() string {
	return "http://" + lb.ln.Addr().String() + "/callback"
}

// wait blocks until the browser hits /callback with an assertion, the timeout elapses,
// or ctx is cancelled.
func (lb *loopback) wait(ctx context.Context, timeout time.Duration) (string, error) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case a := <-lb.done:
		return a, nil
	case <-t.C:
		return "", fmt.Errorf("enrollclient: timed out after %s waiting for the SSO browser sign-in", timeout)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// close shuts the loopback listener down (idempotent enough for a deferred call).
func (lb *loopback) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = lb.srv.Shutdown(ctx)
}

// callbackHTML is the page shown in the user's browser after the assertion lands.
const callbackHTML = `<!doctype html><html><head><meta charset="utf-8"><title>Enrollment</title></head>` +
	`<body style="font-family:sans-serif"><h2>Sign-in complete</h2>` +
	`<p>You can close this tab and return to the terminal.</p></body></html>`

// openBrowser opens url in the user's default browser, best-effort and cross-platform.
// A failure is non-fatal: the caller always also prints the URL.
func openBrowser(target string) error {
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name, args = "open", []string{target}
	case "windows":
		name, args = "cmd", []string{"/c", "start", "", target}
	default: // linux, *bsd, …
		name, args = "xdg-open", []string{target}
	}
	if _, err := exec.LookPath(name); err != nil {
		return errors.New("no browser launcher (" + name + ") found")
	}
	return exec.Command(name, args...).Start()
}
