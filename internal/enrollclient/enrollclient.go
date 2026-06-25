// Package enrollclient is Pilot's enrollment client (implementation-plan 3.7).
// It runs the async flow against the gateway — generate key → fetch nonce →
// submit a signed request → poll for the result → verify the bundle against the
// pinned config-signing key → verify the cert against the CA → write files +
// render config — so a bare host can join with one command.
package enrollclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/awsattest"
	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/hostkey"
	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/paths"
	"github.com/jeks313/nebula-control-plane/internal/wire"
	"github.com/slackhq/nebula/cert"
)

// Params configures an enrollment run.
type Params struct {
	GatewayURL      string
	JoinKey         string // token method; empty when AWSSigV4 is set
	AWSSigV4        bool   // attest via the instance role (IMDS) instead of a join key (M5)
	Region          string // STS region for AWS attestation; default = the IMDS-derived region
	Layout          paths.Layout
	RequestedName   string
	RequestedGroups []string
	PinnedConfigPub *ecdsa.PublicKey // the genesis config-signing key Pilot pins
	HTTPClient      *http.Client
	PollTimeout     time.Duration
	Now             func() time.Time

	imds awsattest.IMDSConfig // testability seam: override the IMDS endpoint (zero = real 169.254.169.254)
}

// enrollCredential builds the method + credential for the enroll request: an
// AWS-SigV4 presigned STS identity (bound to this nonce + pubkey) when AWSSigV4 is
// set, else the join-key token.
func (p Params) enrollCredential(ctx context.Context, nonce, pubkeyHash string) (string, json.RawMessage, error) {
	if p.AWSSigV4 {
		creds, region, err := awsattest.FetchInstanceCredentials(ctx, p.imds)
		if err != nil {
			return "", nil, fmt.Errorf("enrollclient: fetch instance credentials (IMDS): %w", err)
		}
		if p.Region != "" {
			region = p.Region
		}
		pres, err := awsattest.Sign(creds, region, nonce, pubkeyHash, p.Now())
		if err != nil {
			return "", nil, fmt.Errorf("enrollclient: sign attestation: %w", err)
		}
		cred, _ := json.Marshal(pres)
		return wire.MethodAWSSigV4, cred, nil
	}
	if p.JoinKey == "" {
		return "", nil, fmt.Errorf("enrollclient: a join key is required (or set AWSSigV4)")
	}
	cred, _ := json.Marshal(map[string]string{"token": p.JoinKey})
	return wire.MethodToken, cred, nil
}

// Result is the outcome of an enrollment run.
type Result struct {
	Status    string // issued | denied | pending
	OverlayIP string
	Reason    string
}

// Enroll runs the full client flow.
func Enroll(ctx context.Context, p Params) (Result, error) {
	if p.HTTPClient == nil {
		p.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if p.PollTimeout <= 0 {
		p.PollTimeout = 60 * time.Second
	}
	if p.Now == nil {
		p.Now = time.Now
	}
	if p.PinnedConfigPub == nil {
		return Result{}, fmt.Errorf("enrollclient: a pinned config-signing key is required")
	}
	if err := p.Layout.Ensure(); err != nil {
		return Result{}, err
	}

	// 1. Host key (generate once, reuse on retry — P1).
	kp, err := loadOrGenerate(p.Layout)
	if err != nil {
		return Result{}, err
	}
	pubBytes := kp.PublicKeyBytes()
	pubkeyHash := wire.PubkeyHash(pubBytes)

	// 2–4. Resume an existing ticket if we have one (host was left PENDING);
	// otherwise fetch a nonce, sign the request (proof of possession), and submit.
	ticketPath := p.Layout.EnrollTicket()
	acc, resumed := loadTicket(ticketPath)
	if !resumed {
		nonce, err := p.fetchNonce(ctx, pubkeyHash)
		if err != nil {
			return Result{}, err
		}
		method, credential, err := p.enrollCredential(ctx, nonce, pubkeyHash)
		if err != nil {
			return Result{}, err
		}
		acc, err = p.submitEnroll(ctx, kp, pubBytes, pubkeyHash, nonce, method, credential)
		if err != nil {
			return Result{}, err
		}
	}

	// 5–7. Poll -> verify -> write.
	return p.finishEnroll(ctx, pubBytes, acc, ticketPath)
}

// submitEnroll builds, signs (proof of possession), and POSTs the EnrollRequest,
// then persists the returned ticket so a PENDING host can resume after approval.
// The method + credential are the only things that vary across enrollment methods
// (join-key token, aws-sigv4, sso/oidc); everything else — the CSR, the client
// block, the JWS envelope, the submit, and the ticket persistence — is shared.
func (p Params) submitEnroll(ctx context.Context, kp *hostkey.KeyPair, pubBytes []byte, pubkeyHash, nonce, method string, credential json.RawMessage) (wire.EnrollAccepted, error) {
	req := wire.EnrollRequest{
		ProtocolVersion: wire.ProtocolVersion, Type: "enroll",
		IssuedAt: p.Now().UTC().Format(time.RFC3339), Nonce: nonce,
		Method: method, Credential: credential,
	}
	req.CSR = wire.CSR{
		Curve: "P256", PublicKey: base64.RawURLEncoding.EncodeToString(pubBytes),
		RequestedName: p.RequestedName, RequestedGroups: p.RequestedGroups,
	}
	req.Client.SupportedProtocolVersions = []int{wire.ProtocolVersion}
	req.Client.OS, req.Client.Arch = runtime.GOOS, runtime.GOARCH // per-arch release selection
	payload, _ := json.Marshal(req)
	env, err := jws.SignBackendES256(kp, jws.Header{Typ: wire.TypEnrollRequest, Ver: 1, Kid: pubkeyHash}, payload)
	if err != nil {
		return wire.EnrollAccepted{}, err
	}
	body, _ := json.Marshal(env)
	var acc wire.EnrollAccepted
	if err := p.postJSON(ctx, "/v1/enroll", body, &acc); err != nil {
		return wire.EnrollAccepted{}, err
	}
	_ = saveTicket(p.Layout.EnrollTicket(), acc)
	return acc, nil
}

// finishEnroll polls for the result, then on "issued" verifies the bundle against
// the pinned config-signing key + the cert against the CA and writes the files. A
// "pending" result keeps the ticket (resumable after approval); "denied" removes it.
func (p Params) finishEnroll(ctx context.Context, pubBytes []byte, acc wire.EnrollAccepted, ticketPath string) (Result, error) {
	// 5. Poll -> bundle.
	bundleJWS, status, reason, err := p.poll(ctx, acc)
	if err != nil {
		return Result{}, err
	}
	if status != "issued" {
		if status == "denied" {
			_ = os.Remove(ticketPath) // terminal
		}
		return Result{Status: status, Reason: reason}, nil // pending keeps the ticket
	}

	// 6. Verify bundle against the pinned config-signing key, then the cert.
	b, err := bundle.Verify(bundleJWS, p.PinnedConfigPub)
	if err != nil {
		return Result{}, fmt.Errorf("enrollclient: %w", err)
	}
	if err := verifyCert(b, pubBytes); err != nil {
		return Result{}, err
	}

	// 7. Write files + render config; the ticket is spent.
	if err := p.writeArtifacts(b, bundleJWS); err != nil {
		return Result{}, err
	}
	_ = os.Remove(ticketPath)
	return Result{Status: "issued", OverlayIP: b.Device.OverlayIP}, nil
}

// RenewParams configures a renewal run (M4.4).
type RenewParams struct {
	CoreURL         string // Core API base URL (reached over the mesh)
	Layout          paths.Layout
	PinnedConfigPub *ecdsa.PublicKey
	HTTPClient      *http.Client
	Now             func() time.Time
}

// Renew rotates to a fresh key and re-certifies the same identity over the mesh
// (the tunnel authenticates us by our overlay IP). It atomically swaps in the
// new key + cert; a supervised SIGHUP then hot-reloads nebula (same IP/curve).
func Renew(ctx context.Context, p RenewParams) (Result, error) {
	if p.HTTPClient == nil {
		p.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if p.Now == nil {
		p.Now = time.Now
	}
	if p.PinnedConfigPub == nil {
		return Result{}, fmt.Errorf("enrollclient: a pinned config-signing key is required")
	}

	newKP, err := hostkey.Generate()
	if err != nil {
		return Result{}, err
	}
	newPub := newKP.PublicKeyBytes()
	req := wire.RenewRequest{
		ProtocolVersion: wire.ProtocolVersion, Type: "renew",
		IssuedAt: p.Now().UTC().Format(time.RFC3339),
		CSR:      wire.CSR{Curve: "P256", PublicKey: base64.RawURLEncoding.EncodeToString(newPub)},
	}
	payload, _ := json.Marshal(req)
	env, err := jws.SignBackendES256(newKP, jws.Header{Typ: wire.TypRenewRequest, Ver: 1, Kid: wire.PubkeyHash(newPub)}, payload)
	if err != nil {
		return Result{}, err
	}
	reqBody, _ := json.Marshal(env)

	r, err := http.NewRequestWithContext(ctx, http.MethodPost, p.CoreURL+"/v1/certs/renew", bytes.NewReader(reqBody))
	if err != nil {
		return Result{}, err
	}
	r.Header.Set("Content-Type", "application/json")
	code, respBody, err := (Params{HTTPClient: p.HTTPClient}).do(r)
	if err != nil {
		return Result{}, err
	}
	if code != http.StatusOK {
		return Result{}, fmt.Errorf("enrollclient: renew -> %d: %s", code, respBody)
	}
	var rr wire.RenewResponse
	if err := json.Unmarshal(respBody, &rr); err != nil {
		return Result{}, err
	}

	b, err := bundle.Verify(rr.Bundle, p.PinnedConfigPub)
	if err != nil {
		return Result{}, fmt.Errorf("enrollclient: %w", err)
	}
	if err := verifyCert(b, newPub); err != nil {
		return Result{}, err
	}

	// Atomically rotate in the new key, then the cert/config.
	if err := newKP.WritePrivateKeyAtomic(p.Layout.HostKey()); err != nil {
		return Result{}, err
	}
	if err := newKP.WritePublicKey(p.Layout.HostPub()); err != nil {
		return Result{}, err
	}
	if err := (Params{Layout: p.Layout}).writeArtifacts(b, rr.Bundle); err != nil {
		return Result{}, err
	}
	return Result{Status: "issued", OverlayIP: b.Device.OverlayIP}, nil
}

// FetchConfig pulls the host's CURRENT signed config bundle (GET /v1/config) and
// applies the config WITHOUT rotating or rewriting the cert/key — the cheap
// refresh a Pilot runs on an apply_bundle command so a blocklist/policy/lighthouse
// change propagates fast (7.1b). The bundle is verified against the pinned
// config-signing key; only the CA bundle + rendered config.yml are (re)written, so
// a renewed host's on-disk cert is never clobbered by Core's enroll-time copy.
func FetchConfig(ctx context.Context, p RenewParams) (Result, error) {
	if p.HTTPClient == nil {
		p.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if p.PinnedConfigPub == nil {
		return Result{}, fmt.Errorf("enrollclient: a pinned config-signing key is required")
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, p.CoreURL+"/v1/config", http.NoBody)
	if err != nil {
		return Result{}, err
	}
	code, respBody, err := (Params{HTTPClient: p.HTTPClient}).do(r)
	if err != nil {
		return Result{}, err
	}
	if code != http.StatusOK {
		return Result{}, fmt.Errorf("enrollclient: config -> %d: %s", code, respBody)
	}
	var cr wire.ConfigResponse
	if err := json.Unmarshal(respBody, &cr); err != nil {
		return Result{}, err
	}
	b, err := bundle.Verify(cr.Bundle, p.PinnedConfigPub)
	if err != nil {
		return Result{}, fmt.Errorf("enrollclient: %w", err)
	}
	if err := (Params{Layout: p.Layout}).writeConfigArtifacts(b, cr.Bundle); err != nil {
		return Result{}, err
	}
	return Result{Status: "config", OverlayIP: b.Device.OverlayIP}, nil
}

type ticket struct {
	EnrollmentID    string `json:"enrollment_id"`
	RetrievalSecret string `json:"retrieval_secret"`
	PollAfterMs     int    `json:"poll_after_ms"`
}

func loadTicket(path string) (wire.EnrollAccepted, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return wire.EnrollAccepted{}, false
	}
	var t ticket
	if json.Unmarshal(raw, &t) != nil || t.EnrollmentID == "" || t.RetrievalSecret == "" {
		return wire.EnrollAccepted{}, false
	}
	return wire.EnrollAccepted{EnrollmentID: t.EnrollmentID, RetrievalSecret: t.RetrievalSecret, PollAfterMs: t.PollAfterMs}, true
}

func saveTicket(path string, acc wire.EnrollAccepted) error {
	raw, _ := json.Marshal(ticket{EnrollmentID: acc.EnrollmentID, RetrievalSecret: acc.RetrievalSecret, PollAfterMs: acc.PollAfterMs})
	return os.WriteFile(path, raw, 0o600) // contains the retrieval secret
}

func loadOrGenerate(layout paths.Layout) (*hostkey.KeyPair, error) {
	if _, err := os.Stat(layout.HostKey()); err == nil {
		return hostkey.Load(layout.HostKey())
	}
	kp, err := hostkey.Generate()
	if err != nil {
		return nil, err
	}
	if err := kp.WritePrivateKey(layout.HostKey()); err != nil {
		return nil, err
	}
	if err := kp.WritePublicKey(layout.HostPub()); err != nil {
		return nil, err
	}
	return kp, nil
}

func (p Params) fetchNonce(ctx context.Context, binding string) (string, error) {
	var nr wire.NonceResponse
	if err := p.getJSON(ctx, "/v1/nonce?binding="+url.QueryEscape(binding), &nr); err != nil {
		return "", err
	}
	if nr.Nonce == "" {
		return "", fmt.Errorf("enrollclient: empty nonce")
	}
	return nr.Nonce, nil
}

// poll waits for the result, returning the issued bundle JWS or a terminal
// status. A not-yet-processed enrollment (404 — Core hasn't written a result row
// yet) keeps polling until PollTimeout. A pending result (202 — Core processed it
// and parked it for manual approval) returns "pending" IMMEDIATELY: that state
// only clears via a separate admin approve/deny, so polling on would just burn the
// timeout. On timeout with only 404s, it also returns "pending" (Core never got to
// it within the window). Callers print "awaiting approval" and the operator re-runs
// after approval (the ticket resumes the poll).
func (p Params) poll(ctx context.Context, acc wire.EnrollAccepted) (bundleJWS []byte, status, reason string, err error) {
	interval := time.Duration(acc.PollAfterMs) * time.Millisecond
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	deadline := p.Now().Add(p.PollTimeout)
	for p.Now().Before(deadline) {
		code, respBody, err := p.get(ctx, "/v1/enroll/"+acc.EnrollmentID, acc.RetrievalSecret)
		if err != nil {
			return nil, "", "", err
		}
		switch code {
		case http.StatusOK:
			var pr wire.PollResponse
			if err := json.Unmarshal(respBody, &pr); err != nil {
				return nil, "", "", err
			}
			if pr.Status == "issued" {
				return pr.Bundle, "issued", "", nil
			}
			return nil, pr.Status, pr.Reason, nil // denied
		case http.StatusNotFound:
			// Core hasn't written a result row yet (still queued / being processed): keep polling.
		case http.StatusAccepted:
			// Core processed this and is holding it for manual admin approval. 202 means a
			// status="pending" result row EXISTS (a not-yet-processed candidate is the 404 above,
			// never 202), and Core only writes that pending row at a terminal needs-approval
			// decision — it never flips to issued/denied without a separate admin action. So don't
			// burn PollTimeout waiting: return "pending" now; the caller reports "awaiting approval"
			// and the operator re-runs after approval (the ticket resumes). Tradeoff: an approval
			// that lands DURING this call no longer auto-completes — re-run to fetch the bundle.
			return nil, "pending", "", nil
		case http.StatusGone:
			return nil, "", "", fmt.Errorf("enrollclient: result expired/consumed")
		default:
			return nil, "", "", fmt.Errorf("enrollclient: poll status %d: %s", code, respBody)
		}
		select {
		case <-ctx.Done():
			return nil, "", "", ctx.Err()
		case <-time.After(interval):
		}
	}
	return nil, "pending", "", nil
}

func verifyCert(b bundle.Bundle, pubBytes []byte) error {
	pool, err := cert.NewCAPoolFromPEM([]byte(strings.Join(b.CABundle, "\n")))
	if err != nil {
		return fmt.Errorf("enrollclient: parse CA bundle: %w", err)
	}
	leaf, _, err := cert.UnmarshalCertificateFromPEM([]byte(b.Certificate))
	if err != nil {
		return fmt.Errorf("enrollclient: parse leaf: %w", err)
	}
	if _, err := pool.VerifyCertificate(time.Now(), leaf); err != nil {
		return fmt.Errorf("enrollclient: leaf does not verify against CA: %w", err)
	}
	if !bytes.Equal(leaf.PublicKey(), pubBytes) {
		return fmt.Errorf("enrollclient: issued cert is not bound to our key")
	}
	return nil
}

func (p Params) writeArtifacts(b bundle.Bundle, rawBundleJWS []byte) error {
	if err := os.WriteFile(p.Layout.CABundle(), []byte(strings.Join(b.CABundle, "\n")), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(p.Layout.HostCert(), []byte(b.Certificate), 0o644); err != nil {
		return err
	}
	// Retain the signed bundle so drift detection (M6.7) can re-assert it.
	if err := os.WriteFile(p.Layout.Bundle(), rawBundleJWS, 0o644); err != nil {
		return err
	}
	cfg, err := bundle.RenderNebulaConfig(b, p.Layout.CABundle(), p.Layout.HostCert(), p.Layout.HostKey())
	if err != nil {
		return err
	}
	return os.WriteFile(p.Layout.Config(), cfg, 0o644)
}

// writeConfigArtifacts applies a CONFIG-ONLY bundle (GET /v1/config, 7.1b): it
// refreshes the CA bundle, retains the signed bundle for drift (M6.7), and
// re-renders config.yml — but does NOT touch the host cert/key, so a fast config
// refresh can never clobber a renewed host's current cert with Core's stored copy.
func (p Params) writeConfigArtifacts(b bundle.Bundle, rawBundleJWS []byte) error {
	if err := os.WriteFile(p.Layout.CABundle(), []byte(strings.Join(b.CABundle, "\n")), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(p.Layout.Bundle(), rawBundleJWS, 0o644); err != nil {
		return err
	}
	cfg, err := bundle.RenderNebulaConfig(b, p.Layout.CABundle(), p.Layout.HostCert(), p.Layout.HostKey())
	if err != nil {
		return err
	}
	return os.WriteFile(p.Layout.Config(), cfg, 0o644)
}

// --- HTTP helpers ---

func (p Params) getJSON(ctx context.Context, path string, out any) error {
	code, body, err := p.get(ctx, path, "")
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("enrollclient: GET %s -> %d: %s", path, code, body)
	}
	return json.Unmarshal(body, out)
}

func (p Params) get(ctx context.Context, path, bearer string) (int, []byte, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, p.GatewayURL+path, http.NoBody)
	if err != nil {
		return 0, nil, err
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	return p.do(r)
}

func (p Params) postJSON(ctx context.Context, path string, body []byte, out any) error {
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, p.GatewayURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/json")
	code, resp, err := p.do(r)
	if err != nil {
		return err
	}
	if code != http.StatusAccepted {
		return fmt.Errorf("enrollclient: POST %s -> %d: %s", path, code, resp)
	}
	return json.Unmarshal(resp, out)
}

func (p Params) do(r *http.Request) (int, []byte, error) {
	resp, err := p.HTTPClient.Do(r)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}

// ParsePinnedConfigPub parses a config-signing public key PEM (from genesis) into
// the ecdsa key Pilot pins.
func ParsePinnedConfigPub(pemBytes []byte) (*ecdsa.PublicKey, error) {
	pub, _, curve, err := cert.UnmarshalPublicKeyFromPEM(pemBytes)
	if err != nil {
		return nil, err
	}
	if curve != cert.Curve_P256 {
		return nil, errors.New("enrollclient: config-signing key is not P256")
	}
	return jws.ParseP256PublicPoint(pub)
}
