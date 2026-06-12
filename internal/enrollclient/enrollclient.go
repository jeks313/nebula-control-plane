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
	"strings"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/hostkey"
	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/nebulaconfig"
	"github.com/jeks313/nebula-control-plane/internal/paths"
	"github.com/jeks313/nebula-control-plane/internal/wire"
	"github.com/slackhq/nebula/cert"
)

// Params configures an enrollment run.
type Params struct {
	GatewayURL      string
	JoinKey         string
	Layout          paths.Layout
	RequestedName   string
	RequestedGroups []string
	PinnedConfigPub *ecdsa.PublicKey // the genesis config-signing key Pilot pins
	HTTPClient      *http.Client
	PollTimeout     time.Duration
	Now             func() time.Time
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
		req := wire.EnrollRequest{
			ProtocolVersion: wire.ProtocolVersion, Type: "enroll",
			IssuedAt: p.Now().UTC().Format(time.RFC3339), Nonce: nonce,
			Method: wire.MethodToken, Credential: json.RawMessage(`{"token":"` + p.JoinKey + `"}`),
		}
		req.CSR = wire.CSR{
			Curve: "P256", PublicKey: base64.RawURLEncoding.EncodeToString(pubBytes),
			RequestedName: p.RequestedName, RequestedGroups: p.RequestedGroups,
		}
		req.Client.SupportedProtocolVersions = []int{wire.ProtocolVersion}
		payload, _ := json.Marshal(req)
		env, err := jws.SignBackendES256(kp, jws.Header{Typ: wire.TypEnrollRequest, Ver: 1, Kid: pubkeyHash}, payload)
		if err != nil {
			return Result{}, err
		}
		body, _ := json.Marshal(env)
		if err := p.postJSON(ctx, "/v1/enroll", body, &acc); err != nil {
			return Result{}, err
		}
		// Persist the ticket so a PENDING host can resume after approval.
		_ = saveTicket(ticketPath, acc)
	}

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
	if err := p.writeArtifacts(b); err != nil {
		return Result{}, err
	}
	_ = os.Remove(ticketPath)
	return Result{Status: "issued", OverlayIP: b.Device.OverlayIP}, nil
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
// status. A not-yet-processed enrollment (404) or pending (202) keeps polling
// until PollTimeout, after which a still-pending enrollment returns "pending"
// (e.g. awaiting manual approval).
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
		case http.StatusAccepted, http.StatusNotFound:
			// pending or not-yet-processed: keep polling.
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

func (p Params) writeArtifacts(b bundle.Bundle) error {
	if err := os.WriteFile(p.Layout.CABundle(), []byte(strings.Join(b.CABundle, "\n")), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(p.Layout.HostCert(), []byte(b.Certificate), 0o644); err != nil {
		return err
	}
	lhs := make([]nebulaconfig.Lighthouse, len(b.Lighthouses))
	for i, l := range b.Lighthouses {
		lhs[i] = nebulaconfig.Lighthouse{OverlayIP: l.OverlayIP, PublicAddrs: l.PublicAddrs}
	}
	v := nebulaconfig.Values{
		Lighthouses: lhs,
		CACertPath:  p.Layout.CABundle(), CertPath: p.Layout.HostCert(), KeyPath: p.Layout.HostKey(),
	}
	v.Defaults()
	cfg, err := nebulaconfig.Render(v)
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
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, p.GatewayURL+path, nil)
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
