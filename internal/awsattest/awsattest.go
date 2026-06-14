// Package awsattest implements AWS SigV4 instance attestation (implementation-
// plan 5.1/5.2, design §6.1, protocol §5.4). It is the Vault pattern: the Pilot
// signs an `sts:GetCallerIdentity` request with its instance-role credentials,
// folding a Harbor nonce and its host-pubkey hash into the SigV4 signature
// (custom headers that MUST be in SignedHeaders). Core does not verify the
// signature itself — it forwards the request to AWS STS, which validates the
// signature (AWS vouches for the signer) and returns the caller's account + ARN.
// Core then enforces the nonce/pubkey binding, an STS-host allowlist (SSRF
// discipline, design §6.1), and an account/role-path allowlist.
//
// No bespoke crypto (P11): SigV4 is the standard construction (HMAC-SHA256
// chain), implemented to AWS's spec and pinned by a known-answer test.
package awsattest

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Binding header names — these carry the Harbor nonce + host-pubkey hash and
// MUST be covered by the SigV4 signature.
const (
	HeaderNonce      = "X-Harbor-Nonce"
	HeaderPubkeyHash = "X-Harbor-Pubkey-Hash"
)

const (
	stsService = "sts"
	stsBody    = "Action=GetCallerIdentity&Version=2011-06-15"
	stsContent = "application/x-www-form-urlencoded; charset=utf-8"
	algorithm  = "AWS4-HMAC-SHA256"
)

// Errors callers can branch on.
var (
	ErrBinding         = errors.New("awsattest: nonce/pubkey binding mismatch")
	ErrUnsignedBinding = errors.New("awsattest: binding header not covered by the SigV4 signature")
	ErrBadRequest      = errors.New("awsattest: malformed presigned request")
	ErrBadEndpoint     = errors.New("awsattest: STS endpoint is not an allowlisted AWS STS host")
	ErrAttestation     = errors.New("awsattest: STS rejected the attestation")
	ErrNotAllowed      = errors.New("awsattest: caller account/role is not allowlisted")
	// ErrSTSUnavailable is an STS-side unavailability (transport timeout/DNS/refused, or
	// an HTTP 429/5xx) — distinct from ErrAttestation, which is STS actively REJECTING
	// the caller (a 4xx, e.g. a forged/expired signature). The caller decides policy;
	// the enroll consumer treats both as a fail-closed denial (the host re-enrolls with
	// a fresh nonce), but the distinct error gives a clear "unavailable vs rejected" reason.
	ErrSTSUnavailable = errors.New("awsattest: STS unavailable")
)

// Credentials are AWS credentials (from the instance role via IMDS, 5.1).
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string // present for instance-role (temporary) credentials
}

// PresignedRequest mirrors the wire credential payload (protocol §5.4): the
// fully signed GetCallerIdentity request Core will forward to STS.
type PresignedRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// Sign builds a SigV4-signed GetCallerIdentity request bound to nonce +
// pubkeyHash (Pilot side, 5.1). region selects the regional STS endpoint.
func Sign(creds Credentials, region, nonce, pubkeyHash string, now time.Time) (PresignedRequest, error) {
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return PresignedRequest{}, errors.New("awsattest: empty credentials")
	}
	if region == "" {
		return PresignedRequest{}, errors.New("awsattest: region required")
	}
	if nonce == "" || pubkeyHash == "" {
		return PresignedRequest{}, errors.New("awsattest: nonce and pubkey hash required")
	}
	host := "sts." + region + ".amazonaws.com"
	amzDate := now.UTC().Format("20060102T150405Z")

	headers := map[string]string{
		"host":                 host,
		"content-type":         stsContent,
		"x-amz-date":           amzDate,
		"x-harbor-nonce":       nonce,
		"x-harbor-pubkey-hash": pubkeyHash,
	}
	if creds.SessionToken != "" {
		headers["x-amz-security-token"] = creds.SessionToken
	}

	auth := sign(creds, region, stsService, "POST", "/", "", headers, stsBody, now)

	// Emit canonical (Title-Case-ish) header keys for the wire payload; Core
	// reads them case-insensitively.
	out := map[string]string{
		"Host":           host,
		"Content-Type":   stsContent,
		"X-Amz-Date":     amzDate,
		HeaderNonce:      nonce,
		HeaderPubkeyHash: pubkeyHash,
		"Authorization":  auth,
	}
	if creds.SessionToken != "" {
		out["X-Amz-Security-Token"] = creds.SessionToken
	}
	return PresignedRequest{
		Method:  "POST",
		URL:     "https://" + host + "/",
		Headers: out,
		Body:    stsBody,
	}, nil
}

// sign computes the SigV4 Authorization header value for a request. It is the
// standard algorithm (AWS docs "Signature Version 4 signing process"), kept as a
// small testable unit pinned by a known-answer test.
func sign(creds Credentials, region, service, method, path, query string, headers map[string]string, body string, now time.Time) string {
	amzDate := headers["x-amz-date"]
	dateStamp := amzDate[:8]

	// Canonical headers + signed-header list (lowercased keys, sorted).
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, strings.ToLower(k))
	}
	sort.Strings(keys)
	var canonHeaders strings.Builder
	for _, k := range keys {
		canonHeaders.WriteString(k)
		canonHeaders.WriteString(":")
		canonHeaders.WriteString(strings.TrimSpace(headers[canonicalKey(headers, k)]))
		canonHeaders.WriteString("\n")
	}
	signedHeaders := strings.Join(keys, ";")

	payloadHash := sha256hex([]byte(body))
	canonicalRequest := strings.Join([]string{
		method, path, query, canonHeaders.String(), signedHeaders, payloadHash,
	}, "\n")

	scope := dateStamp + "/" + region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		algorithm, amzDate, scope, sha256hex([]byte(canonicalRequest)),
	}, "\n")

	signingKey := hmacBytes(hmacBytes(hmacBytes(hmacBytes([]byte("AWS4"+creds.SecretAccessKey), []byte(dateStamp)), []byte(region)), []byte(service)), []byte("aws4_request"))
	signature := hex.EncodeToString(hmacBytes(signingKey, []byte(stringToSign)))

	return fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm, creds.AccessKeyID, scope, signedHeaders, signature)
}

// canonicalKey finds the original-cased key in headers matching lowercase lk.
func canonicalKey(headers map[string]string, lk string) string {
	for k := range headers {
		if strings.EqualFold(k, lk) {
			return k
		}
	}
	return lk
}

// IMDSConfig configures the instance-metadata fetch (Pilot, 5.1). BaseURL
// defaults to the link-local IMDS address; tests point it at a fake server.
type IMDSConfig struct {
	BaseURL    string
	HTTPClient *http.Client
}

// FetchInstanceCredentials reads the instance role's temporary credentials and
// region via IMDSv2 (token-protected). Used on a real EC2 instance; unit-tested
// against a fake IMDS. Returns creds + region for Sign.
func FetchInstanceCredentials(ctx context.Context, cfg IMDSConfig) (Credentials, string, error) {
	base := cfg.BaseURL
	if base == "" {
		base = "http://169.254.169.254"
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}

	// IMDSv2: get a session token first (PUT), then use it on every GET.
	tokReq, _ := http.NewRequestWithContext(ctx, "PUT", base+"/latest/api/token", http.NoBody)
	tokReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
	tokResp, err := client.Do(tokReq)
	if err != nil {
		return Credentials{}, "", fmt.Errorf("awsattest: imds token: %w", err)
	}
	tokB, _ := io.ReadAll(io.LimitReader(tokResp.Body, 4096))
	tokResp.Body.Close()
	token := strings.TrimSpace(string(tokB))

	get := func(path string) (string, error) {
		r, _ := http.NewRequestWithContext(ctx, "GET", base+path, http.NoBody)
		if token != "" {
			r.Header.Set("X-aws-ec2-metadata-token", token)
		}
		resp, err := client.Do(r)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("awsattest: imds %s: status %d", path, resp.StatusCode)
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return strings.TrimSpace(string(b)), nil
	}

	region, err := get("/latest/meta-data/placement/region")
	if err != nil {
		return Credentials{}, "", err
	}
	role, err := get("/latest/meta-data/iam/security-credentials/")
	if err != nil {
		return Credentials{}, "", err
	}
	if role == "" {
		return Credentials{}, "", errors.New("awsattest: instance has no IAM role (sigv4 attestation requires one)")
	}
	credJSON, err := get("/latest/meta-data/iam/security-credentials/" + role)
	if err != nil {
		return Credentials{}, "", err
	}
	var c struct {
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
	}
	if err := json.Unmarshal([]byte(credJSON), &c); err != nil {
		return Credentials{}, "", fmt.Errorf("awsattest: imds creds: %w", err)
	}
	return Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.Token}, region, nil
}

// Identity is the verified caller identity from STS.
type Identity struct {
	Account string
	Arn     string
	UserID  string
}

var stsHostRE = regexp.MustCompile(`^sts(\.[a-z0-9-]+)?\.amazonaws\.com$`)

// VerifyConfig parameterizes Core-side verification.
type VerifyConfig struct {
	// HTTPClient executes the STS call (default: a no-redirect client, 5s timeout).
	HTTPClient *http.Client
	// Endpoint, if set, overrides where the request is POSTed (tests). The SigV4
	// host allowlist is still enforced against the signed PresignedRequest.URL.
	Endpoint string
}

// Verify enforces the binding, the STS-host allowlist (SSRF), then forwards the
// request to STS and parses the returned identity (Core side, 5.2). It does NOT
// validate the SigV4 signature itself — STS does, which is the whole point.
func Verify(ctx context.Context, pres PresignedRequest, expectedNonce, expectedPubkeyHash string, cfg VerifyConfig) (Identity, error) {
	if !strings.EqualFold(pres.Method, "POST") || pres.Body != stsBody {
		return Identity{}, fmt.Errorf("%w: method/body", ErrBadRequest)
	}
	h := lowerHeaders(pres.Headers)

	// 1) Binding values must match this enrollment's nonce + pubkey.
	if h["x-harbor-nonce"] != expectedNonce || h["x-harbor-pubkey-hash"] != expectedPubkeyHash {
		return Identity{}, ErrBinding
	}

	// 2) The binding headers must be in SignedHeaders — otherwise an attacker
	// could bolt them onto someone else's validly-signed request.
	signed, err := signedHeaderSet(h["authorization"])
	if err != nil {
		return Identity{}, err
	}
	if !signed["x-harbor-nonce"] || !signed["x-harbor-pubkey-hash"] || !signed["host"] {
		return Identity{}, ErrUnsignedBinding
	}

	// 3) SSRF: the signed URL must be an AWS STS host over https.
	u, err := url.Parse(pres.URL)
	if err != nil || u.Scheme != "https" || !stsHostRE.MatchString(u.Hostname()) {
		return Identity{}, ErrBadEndpoint
	}

	// 4) Forward to STS (operator-configured endpoint in tests; the signed URL in
	// prod). Attestation content never selects a prod URL.
	target := pres.URL
	if cfg.Endpoint != "" {
		target = cfg.Endpoint
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout:       5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	req, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(pres.Body))
	if err != nil {
		return Identity{}, err
	}
	for k, v := range pres.Headers {
		req.Header.Set(k, v)
	}
	req.Host = u.Host // preserve the signed Host even when Endpoint redirects execution
	resp, err := client.Do(req)
	if err != nil {
		// Transport failure (STS unreachable) — transient, not a rejection.
		return Identity{}, fmt.Errorf("%w: %w", ErrSTSUnavailable, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		// Throttling / STS-side degradation — unavailable, not a rejection of the caller.
		return Identity{}, fmt.Errorf("%w: STS status %d", ErrSTSUnavailable, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		// A 4xx sender rejection (e.g. 403 for a forged/expired signature) — terminal.
		return Identity{}, fmt.Errorf("%w: STS status %d", ErrAttestation, resp.StatusCode)
	}

	var out struct {
		Result struct {
			Account string `xml:"Account"`
			Arn     string `xml:"Arn"`
			UserID  string `xml:"UserId"`
		} `xml:"GetCallerIdentityResult"`
	}
	if err := xml.Unmarshal(raw, &out); err != nil || out.Result.Account == "" {
		return Identity{}, fmt.Errorf("%w: unparseable STS response", ErrAttestation)
	}
	return Identity{Account: out.Result.Account, Arn: out.Result.Arn, UserID: out.Result.UserID}, nil
}

// Policy is the account + role-path allowlist (design §6.1): groups are derived
// elsewhere from immutable facts (5.5); this gate decides who may attest at all.
type Policy struct {
	Accounts    []string // allowed AWS account IDs (empty = any account)
	ARNPatterns []string // allowed caller ARNs as glob-ish patterns (empty = any)
}

// Check enforces the allowlist on a verified identity.
func (p Policy) Check(id Identity) error {
	if len(p.Accounts) > 0 && !contains(p.Accounts, id.Account) {
		return fmt.Errorf("%w: account %s", ErrNotAllowed, id.Account)
	}
	if len(p.ARNPatterns) > 0 {
		ok := false
		for _, pat := range p.ARNPatterns {
			if matchGlob(pat, id.Arn) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%w: arn %s", ErrNotAllowed, id.Arn)
		}
	}
	return nil
}

func signedHeaderSet(authz string) (map[string]bool, error) {
	const marker = "SignedHeaders="
	i := strings.Index(authz, marker)
	if i < 0 {
		return nil, fmt.Errorf("%w: no Authorization/SignedHeaders", ErrBadRequest)
	}
	rest := authz[i+len(marker):]
	if c := strings.IndexByte(rest, ','); c >= 0 {
		rest = rest[:c]
	}
	set := map[string]bool{}
	for _, h := range strings.Split(strings.TrimSpace(rest), ";") {
		set[strings.ToLower(h)] = true
	}
	return set, nil
}

func lowerHeaders(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[strings.ToLower(k)] = v
	}
	return out
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func hmacBytes(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// matchGlob does simple '*'-glob matching (sufficient for ARN role-path
// allowlisting, e.g. "arn:aws:sts::123456789012:assumed-role/web-*/*").
func matchGlob(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for _, p := range parts[1 : len(parts)-1] {
		i := strings.Index(s, p)
		if i < 0 {
			return false
		}
		s = s[i+len(p):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}
