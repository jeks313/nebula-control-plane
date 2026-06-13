package awsattest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestSigV4KnownAnswer pins the SigV4 math against AWS's published
// "get-vanilla" test-suite vector — proof we implement the standard, not a
// bespoke scheme (P11).
func TestSigV4KnownAnswer(t *testing.T) {
	creds := Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
	now := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	headers := map[string]string{
		"host":       "example.amazonaws.com",
		"x-amz-date": "20150830T123600Z",
	}
	got := sign(creds, "us-east-1", "service", "GET", "/", "", headers, "", now)
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
		"SignedHeaders=host;x-amz-date, " +
		"Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got != want {
		t.Fatalf("get-vanilla mismatch:\n got=%s\nwant=%s", got, want)
	}
}

func TestSignBindsNonceAndPubkey(t *testing.T) {
	creds := Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret", SessionToken: "tok"}
	pres, err := Sign(creds, "us-east-1", "nonce-abc", "pubhash-xyz", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if pres.Headers[HeaderNonce] != "nonce-abc" || pres.Headers[HeaderPubkeyHash] != "pubhash-xyz" {
		t.Fatal("binding headers not set")
	}
	if pres.URL != "https://sts.us-east-1.amazonaws.com/" {
		t.Fatalf("url = %s", pres.URL)
	}
	signed, err := signedHeaderSet(pres.Headers["Authorization"])
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"x-harbor-nonce", "x-harbor-pubkey-hash", "host", "x-amz-security-token"} {
		if !signed[h] {
			t.Fatalf("%q not in SignedHeaders", h)
		}
	}
	// Determinism + tamper sensitivity: a different nonce yields a different sig.
	other, _ := Sign(creds, "us-east-1", "nonce-DIFFERENT", "pubhash-xyz", timeFixed())
	same, _ := Sign(creds, "us-east-1", "nonce-abc", "pubhash-xyz", timeFixed())
	again, _ := Sign(creds, "us-east-1", "nonce-abc", "pubhash-xyz", timeFixed())
	if same.Headers["Authorization"] != again.Headers["Authorization"] {
		t.Fatal("signing not deterministic")
	}
	if same.Headers["Authorization"] == other.Headers["Authorization"] {
		t.Fatal("changing the nonce did not change the signature (binding broken)")
	}
}

func timeFixed() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

// fakeSTS simulates AWS STS: it returns the configured identity on 200 (i.e.
// AWS has validated the signature), or a 403 when told to reject.
func fakeSTS(t *testing.T, account, arn string, reject bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reject {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>`))
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult>` +
			`<Arn>` + arn + `</Arn><UserId>AROAEXAMPLE:i-0abc</UserId><Account>` + account + `</Account>` +
			`</GetCallerIdentityResult></GetCallerIdentityResponse>`))
	}))
}

func goodPres(t *testing.T) PresignedRequest {
	t.Helper()
	p, err := Sign(Credentials{AccessKeyID: "AKID", SecretAccessKey: "s", SessionToken: "tok"},
		"us-east-1", "nonce-1", "ph-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestVerifyHappyPath: a well-formed, bound request that STS accepts yields the
// caller identity, and the account/role allowlist passes.
func TestVerifyHappyPath(t *testing.T) {
	sts := fakeSTS(t, "123456789012", "arn:aws:sts::123456789012:assumed-role/web/i-0abc", false)
	defer sts.Close()

	id, err := Verify(context.Background(), goodPres(t), "nonce-1", "ph-1", VerifyConfig{Endpoint: sts.URL})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id.Account != "123456789012" {
		t.Fatalf("account = %s", id.Account)
	}
	pol := Policy{Accounts: []string{"123456789012"}, ARNPatterns: []string{"arn:aws:sts::123456789012:assumed-role/web/*"}}
	if err := pol.Check(id); err != nil {
		t.Fatalf("allowlist should pass: %v", err)
	}
}

func TestVerifyNonceMismatch(t *testing.T) {
	sts := fakeSTS(t, "123456789012", "arn", false)
	defer sts.Close()
	if _, err := Verify(context.Background(), goodPres(t), "WRONG-nonce", "ph-1", VerifyConfig{Endpoint: sts.URL}); err != ErrBinding {
		t.Fatalf("err = %v, want ErrBinding", err)
	}
}

// TestVerifyUnsignedBinding: an attacker bolts the binding headers onto a
// request whose signature does NOT cover them — must be refused.
func TestVerifyUnsignedBinding(t *testing.T) {
	sts := fakeSTS(t, "123456789012", "arn", false)
	defer sts.Close()
	p := goodPres(t)
	// Strip the binding headers from SignedHeaders in the Authorization value.
	authz := p.Headers["Authorization"]
	authz = strings.Replace(authz, "x-harbor-nonce;", "", 1)
	authz = strings.Replace(authz, "x-harbor-pubkey-hash;", "", 1)
	p.Headers["Authorization"] = authz
	if _, err := Verify(context.Background(), p, "nonce-1", "ph-1", VerifyConfig{Endpoint: sts.URL}); err != ErrUnsignedBinding {
		t.Fatalf("err = %v, want ErrUnsignedBinding", err)
	}
}

// TestVerifySSRF: a non-STS signed URL is refused before any network call.
func TestVerifySSRF(t *testing.T) {
	p := goodPres(t)
	p.URL = "https://evil.example.com/"
	if _, err := Verify(context.Background(), p, "nonce-1", "ph-1", VerifyConfig{Endpoint: "http://127.0.0.1:0"}); err != ErrBadEndpoint {
		t.Fatalf("err = %v, want ErrBadEndpoint", err)
	}
}

// TestVerifySTSRejects: STS returning non-200 (bad signature) => attestation
// failed.
func TestVerifySTSRejects(t *testing.T) {
	sts := fakeSTS(t, "", "", true)
	defer sts.Close()
	if _, err := Verify(context.Background(), goodPres(t), "nonce-1", "ph-1", VerifyConfig{Endpoint: sts.URL}); err == nil || !strings.Contains(err.Error(), "STS") {
		t.Fatalf("err = %v, want attestation/STS failure", err)
	}
}

// TestFetchInstanceCredentials drives the IMDSv2 flow against a fake metadata
// service: token (PUT) gated GETs for region, role, then credentials.
func TestFetchInstanceCredentials(t *testing.T) {
	const role = "web-role"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "PUT" && r.URL.Path == "/latest/api/token":
			_, _ = w.Write([]byte("the-token"))
		case r.Header.Get("X-aws-ec2-metadata-token") != "the-token":
			w.WriteHeader(http.StatusUnauthorized) // IMDSv2: GETs require the token
		case r.URL.Path == "/latest/meta-data/placement/region":
			_, _ = w.Write([]byte("us-east-1"))
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/":
			_, _ = w.Write([]byte(role))
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/"+role:
			_, _ = w.Write([]byte(`{"AccessKeyId":"AKIDIMDS","SecretAccessKey":"sek","Token":"sesh"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	creds, region, err := FetchInstanceCredentials(context.Background(), IMDSConfig{BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if creds.AccessKeyID != "AKIDIMDS" || creds.SessionToken != "sesh" || region != "us-east-1" {
		t.Fatalf("creds=%+v region=%s", creds, region)
	}
	// The fetched creds sign a valid, bound attestation request.
	if _, err := Sign(creds, region, "n", "p", time.Now()); err != nil {
		t.Fatalf("sign with imds creds: %v", err)
	}
}

func TestPolicyRejects(t *testing.T) {
	id := Identity{Account: "999999999999", Arn: "arn:aws:sts::999999999999:assumed-role/admin/i-9"}
	if err := (Policy{Accounts: []string{"123456789012"}}).Check(id); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("account gate err = %v, want ErrNotAllowed", err)
	}
	if err := (Policy{ARNPatterns: []string{"arn:aws:sts::*:assumed-role/web/*"}}).Check(id); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("arn gate err = %v, want ErrNotAllowed", err)
	}
	okID := Identity{Account: "123456789012", Arn: "arn:aws:sts::123456789012:assumed-role/web/i-1"}
	if err := (Policy{ARNPatterns: []string{"arn:aws:sts::*:assumed-role/web/*"}}).Check(okID); err != nil {
		t.Fatalf("matching arn should pass: %v", err)
	}
}
