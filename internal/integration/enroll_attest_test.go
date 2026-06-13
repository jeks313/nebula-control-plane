package integration

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/awsattest"
	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/cloudtrust"
	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/ipam"
	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/queue"
	"github.com/jeks313/nebula-control-plane/internal/replay"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

// fakeSTSServer returns a GetCallerIdentity verifier that vouches a fixed identity.
func fakeSTSServer(t *testing.T, account, arn string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult>` +
			`<Arn>` + arn + `</Arn><UserId>AROAEXAMPLE:i-0abc</UserId><Account>` + account + `</Account>` +
			`</GetCallerIdentityResult></GetCallerIdentityResponse>`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// attestConsumer rebuilds the consumer with AWS SigV4 attestation enabled, reusing the
// env's CA/signer/queue/store (the STS endpoint is overridden to a test server).
func (e enrollEnv) attestConsumer(t *testing.T, ct *cloudtrust.Config, stsURL string) *enrollment.Consumer {
	t.Helper()
	alloc, err := ipam.NewAllocator(e.store, ipam.Pool{Prefix: e.pool})
	if err != nil {
		t.Fatal(err)
	}
	return enrollment.New(enrollment.Config{
		Store: e.store, Nonces: e.ring, Replay: replay.New(2 * time.Minute),
		Signer: e.sg, Allocator: alloc, Pool: e.pool, CertLifetime: 24 * time.Hour,
		ConfigBackend: e.cfgB, ConfigKeyID: e.configKeyID, CABundlePEM: e.caPEM,
		Lighthouses: []bundle.Lighthouse{{OverlayIP: "100.64.0.1", PublicAddrs: []string{"198.51.100.1:4242"}}},
		Policy:      e.policy,
		Results:     e.d, ResultTTL: time.Hour,
		AWSSigV4Enabled: true, CloudTrust: ct, AWSVerify: awsattest.VerifyConfig{Endpoint: stsURL},
	})
}

// attestCandidate builds a signed aws-sigv4 candidate whose SigV4 attestation is bound to
// the candidate's nonce + host pubkey (using a deliberately-wrong nonce models replay).
func (e enrollEnv) attestCandidate(t *testing.T, name, signNonce string) queue.Candidate {
	t.Helper()
	priv, pkh, n := e.fresh(t)
	bindNonce := n
	if signNonce != "" {
		bindNonce = signNonce // attestation bound to a DIFFERENT nonce than the request
	}
	pres, err := awsattest.Sign(awsattest.Credentials{AccessKeyID: "AKID", SecretAccessKey: "s", SessionToken: "tok"},
		"us-east-1", bindNonce, pkh, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cred, _ := json.Marshal(pres)
	return queue.Candidate{EnrollmentID: "eid-" + name, PubkeyHash: pkh, RequestJWS: signAttestBody(t, priv, n, cred, name), ReceivedAt: time.Now()}
}

func signAttestBody(t *testing.T, priv *ecdsa.PrivateKey, nonce string, cred []byte, name string) []byte {
	t.Helper()
	ek, _ := priv.PublicKey.ECDH()
	pub := ek.Bytes()
	req := wire.EnrollRequest{
		ProtocolVersion: wire.ProtocolVersion, Type: "enroll",
		IssuedAt: time.Now().UTC().Format(time.RFC3339), Nonce: nonce,
		Method: wire.MethodAWSSigV4, Credential: cred,
	}
	req.CSR = wire.CSR{Curve: "P256", PublicKey: base64.RawURLEncoding.EncodeToString(pub), RequestedName: name}
	payload, _ := json.Marshal(req)
	env, err := jws.SignES256(priv, jws.Header{Typ: wire.TypEnrollRequest, Ver: 1, Kid: wire.PubkeyHash(pub)}, payload)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(env)
	return body
}

func loadEnrollment(t *testing.T, e enrollEnv, eid string) enrollment.Enrollment {
	t.Helper()
	var row enrollment.Enrollment
	if err := e.store.DB.Where("enrollment_id = ?", eid).First(&row).Error; err != nil {
		t.Fatalf("reload %s: %v", eid, err)
	}
	return row
}

// TestEnrollAttestedAutoIssue: an attested host from a trusted account auto-issues with
// groups = default ∪ account, and the provider evidence (account/ARN/region) is captured.
func TestEnrollAttestedAutoIssue(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	sts := fakeSTSServer(t, "111122223333", "arn:aws:sts::111122223333:assumed-role/web/i-0abc")
	ct := &cloudtrust.Config{DefaultGroups: []string{"fleet"}, AWS: []cloudtrust.AWSAccount{
		{Account: "111122223333", ARNPatterns: []string{"arn:aws:sts::111122223333:assumed-role/web/*"}, Groups: []string{"web"}, AutoIssue: true},
	}}
	cons := e.attestConsumer(t, ct, sts.URL)

	res, err := cons.Process(ctx, e.attestCandidate(t, "host-aws", ""))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if res.Status != enrollment.StatusIssued || res.CertPEM == nil {
		t.Fatalf("want issued+cert, got %+v", res)
	}
	c := e.verifyCert(t, res.CertPEM)
	if g := c.Groups(); len(g) != 2 || g[0] != "fleet" || g[1] != "web" {
		t.Fatalf("groups = %v, want [fleet web] (default ∪ account)", g)
	}
	row := loadEnrollment(t, e, "eid-host-aws")
	if row.Method != wire.MethodAWSSigV4 || row.AttestProvider != "aws" ||
		row.AttestAccount != "111122223333" || row.AttestRegion != "us-east-1" || row.VerifiedAt == 0 {
		t.Fatalf("evidence not captured: %+v", row)
	}
	if row.AttestPrincipal != "arn:aws:sts::111122223333:assumed-role/web/i-0abc" {
		t.Fatalf("principal = %q", row.AttestPrincipal)
	}
}

// TestEnrollAttestedPending: a trusted account with auto_issue=false queues for approval,
// still capturing evidence; JoinKeyID stays 0 (no join key).
func TestEnrollAttestedPending(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	sts := fakeSTSServer(t, "444455556666", "arn:aws:sts::444455556666:assumed-role/db/i-1")
	ct := &cloudtrust.Config{AWS: []cloudtrust.AWSAccount{{Account: "444455556666", Groups: []string{"db"}}}}
	cons := e.attestConsumer(t, ct, sts.URL)

	res, err := cons.Process(ctx, e.attestCandidate(t, "host-pend", ""))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if res.Status != enrollment.StatusPending || res.CertPEM != nil {
		t.Fatalf("want pending+no-cert, got %+v", res)
	}
	row := loadEnrollment(t, e, "eid-host-pend")
	if row.AttestAccount != "444455556666" || row.JoinKeyID != 0 || row.VerifiedAt == 0 {
		t.Fatalf("evidence/joinkey wrong: %+v", row)
	}
}

// TestEnrollAttestedUntrustedDenied: STS vouches an account NOT in the trust config —
// denied with a terminal ErrNotAllowed (fail closed).
func TestEnrollAttestedUntrustedDenied(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	sts := fakeSTSServer(t, "999988887777", "arn:aws:sts::999988887777:assumed-role/web/x")
	ct := &cloudtrust.Config{AWS: []cloudtrust.AWSAccount{{Account: "111122223333", AutoIssue: true}}}
	cons := e.attestConsumer(t, ct, sts.URL)

	res, err := cons.Process(ctx, e.attestCandidate(t, "host-untrusted", ""))
	if !errors.Is(err, awsattest.ErrNotAllowed) {
		t.Fatalf("err = %v, want ErrNotAllowed", err)
	}
	if res.Status != enrollment.StatusDenied {
		t.Fatalf("status = %s, want denied", res.Status)
	}
}

// TestEnrollAttestedBindingMismatch: an attestation bound to a different nonce than the
// enrollment request is rejected (the consumer binds Verify to the request's own nonce).
func TestEnrollAttestedBindingMismatch(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	sts := fakeSTSServer(t, "111122223333", "arn:aws:sts::111122223333:assumed-role/web/x")
	ct := &cloudtrust.Config{AWS: []cloudtrust.AWSAccount{{Account: "111122223333", AutoIssue: true}}}
	cons := e.attestConsumer(t, ct, sts.URL)

	res, err := cons.Process(ctx, e.attestCandidate(t, "host-bind", "some-other-nonce"))
	if !errors.Is(err, awsattest.ErrBinding) {
		t.Fatalf("err = %v, want ErrBinding", err)
	}
	if res.Status != enrollment.StatusDenied {
		t.Fatalf("status = %s, want denied", res.Status)
	}
}

// TestEnrollAttestedSTSUnavailableDenied: when STS is unavailable (503), the attempt is
// denied as a TERMINAL outcome (not nacked into a replay loop), with a distinct reason.
// The host recovers by re-enrolling with a fresh nonce.
func TestEnrollAttestedSTSUnavailableDenied(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(down.Close)
	ct := &cloudtrust.Config{AWS: []cloudtrust.AWSAccount{{Account: "111122223333", AutoIssue: true}}}
	cons := e.attestConsumer(t, ct, down.URL)

	res, err := cons.Process(ctx, e.attestCandidate(t, "host-stsdown", ""))
	if !errors.Is(err, awsattest.ErrSTSUnavailable) {
		t.Fatalf("err = %v, want ErrSTSUnavailable", err)
	}
	if res.Status != enrollment.StatusDenied {
		t.Fatalf("status = %s, want denied", res.Status)
	}
	// Terminal: Drain would ACK (not loop). A fresh enrollment (new nonce) succeeds once
	// STS is back — proving recovery is via re-enroll, not queue redelivery.
	up := fakeSTSServer(t, "111122223333", "arn:aws:sts::111122223333:assumed-role/x/i-1")
	cons2 := e.attestConsumer(t, ct, up.URL)
	res2, err := cons2.Process(ctx, e.attestCandidate(t, "host-recovered", ""))
	if err != nil || res2.Status != enrollment.StatusIssued {
		t.Fatalf("re-enroll after recovery: status=%s err=%v", res2.Status, err)
	}
}

// TestEnrollAttestedDisabledDenied: with attestation disabled (the default consumer),
// an aws-sigv4 request is refused (fail closed).
func TestEnrollAttestedDisabledDenied(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	res, err := e.cons.Process(ctx, e.attestCandidate(t, "host-off", ""))
	if !errors.Is(err, enrollment.ErrMethod) {
		t.Fatalf("err = %v, want ErrMethod", err)
	}
	if res.Status != enrollment.StatusDenied {
		t.Fatalf("status = %s, want denied", res.Status)
	}
}
