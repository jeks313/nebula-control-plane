package integration

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/ipam"
	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/queue"
	"github.com/jeks313/nebula-control-plane/internal/replay"
	"github.com/jeks313/nebula-control-plane/internal/ssoassert"
	"github.com/jeks313/nebula-control-plane/internal/usertrust"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

// ssoConsumer rebuilds the consumer with SSO enrollment configured: the PINNED gateway
// assertion-verify public key + an active user-trust getter (the seam). Reuses the env's
// CA/signer/queue/store. A nil ut models "no user-trust published".
func (e enrollEnv) ssoConsumer(t *testing.T, pinned *ecdsa.PublicKey, ut *usertrust.Config) *enrollment.Consumer {
	t.Helper()
	// Carve a "corp" sub-range so the netblock-binding path (S2 / ADR 0010) is exercised
	// on the static test allocator (production uses the DB-backed netblock registry).
	alloc, err := ipam.NewAllocator(e.store, ipam.Pool{
		Prefix:    e.pool,
		SubRanges: map[string]netip.Prefix{"corp": netip.MustParsePrefix("100.64.7.0/24")},
	})
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
		AssertionVerifyKey: pinned,
		UserTrustActive:    func() *usertrust.Config { return ut },
	})
}

// ssoOpts tweaks the assertion a candidate carries, to model the failure paths.
type ssoOpts struct {
	signKey    *ecdsa.PrivateKey // override the gateway signing key (wrong-key forgery)
	pubkeyHash string            // override the assertion PubkeyHash binding (wrong device)
	nonce      string            // override the assertion Nonce binding (wrong/forged nonce)
	issuedAt   int64             // override iat (0 -> now)
	expiresAt  int64             // override exp (0 -> now+10m)
	issuer     string
	groups     []string
}

// ssoCandidate builds a signed oidc candidate whose credential is a gateway-signed
// assertion bound (by default) to the candidate's own nonce + host pubkey hash.
func (e enrollEnv) ssoCandidate(t *testing.T, gw *ecdsa.PrivateKey, name string, o ssoOpts) queue.Candidate {
	t.Helper()
	priv, pkh, n := e.fresh(t)

	signKey := gw
	if o.signKey != nil {
		signKey = o.signKey
	}
	bindPKH := pkh
	if o.pubkeyHash != "" {
		bindPKH = o.pubkeyHash
	}
	bindNonce := n
	if o.nonce != "" {
		bindNonce = o.nonce
	}
	iat := o.issuedAt
	exp := o.expiresAt
	if exp == 0 {
		exp = time.Now().Add(10 * time.Minute).Unix()
	}
	issuer := o.issuer
	if issuer == "" {
		issuer = "https://idp.corp.example/realm"
	}

	assertion, err := ssoassert.Sign(signKey, ssoassert.Assertion{
		Subject: "u-123", Email: "alice@corp.example", Issuer: issuer,
		IdPGroups: o.groups, PubkeyHash: bindPKH, Nonce: bindNonce,
		IssuedAt: iat, ExpiresAt: exp,
	})
	if err != nil {
		t.Fatal(err)
	}
	cred, _ := json.Marshal(struct {
		Assertion string `json:"assertion"`
	}{Assertion: string(assertion)})
	return queue.Candidate{EnrollmentID: "eid-" + name, PubkeyHash: pkh, RequestJWS: signSSOBody(t, priv, n, cred, name), ReceivedAt: time.Now()}
}

func signSSOBody(t *testing.T, priv *ecdsa.PrivateKey, nonce string, cred []byte, name string) []byte {
	t.Helper()
	ek, _ := priv.PublicKey.ECDH()
	pub := ek.Bytes()
	req := wire.EnrollRequest{
		ProtocolVersion: wire.ProtocolVersion, Type: "enroll",
		IssuedAt: time.Now().UTC().Format(time.RFC3339), Nonce: nonce,
		Method: wire.MethodOIDC, Credential: cred,
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

// TestEnrollSSOPending is the S8 acceptance: a valid SSO enrollment whose matched
// user-trust entry does NOT auto-issue lands PENDING with the resolved groups + evidence,
// issuing no cert. usertrust.Match first-match-wins picks the entry.
func TestEnrollSSOPending(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	gw, _ := ssoassert.GenerateKey()
	ut := &usertrust.Config{
		DefaultGroups: []string{"fleet"},
		IDPEntries: []usertrust.IDPEntry{
			// First entry matches a group the user is NOT in -> skipped (proves first-match).
			{Realm: "https://idp.corp.example/realm", DirectoryGroup: "admins", MeshGroups: []string{"admin"}},
			{Realm: "https://idp.corp.example/realm", DirectoryGroup: "engineers", MeshGroups: []string{"eng"}, Netblock: "corp"},
		},
	}
	cons := e.ssoConsumer(t, &gw.PublicKey, ut)

	res, err := cons.Process(ctx, e.ssoCandidate(t, gw, "host-sso-pend", ssoOpts{groups: []string{"engineers"}}))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if res.Status != enrollment.StatusPending || res.CertPEM != nil {
		t.Fatalf("want pending+no-cert, got %+v", res)
	}
	row := loadEnrollment(t, e, "eid-host-sso-pend")
	if row.Method != wire.MethodOIDC || row.AttestProvider != "sso" ||
		row.AttestAccount != "https://idp.corp.example/realm" || row.AttestPrincipal != "alice@corp.example" || row.VerifiedAt == 0 {
		t.Fatalf("evidence not captured: %+v", row)
	}
	if row.JoinKeyID != 0 {
		t.Fatalf("join_key_id = %d, want 0 (no join key)", row.JoinKeyID)
	}
	var groups []string
	_ = json.Unmarshal([]byte(row.Groups), &groups)
	if len(groups) != 2 || groups[0] != "eng" || groups[1] != "fleet" {
		t.Fatalf("groups = %v, want [eng fleet] (default ∪ entry, first-match)", groups)
	}

	// Approve lands in the matched entry's groups + netblock (re-resolved from evidence).
	app, err := cons.Approve(ctx, "eid-host-sso-pend", "admin")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	c := e.verifyCert(t, app.CertPEM)
	if g := c.Groups(); len(g) != 2 || g[0] != "eng" || g[1] != "fleet" {
		t.Fatalf("approved groups = %v, want [eng fleet]", g)
	}
	// The approved cert IP must fall inside the matched entry's "corp" netblock,
	// proving the SSO netblock binding was re-resolved on approve from the row's evidence.
	corp := netip.MustParsePrefix("100.64.7.0/24")
	if ip := c.Networks()[0].Addr(); !corp.Contains(ip) {
		t.Fatalf("approved IP %v not in corp netblock %v", ip, corp)
	}
}

// TestEnrollSSOAutoIssue: a matched entry with auto_issue=true issues immediately.
func TestEnrollSSOAutoIssue(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	gw, _ := ssoassert.GenerateKey()
	ut := &usertrust.Config{IDPEntries: []usertrust.IDPEntry{
		{Realm: "https://idp.corp.example/realm", DirectoryGroup: "engineers", MeshGroups: []string{"eng"}, AutoIssue: true},
	}}
	cons := e.ssoConsumer(t, &gw.PublicKey, ut)

	res, err := cons.Process(ctx, e.ssoCandidate(t, gw, "host-sso-auto", ssoOpts{groups: []string{"engineers"}}))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if res.Status != enrollment.StatusIssued || res.CertPEM == nil {
		t.Fatalf("want issued+cert, got %+v", res)
	}
	c := e.verifyCert(t, res.CertPEM)
	if g := c.Groups(); len(g) != 1 || g[0] != "eng" {
		t.Fatalf("groups = %v, want [eng]", g)
	}
}

// TestEnrollSSOBadSignature: an assertion signed by a DIFFERENT key than the pinned one
// is a terminal deny (fail closed, not retried).
func TestEnrollSSOBadSignature(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	gw, _ := ssoassert.GenerateKey()
	forger, _ := ssoassert.GenerateKey()
	ut := &usertrust.Config{IDPEntries: []usertrust.IDPEntry{{Realm: "https://idp.corp.example/realm", DirectoryGroup: "engineers", MeshGroups: []string{"eng"}, AutoIssue: true}}}
	cons := e.ssoConsumer(t, &gw.PublicKey, ut)

	res, err := cons.Process(ctx, e.ssoCandidate(t, gw, "host-sso-forge", ssoOpts{signKey: forger, groups: []string{"engineers"}}))
	if !errors.Is(err, enrollment.ErrSSOAssertion) {
		t.Fatalf("err = %v, want ErrSSOAssertion", err)
	}
	if res.Status != enrollment.StatusDenied {
		t.Fatalf("status = %s, want denied", res.Status)
	}
	if !enrollment.Terminal(err) {
		t.Fatalf("ErrSSOAssertion must be terminal (acked, not redelivered)")
	}
}

// TestEnrollSSOExpired: an assertion outside its validity window is a terminal deny.
func TestEnrollSSOExpired(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	gw, _ := ssoassert.GenerateKey()
	ut := &usertrust.Config{IDPEntries: []usertrust.IDPEntry{{Realm: "https://idp.corp.example/realm", DirectoryGroup: "engineers", MeshGroups: []string{"eng"}, AutoIssue: true}}}
	cons := e.ssoConsumer(t, &gw.PublicKey, ut)

	expired := time.Now().Add(-time.Minute).Unix()
	res, err := cons.Process(ctx, e.ssoCandidate(t, gw, "host-sso-exp", ssoOpts{expiresAt: expired, groups: []string{"engineers"}}))
	if !errors.Is(err, enrollment.ErrSSOAssertion) {
		t.Fatalf("err = %v, want ErrSSOAssertion", err)
	}
	if res.Status != enrollment.StatusDenied {
		t.Fatalf("status = %s, want denied", res.Status)
	}
}

// TestEnrollSSOWrongPubkeyBinding: an assertion bound to a DIFFERENT device pubkey hash
// than the enrolling host's is a terminal deny (anti-relay).
func TestEnrollSSOWrongPubkeyBinding(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	gw, _ := ssoassert.GenerateKey()
	ut := &usertrust.Config{IDPEntries: []usertrust.IDPEntry{{Realm: "https://idp.corp.example/realm", DirectoryGroup: "engineers", MeshGroups: []string{"eng"}, AutoIssue: true}}}
	cons := e.ssoConsumer(t, &gw.PublicKey, ut)

	res, err := cons.Process(ctx, e.ssoCandidate(t, gw, "host-sso-pkh", ssoOpts{pubkeyHash: "some-other-device-hash", groups: []string{"engineers"}}))
	if !errors.Is(err, enrollment.ErrSSOBinding) {
		t.Fatalf("err = %v, want ErrSSOBinding", err)
	}
	if res.Status != enrollment.StatusDenied {
		t.Fatalf("status = %s, want denied", res.Status)
	}
}

// TestEnrollSSOWrongNonceBinding: an assertion bound to a DIFFERENT nonce than the
// enrollment request's is a terminal deny (anti-relay — the assertion's nonce must be
// the SAME single-use nonce the request used).
func TestEnrollSSOWrongNonceBinding(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	gw, _ := ssoassert.GenerateKey()
	ut := &usertrust.Config{IDPEntries: []usertrust.IDPEntry{{Realm: "https://idp.corp.example/realm", DirectoryGroup: "engineers", MeshGroups: []string{"eng"}, AutoIssue: true}}}
	cons := e.ssoConsumer(t, &gw.PublicKey, ut)

	res, err := cons.Process(ctx, e.ssoCandidate(t, gw, "host-sso-nonce", ssoOpts{nonce: "a-different-nonce", groups: []string{"engineers"}}))
	if !errors.Is(err, enrollment.ErrSSOBinding) {
		t.Fatalf("err = %v, want ErrSSOBinding", err)
	}
	if res.Status != enrollment.StatusDenied {
		t.Fatalf("status = %s, want denied", res.Status)
	}
}

// TestEnrollSSONoTrustedGroup: a valid, well-bound assertion whose IdP groups match no
// user-trust entry is a terminal deny (fail closed).
func TestEnrollSSONoTrustedGroup(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	gw, _ := ssoassert.GenerateKey()
	ut := &usertrust.Config{IDPEntries: []usertrust.IDPEntry{{Realm: "https://idp.corp.example/realm", DirectoryGroup: "engineers", MeshGroups: []string{"eng"}, AutoIssue: true}}}
	cons := e.ssoConsumer(t, &gw.PublicKey, ut)

	res, err := cons.Process(ctx, e.ssoCandidate(t, gw, "host-sso-untrust", ssoOpts{groups: []string{"contractors"}}))
	if !errors.Is(err, enrollment.ErrSSONotAllowed) {
		t.Fatalf("err = %v, want ErrSSONotAllowed", err)
	}
	if res.Status != enrollment.StatusDenied {
		t.Fatalf("status = %s, want denied", res.Status)
	}
}

// TestEnrollSSONotConfigured: with the SSO seam nil (no pinned key / no user-trust
// source), an oidc enrollment is a terminal deny — fail closed.
func TestEnrollSSONotConfigured(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	gw, _ := ssoassert.GenerateKey()

	// Default consumer (no SSO config wired): nil pinned key + nil getter.
	res, err := e.cons.Process(ctx, e.ssoCandidate(t, gw, "host-sso-off", ssoOpts{groups: []string{"engineers"}}))
	if !errors.Is(err, enrollment.ErrSSONotConfigured) {
		t.Fatalf("err = %v, want ErrSSONotConfigured", err)
	}
	if res.Status != enrollment.StatusDenied {
		t.Fatalf("status = %s, want denied", res.Status)
	}

	// A pinned key but the getter returns nil (no user-trust published yet) is also denied.
	cons := e.ssoConsumer(t, &gw.PublicKey, nil)
	res2, err2 := cons.Process(ctx, e.ssoCandidate(t, gw, "host-sso-noUT", ssoOpts{groups: []string{"engineers"}}))
	if !errors.Is(err2, enrollment.ErrSSONotConfigured) {
		t.Fatalf("err = %v, want ErrSSONotConfigured", err2)
	}
	if res2.Status != enrollment.StatusDenied {
		t.Fatalf("status = %s, want denied", res2.Status)
	}
}
