package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/ipam"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/nonce"
	"github.com/jeks313/nebula-control-plane/internal/queue"
	"github.com/jeks313/nebula-control-plane/internal/replay"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
	"github.com/jeks313/nebula-control-plane/internal/wire"
	"github.com/slackhq/nebula/cert"
)

type enrollEnv struct {
	cons  *enrollment.Consumer
	store *store.Store
	ring  *nonce.Keyring
	caPEM []byte
	pool  netip.Prefix
}

func setupEnroll(t *testing.T) enrollEnv {
	t.Helper()
	dsn := store.DefaultSQLiteDSN(filepath.Join(t.TempDir(), "h.db"))
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}

	caB, _ := signer.NewSoftwareBackend()
	pool := netip.MustParsePrefix("100.64.0.0/16")
	now := time.Now()
	_, caPEM, err := signer.SelfSignCA(caB, signer.CATemplate{
		Name: "ca", Networks: []netip.Prefix{pool},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	audit := func(c context.Context, a, ac, tg, d string) error { _, e := s.AppendAudit(c, a, ac, tg, d); return e }
	sg, err := signer.New(signer.Config{
		CACertPEM: caPEM, Backend: caB,
		Policy: signer.Policy{AllowedNetwork: pool, MaxLifetime: 48 * time.Hour}, Audit: audit,
	})
	if err != nil {
		t.Fatal(err)
	}
	alloc, _ := ipam.NewAllocator(s, ipam.Pool{Prefix: pool})
	ring, _ := nonce.NewKeyring([][]byte{make([]byte, 32)}, 0, 0)
	cons := enrollment.New(enrollment.Config{
		Store: s, Nonces: ring, Replay: replay.New(2 * time.Minute),
		Signer: sg, Allocator: alloc, Pool: pool, CertLifetime: 24 * time.Hour,
	})
	return enrollEnv{cons: cons, store: s, ring: ring, caPEM: caPEM, pool: pool}
}

// candidate builds a signed enrollment candidate as the gateway would have.
func (e enrollEnv) candidate(t *testing.T, token, name string) queue.Candidate {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ek, _ := priv.PublicKey.ECDH()
	pub := ek.Bytes()
	pkh := wire.PubkeyHash(pub)
	n, _ := e.ring.Mint([]byte(pkh))

	req := wire.EnrollRequest{
		ProtocolVersion: wire.ProtocolVersion, Type: "enroll",
		IssuedAt: time.Now().UTC().Format(time.RFC3339), Nonce: n,
		Method: wire.MethodToken, Credential: json.RawMessage(`{"token":"` + token + `"}`),
	}
	req.CSR = wire.CSR{Curve: "P256", PublicKey: base64.RawURLEncoding.EncodeToString(pub), RequestedName: name}
	payload, _ := json.Marshal(req)
	env, err := jws.SignES256(priv, jws.Header{Typ: wire.TypEnrollRequest, Ver: 1, Kid: pkh}, payload)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(env)
	return queue.Candidate{EnrollmentID: "eid-" + name, PubkeyHash: pkh, RequestJWS: body, ReceivedAt: time.Now()}
}

func (e enrollEnv) verifyCert(t *testing.T, certPEM []byte) cert.Certificate {
	t.Helper()
	pool, err := cert.NewCAPoolFromPEM(e.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := cert.UnmarshalCertificateFromPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.VerifyCertificate(time.Now(), c); err != nil {
		t.Fatalf("cert does not verify: %v", err)
	}
	return c
}

// TestEnrollDefaultsToPendingThenApprove is the core M3.4 acceptance: a join-key
// (non-attested) enrollment lands in PENDING and is issued only after approval.
func TestEnrollDefaultsToPendingThenApprove(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	secret, _, _ := joinkey.Create(ctx, e.store, joinkey.Params{Name: "k", Groups: []string{"web"}, MaxUses: 1}, time.Now())

	res, err := e.cons.Process(ctx, e.candidate(t, secret, "host-1"))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if res.Status != enrollment.StatusPending || res.CertPEM != nil {
		t.Fatalf("default should be PENDING with no cert, got %+v", res)
	}
	pend, _ := e.cons.Pending(ctx)
	if len(pend) != 1 {
		t.Fatalf("pending = %d, want 1", len(pend))
	}

	app, err := e.cons.Approve(ctx, "eid-host-1", "admin")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if app.Status != enrollment.StatusIssued {
		t.Fatalf("approve status = %s", app.Status)
	}
	c := e.verifyCert(t, app.CertPEM)
	if g := c.Groups(); len(g) != 1 || g[0] != "web" {
		t.Fatalf("groups = %v, want [web] (from the key)", g)
	}
}

func TestEnrollAutoIssue(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	secret, _, _ := joinkey.Create(ctx, e.store, joinkey.Params{Name: "auto", Groups: []string{"db"}, MaxUses: 1, AutoIssue: true}, time.Now())

	res, err := e.cons.Process(ctx, e.candidate(t, secret, "host-auto"))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if res.Status != enrollment.StatusIssued || res.CertPEM == nil {
		t.Fatalf("auto_issue should issue, got %+v", res)
	}
	c := e.verifyCert(t, res.CertPEM)
	if !e.pool.Contains(c.Networks()[0].Addr()) {
		t.Fatalf("cert IP %v not in pool", c.Networks())
	}
	if g := c.Groups(); len(g) != 1 || g[0] != "db" {
		t.Fatalf("groups = %v, want [db]", g)
	}
}

func TestEnrollReplayRejected(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	secret, _, _ := joinkey.Create(ctx, e.store, joinkey.Params{Name: "rk", MaxUses: 0, AutoIssue: true}, time.Now())
	cand := e.candidate(t, secret, "host-replay")
	if _, err := e.cons.Process(ctx, cand); err != nil {
		t.Fatalf("first process: %v", err)
	}
	if _, err := e.cons.Process(ctx, cand); !errors.Is(err, enrollment.ErrReplay) {
		t.Fatalf("err = %v, want ErrReplay", err)
	}
}

func TestEnrollRevokedKeyDenied(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	secret, _, _ := joinkey.Create(ctx, e.store, joinkey.Params{Name: "rev", MaxUses: 0, AutoIssue: true}, time.Now())
	if err := joinkey.Revoke(ctx, e.store, "rev"); err != nil {
		t.Fatal(err)
	}
	res, err := e.cons.Process(ctx, e.candidate(t, secret, "host-revoked"))
	if !errors.Is(err, joinkey.ErrNotFound) {
		t.Fatalf("err = %v, want joinkey.ErrNotFound", err)
	}
	if res.Status != enrollment.StatusDenied {
		t.Fatalf("status = %s, want denied", res.Status)
	}
}
