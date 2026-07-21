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
	"sync"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/ca"
	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/ipam"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/nonce"
	"github.com/jeks313/nebula-control-plane/internal/policy"
	"github.com/jeks313/nebula-control-plane/internal/queue"
	"github.com/jeks313/nebula-control-plane/internal/replay"
	"github.com/jeks313/nebula-control-plane/internal/revocation"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
	"github.com/jeks313/nebula-control-plane/internal/wire"
	"github.com/slackhq/nebula/cert"
)

type enrollEnv struct {
	cons        *enrollment.Consumer
	store       *store.Store
	ring        *nonce.Keyring
	caPEM       []byte
	pool        netip.Prefix
	d           *queue.Durable   // shared gateway↔Core store (queue + results)
	pinned      *ecdsa.PublicKey // config-signing pubkey (Pilot pins this)
	configKeyID string
	sg          *signer.Signer
	cfgB        signer.Backend
	policy      *policy.Policy
	rev         *revocation.Registry // cert blocklist (7.1); wired as BlocklistSource
	caReg       *ca.Registry         // CA rotation registry (M8); wired as CABundleSource, seeded with the current CA
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
		Policy: signer.IssuePolicy{AllowedNetwork: pool, MaxLifetime: 48 * time.Hour}, Audit: audit,
	})
	if err != nil {
		t.Fatal(err)
	}
	alloc, _ := ipam.NewAllocator(s, ipam.Pool{Prefix: pool})
	ring, _ := nonce.NewKeyring([][]byte{make([]byte, 32)}, 0, 0)

	// Config-signing key (signs bundles) + the shared queue/result store.
	cfgB, _ := signer.NewSoftwareBackend()
	cfgPub, _ := cfgB.PublicKey()
	pinned, _ := jws.ParseP256PublicPoint(cfgPub)
	configKeyID := wire.PubkeyHash(cfgPub)
	d, err := queue.OpenDurable(queue.DurableConfig{
		DSN: filepath.Join(t.TempDir(), "q.db") + "?_pragma=busy_timeout(5000)", Key: make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })

	pol, err := policy.Parse("allow group:web -> group:db tcp 5432\nallow any -> group:web tcp 443\n")
	if err != nil {
		t.Fatal(err)
	}
	rev := revocation.New(s.DB, audit)
	// M8: the CA rotation registry, seeded with the current CA as active (as the live serve
	// path does on boot), wired as the bundle's CABundleSource so a staged CA propagates.
	caReg := ca.New(s.DB, audit)
	if _, _, err := caReg.SeedActive(context.Background(), "test-ca", string(caPEM), "software", "boot"); err != nil {
		t.Fatalf("seed CA: %v", err)
	}
	cons := enrollment.New(enrollment.Config{
		Store: s, Nonces: ring, Replay: replay.New(2 * time.Minute),
		Signer: sg, Allocator: alloc, Pool: pool, CertLifetime: 24 * time.Hour,
		// Ephemeral hosts get a meaningfully shorter cert (2h vs the 24h standard) so the
		// ephemeral tests can assert the validity window differs.
		EphemeralCertTTL: 2 * time.Hour,
		ConfigBackend:    cfgB, ConfigKeyID: configKeyID, CABundlePEM: caPEM,
		Lighthouses:     []bundle.Lighthouse{{OverlayIP: "100.64.0.1", PublicAddrs: []string{"198.51.100.1:4242"}}},
		Policy:          &pol,
		BlocklistSource: rev.ActiveFingerprints,
		CABundleSource:  caReg.TrustBundle,
		Results:         d, ResultTTL: time.Hour,
	})
	return enrollEnv{cons: cons, store: s, ring: ring, caPEM: caPEM, pool: pool, d: d, pinned: pinned, configKeyID: configKeyID, sg: sg, cfgB: cfgB, policy: &pol, rev: rev, caReg: caReg}
}

// fresh generates a host key and a nonce bound to it.
func (e enrollEnv) fresh(t *testing.T) (priv *ecdsa.PrivateKey, pkh, nonce string) {
	t.Helper()
	priv, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ek, _ := priv.PublicKey.ECDH()
	pkh = wire.PubkeyHash(ek.Bytes())
	nonce, _ = e.ring.Mint([]byte(pkh))
	return priv, pkh, nonce
}

// signBody builds and signs an enroll request body as the gateway would receive.
func signBody(t *testing.T, priv *ecdsa.PrivateKey, nonce, token, name string) []byte {
	t.Helper()
	ek, _ := priv.PublicKey.ECDH()
	pub := ek.Bytes()
	pkh := wire.PubkeyHash(pub)
	req := wire.EnrollRequest{
		ProtocolVersion: wire.ProtocolVersion, Type: "enroll",
		IssuedAt: time.Now().UTC().Format(time.RFC3339), Nonce: nonce,
		Method: wire.MethodToken, Credential: json.RawMessage(`{"token":"` + token + `"}`),
	}
	req.CSR = wire.CSR{Curve: "P256", PublicKey: base64.RawURLEncoding.EncodeToString(pub), RequestedName: name}
	payload, _ := json.Marshal(req)
	env, err := jws.SignES256(priv, jws.Header{Typ: wire.TypEnrollRequest, Ver: 1, Kid: pkh}, payload)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(env)
	return body
}

// candidate builds a fresh signed enrollment candidate.
func (e enrollEnv) candidate(t *testing.T, token, name string) queue.Candidate {
	t.Helper()
	priv, pkh, n := e.fresh(t)
	return queue.Candidate{EnrollmentID: "eid-" + name, PubkeyHash: pkh, RequestJWS: signBody(t, priv, n, token, name), ReceivedAt: time.Now()}
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

// TestEnrollPersistsNetblock: the IPAM netblock chosen at enroll time (here a join
// key's sub-range) is persisted on the pending enrollment row, so Approve allocates
// from the SAME block by reading it — instead of re-deriving it at approve time, which
// for SSO/cloud needs the trust config loaded in the approving process (the bug that
// put manually-approved SSO hosts in 'default').
func TestEnrollPersistsNetblock(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	secret, _, _ := joinkey.Create(ctx, e.store, joinkey.Params{Name: "nb", Groups: []string{"web"}, MaxUses: 1, SubRange: "special-block"}, time.Now())
	res, err := e.cons.Process(ctx, e.candidate(t, secret, "host-nb"))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if res.Status != enrollment.StatusPending {
		t.Fatalf("status = %q, want pending", res.Status)
	}
	pend, _ := e.cons.Pending(ctx)
	var row *enrollment.Enrollment
	for i := range pend {
		if pend[i].EnrollmentID == "eid-host-nb" {
			row = &pend[i]
		}
	}
	if row == nil {
		t.Fatal("pending enrollment eid-host-nb not found")
	}
	if row.SubRange != "special-block" {
		t.Errorf("persisted SubRange = %q, want special-block (the netblock captured at enroll time)", row.SubRange)
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

func TestEnrollIdempotentRedelivery(t *testing.T) {
	// Same candidate (same enrollment_id) delivered twice (at-least-once) must
	// not re-issue — the second returns the recorded result.
	e := setupEnroll(t)
	ctx := context.Background()
	secret, _, _ := joinkey.Create(ctx, e.store, joinkey.Params{Name: "idem", MaxUses: 0, AutoIssue: true}, time.Now())
	cand := e.candidate(t, secret, "host-idem")
	r1, err := e.cons.Process(ctx, cand)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := e.cons.Process(ctx, cand)
	if err != nil {
		t.Fatalf("redelivery: %v", err)
	}
	if r1.OverlayIP != r2.OverlayIP || r2.Status != enrollment.StatusIssued {
		t.Fatalf("redelivery not idempotent: %+v vs %+v", r1, r2)
	}
}

func TestEnrollNonceReplayRejected(t *testing.T) {
	// Two DIFFERENT enrollments reusing the same nonce: the second is a replay.
	e := setupEnroll(t)
	ctx := context.Background()
	secret, _, _ := joinkey.Create(ctx, e.store, joinkey.Params{Name: "rk", MaxUses: 0, AutoIssue: true}, time.Now())
	priv, pkh, n := e.fresh(t)

	c1 := queue.Candidate{EnrollmentID: "eid-r1", PubkeyHash: pkh, RequestJWS: signBody(t, priv, n, secret, "host-r1"), ReceivedAt: time.Now()}
	if _, err := e.cons.Process(ctx, c1); err != nil {
		t.Fatalf("first: %v", err)
	}
	c2 := queue.Candidate{EnrollmentID: "eid-r2", PubkeyHash: pkh, RequestJWS: signBody(t, priv, n, secret, "host-r2"), ReceivedAt: time.Now()}
	if _, err := e.cons.Process(ctx, c2); !errors.Is(err, enrollment.ErrReplay) {
		t.Fatalf("err = %v, want ErrReplay", err)
	}
}

// TestEnrollPerKeyQuota is the M3.10 acceptance: a per-key rate quota blocks
// further enrollments once the ceiling is hit, without over-consuming the key.
func TestEnrollPerKeyQuota(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	secret, _, _ := joinkey.Create(ctx, e.store,
		joinkey.Params{Name: "q", Groups: []string{"web"}, MaxUses: 0, AutoIssue: true, QuotaPerHour: 2}, time.Now())

	for _, name := range []string{"hq0", "hq1"} {
		res, err := e.cons.Process(ctx, e.candidate(t, secret, name))
		if err != nil || res.Status != enrollment.StatusIssued {
			t.Fatalf("%s: status=%s err=%v", name, res.Status, err)
		}
	}
	// 3rd within the window is blocked.
	res, err := e.cons.Process(ctx, e.candidate(t, secret, "hq2"))
	if !errors.Is(err, enrollment.ErrQuota) {
		t.Fatalf("3rd enroll err = %v, want ErrQuota", err)
	}
	if res.Status != enrollment.StatusDenied {
		t.Fatalf("3rd status = %s, want denied", res.Status)
	}
	// The blocked attempt did not consume a use.
	keys, _ := joinkey.List(ctx, e.store)
	for _, k := range keys {
		if k.Name == "q" && k.UsedCount != 2 {
			t.Fatalf("used_count = %d, want 2 (blocked attempt must not consume)", k.UsedCount)
		}
	}
}

// TestEnrollApproveDenyRace is the A0.5 concurrency-safety acceptance (the
// admin-API now exposes approve AND deny on the same pending row to concurrent
// operators). Whichever wins, the compare-and-set guarantees the loser sees
// ErrNotPending and — critically — a DENIED host never keeps an issued cert.
// Run with -race.
func TestEnrollApproveDenyRace(t *testing.T) {
	for i := 0; i < 25; i++ {
		e := setupEnroll(t)
		ctx := context.Background()
		secret, _, _ := joinkey.Create(ctx, e.store, joinkey.Params{Name: "rk", Groups: []string{"web"}, MaxUses: 1}, time.Now())
		if _, err := e.cons.Process(ctx, e.candidate(t, secret, "host-rc")); err != nil {
			t.Fatalf("process: %v", err)
		}

		type out struct {
			status string
			err    error
		}
		var apr, dny out
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			r, err := e.cons.Approve(ctx, "eid-host-rc", "admin-a")
			apr = out{r.Status, err}
		}()
		go func() {
			defer wg.Done()
			r, err := e.cons.Deny(ctx, "eid-host-rc", "admin-b", "veto")
			dny = out{r.Status, err}
		}()
		wg.Wait()

		// Exactly one mutator wins; the loser gets ErrNotPending (never a silent success).
		aprWon := apr.err == nil
		dnyWon := dny.err == nil
		if aprWon == dnyWon {
			t.Fatalf("iter %d: exactly one must win, got approve(err=%v) deny(err=%v)", i, apr.err, dny.err)
		}
		if loser := apr.err; !aprWon && !errors.Is(loser, enrollment.ErrNotPending) {
			t.Fatalf("iter %d: losing approve err = %v, want ErrNotPending", i, loser)
		}
		if loser := dny.err; !dnyWon && !errors.Is(loser, enrollment.ErrNotPending) {
			t.Fatalf("iter %d: losing deny err = %v, want ErrNotPending", i, loser)
		}

		// The durable row must match the winner — and a denied host must hold NO cert.
		var row enrollment.Enrollment
		if err := e.store.DB.WithContext(ctx).Where("enrollment_id = ?", "eid-host-rc").First(&row).Error; err != nil {
			t.Fatalf("iter %d: reload: %v", i, err)
		}
		if dnyWon {
			if row.Status != enrollment.StatusDenied {
				t.Fatalf("iter %d: deny won but row status = %s", i, row.Status)
			}
			if len(row.CertPEM) != 0 || row.OverlayIP != "" {
				t.Fatalf("iter %d: DENIED host kept a cert/IP (cert=%dB ip=%q) — CAS failed", i, len(row.CertPEM), row.OverlayIP)
			}
		} else {
			if row.Status != enrollment.StatusIssued || len(row.CertPEM) == 0 {
				t.Fatalf("iter %d: approve won but row status=%s cert=%dB", i, row.Status, len(row.CertPEM))
			}
		}
	}
}

// certValidity returns a leaf cert's validity window (NotAfter - NotBefore) — which the
// issue path sets to the cert TTL (NotBefore = now-5m, NotAfter = NotBefore + TTL).
func certValidity(t *testing.T, certPEM []byte) time.Duration {
	t.Helper()
	c, _, err := cert.UnmarshalCertificateFromPEM(certPEM)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c.NotAfter().Sub(c.NotBefore())
}

// enrollmentRow reads the persisted enrollment row by id.
func (e enrollEnv) enrollmentRow(t *testing.T, enrollmentID string) enrollment.Enrollment {
	t.Helper()
	var row enrollment.Enrollment
	if err := e.store.DB.Where("enrollment_id = ?", enrollmentID).First(&row).Error; err != nil {
		t.Fatalf("reload enrollment %s: %v", enrollmentID, err)
	}
	return row
}

// TestEnrollEphemeralAutoIssue: an auto-issue join via an EPHEMERAL key records
// ephemeral=true on the row and mints a cert whose validity == EphemeralCertTTL (2h),
// strictly shorter than the standard CertLifetime (24h).
func TestEnrollEphemeralAutoIssue(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	secret, _, _ := joinkey.Create(ctx, e.store,
		joinkey.Params{Name: "eph", Groups: []string{"ci"}, MaxUses: 0, AutoIssue: true, Ephemeral: true}, time.Now())

	res, err := e.cons.Process(ctx, e.candidate(t, secret, "host-eph"))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if res.Status != enrollment.StatusIssued || res.CertPEM == nil {
		t.Fatalf("ephemeral auto_issue should issue, got %+v", res)
	}
	e.verifyCert(t, res.CertPEM)
	if v := certValidity(t, res.CertPEM); v != 2*time.Hour {
		t.Fatalf("ephemeral cert validity = %s, want 2h (EphemeralCertTTL)", v)
	}
	if row := e.enrollmentRow(t, "eid-host-eph"); !row.Ephemeral {
		t.Fatalf("ephemeral=%v on the row, want true", row.Ephemeral)
	}
}

// TestEnrollNonEphemeralStandardTTL: a non-ephemeral key records ephemeral=false and
// mints a cert with the standard CertLifetime (24h), so the shortening is opt-in.
func TestEnrollNonEphemeralStandardTTL(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	secret, _, _ := joinkey.Create(ctx, e.store,
		joinkey.Params{Name: "std", Groups: []string{"db"}, MaxUses: 0, AutoIssue: true}, time.Now())

	res, err := e.cons.Process(ctx, e.candidate(t, secret, "host-std"))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if res.Status != enrollment.StatusIssued || res.CertPEM == nil {
		t.Fatalf("auto_issue should issue, got %+v", res)
	}
	if v := certValidity(t, res.CertPEM); v != 24*time.Hour {
		t.Fatalf("standard cert validity = %s, want 24h (CertLifetime)", v)
	}
	if row := e.enrollmentRow(t, "eid-host-std"); row.Ephemeral {
		t.Fatalf("ephemeral=%v on a non-ephemeral key, want false", row.Ephemeral)
	}
}

// TestEnrollEphemeralApproveRederives: a PENDING enrollment via an ephemeral key, on
// Approve, re-derives ephemeral from the join key — the issued cert gets the shorter
// EphemeralCertTTL and the row stays ephemeral=true (mirrors the netblock re-derivation).
func TestEnrollEphemeralApproveRederives(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	// auto_issue=false (default) => lands PENDING; Ephemeral=true on the key.
	secret, _, _ := joinkey.Create(ctx, e.store,
		joinkey.Params{Name: "eph-pending", Groups: []string{"ci"}, MaxUses: 1, Ephemeral: true}, time.Now())

	res, err := e.cons.Process(ctx, e.candidate(t, secret, "host-ephp"))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if res.Status != enrollment.StatusPending {
		t.Fatalf("ephemeral non-auto key should land PENDING, got %+v", res)
	}
	// The pending row already carries the flag (recorded at processToken time).
	if row := e.enrollmentRow(t, "eid-host-ephp"); !row.Ephemeral {
		t.Fatalf("pending row ephemeral=%v, want true", row.Ephemeral)
	}

	app, err := e.cons.Approve(ctx, "eid-host-ephp", "admin")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if app.Status != enrollment.StatusIssued {
		t.Fatalf("approve status = %s", app.Status)
	}
	e.verifyCert(t, app.CertPEM)
	if v := certValidity(t, app.CertPEM); v != 2*time.Hour {
		t.Fatalf("approved ephemeral cert validity = %s, want 2h (re-derived EphemeralCertTTL)", v)
	}
	if row := e.enrollmentRow(t, "eid-host-ephp"); !row.Ephemeral || row.Status != enrollment.StatusIssued {
		t.Fatalf("post-approve row ephemeral=%v status=%s, want true/issued", row.Ephemeral, row.Status)
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
