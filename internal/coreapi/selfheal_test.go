package coreapi

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/genesis"
	"github.com/jeks313/nebula-control-plane/internal/ipam"
	"github.com/jeks313/nebula-control-plane/internal/revocation"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
	"github.com/slackhq/nebula/cert"
)

// --- harness ---------------------------------------------------------------

var testPool = netip.MustParsePrefix("100.64.0.0/16")

type coreFixture struct {
	srv     *Server
	store   *store.Store
	backend signer.Backend
	caCert  cert.Certificate
	alloc   *ipam.Allocator
	rev     *revocation.Registry
}

func newCoreFixture(t *testing.T) *coreFixture {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(filepath.Join(t.TempDir(), "core.db"))})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	b, err := signer.NewSoftwareBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	pub, err := b.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	caC, err := signer.SignTBS(b, &cert.TBSCertificate{
		Version: cert.Version2, Name: "test-ca", IsCA: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		PublicKey: pub, Curve: cert.Curve_P256,
	}, nil)
	if err != nil {
		t.Fatalf("self-sign CA: %v", err)
	}
	alloc, err := ipam.NewAllocator(s, ipam.Pool{Prefix: testPool})
	if err != nil {
		t.Fatalf("allocator: %v", err)
	}
	rev := revocation.New(s.DB, func(context.Context, string, string, string, string) error { return nil })
	srv := New(Config{
		Store: s, Pool: testPool, CertLifetime: time.Hour,
		Allocator: alloc, Revocation: rev, Central: genesis.CentralBlock(testPool),
		Now: time.Now,
	})
	return &coreFixture{srv: srv, store: s, backend: b, caCert: caC, alloc: alloc, rev: rev}
}

// mintLeaf signs a host leaf cert with the given expiry; returns (pem, fingerprint).
func (f *coreFixture) mintLeaf(t *testing.T, name, overlayIP string, notAfter time.Time) ([]byte, string) {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := signer.SignTBS(f.backend, &cert.TBSCertificate{
		Version: cert.Version2, Name: name,
		Networks:  []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr(overlayIP), testPool.Bits())},
		Groups:    []string{"laptops"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter,
		PublicKey: k.PublicKey().Bytes(), Curve: cert.Curve_P256,
	}, f.caCert)
	if err != nil {
		t.Fatalf("sign leaf: %v", err)
	}
	pem, err := leaf.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	fp, err := leaf.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	return pem, fp
}

// seedEnroll inserts an enrollment row (any status) with a cert.
func (f *coreFixture) seedEnroll(t *testing.T, status, name, overlayIP string, certPEM []byte, fp string) {
	t.Helper()
	e := enrollment.Enrollment{
		EnrollmentID: name + "-enr", DeviceName: name, OverlayIP: overlayIP,
		Groups: `["laptops"]`, Status: status, CertPEM: certPEM, Fingerprint: fp,
		Pubkey: []byte("x"), Method: "token", CreatedAt: time.Now().UnixNano(),
	}
	if err := f.store.DB.Create(&e).Error; err != nil {
		t.Fatalf("seed enrollment: %v", err)
	}
}

// allocOwner returns the device name holding overlayIP in IPAM, "" if free.
func (f *coreFixture) allocOwner(t *testing.T, overlayIP string) string {
	t.Helper()
	var name string
	_ = f.store.DB.Raw(
		"SELECT d.name FROM ip_allocations a JOIN devices d ON d.id = a.device_id WHERE a.ip = ?", overlayIP).Scan(&name).Error
	return name
}

func (f *coreFixture) enrollStatus(t *testing.T, name string) string {
	t.Helper()
	var st string
	_ = f.store.DB.Raw("SELECT status FROM enrollments WHERE device_name = ? ORDER BY id DESC LIMIT 1", name).Scan(&st).Error
	return st
}

func (f *coreFixture) heartbeatExists(t *testing.T, overlayIP string) bool {
	t.Helper()
	var n int64
	_ = f.store.DB.Raw("SELECT COUNT(*) FROM heartbeats WHERE overlay_ip = ?", overlayIP).Scan(&n).Error
	return n > 0
}

func (f *coreFixture) beat(overlayIP string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", strings.NewReader(`{"type":"heartbeat"}`))
	req.RemoteAddr = overlayIP + ":40000"
	w := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(w, req)
	return w
}

// --- tests -----------------------------------------------------------------

// BLOCKER-1 fix: a live host (issued enrollment) whose overlay IP was released (a reaper
// false-positive) gets its IPAM allocation re-asserted on its next heartbeat — so the IP can never be
// handed to a second device.
func TestHeartbeatReconcilesReleasedIP(t *testing.T) {
	f := newCoreFixture(t)
	const ip = "100.64.0.100"
	pem, fp := f.mintLeaf(t, "macA", ip, time.Now().Add(time.Hour))
	f.seedEnroll(t, "issued", "macA", ip, pem, fp)
	// Allocate then RELEASE the IP (simulate the reaper reclaiming a live host's IP).
	if err := f.alloc.AllocateSpecific(context.Background(), "macA", netip.MustParseAddr(ip), "token"); err != nil {
		t.Fatalf("seed alloc: %v", err)
	}
	if err := f.alloc.Release(context.Background(), netip.MustParseAddr(ip)); err != nil {
		t.Fatalf("seed release: %v", err)
	}
	if o := f.allocOwner(t, ip); o != "" {
		t.Fatalf("precondition: IP should be free after release, got owner %q", o)
	}

	if w := f.beat(ip); w.Code != http.StatusOK {
		t.Fatalf("heartbeat code = %d, want 200; body=%s", w.Code, w.Body)
	}
	if o := f.allocOwner(t, ip); o != "macA" {
		t.Fatalf("after heartbeat, IP %s owner = %q, want macA (reconcile must re-assert it)", ip, o)
	}
}

// A genuine conflict — the overlay IP now belongs to a DIFFERENT device — must NOT be clobbered.
func TestHeartbeatReconcileIPConflictNotClobbered(t *testing.T) {
	f := newCoreFixture(t)
	const ip = "100.64.0.110"
	pem, fp := f.mintLeaf(t, "macA", ip, time.Now().Add(time.Hour))
	f.seedEnroll(t, "issued", "macA", ip, pem, fp)
	// A different device already holds the IP in IPAM.
	if err := f.alloc.AllocateSpecific(context.Background(), "otherdev", netip.MustParseAddr(ip), "token"); err != nil {
		t.Fatalf("seed alloc: %v", err)
	}
	if w := f.beat(ip); w.Code != http.StatusOK {
		t.Fatalf("heartbeat code = %d, want 200", w.Code)
	}
	if o := f.allocOwner(t, ip); o != "otherdev" {
		t.Fatalf("IP owner = %q, want otherdev unchanged (must not clobber)", o)
	}
}

// Self-heal happy path: a non-issued enrollment carrying a VALID, non-revoked cert is repaired
// (re-marked issued, IP re-claimed) on heartbeat.
func TestSelfHealValidRepairs(t *testing.T) {
	f := newCoreFixture(t)
	const ip = "100.64.0.101"
	pem, fp := f.mintLeaf(t, "macB", ip, time.Now().Add(time.Hour))
	f.seedEnroll(t, "denied", "macB", ip, pem, fp) // not 'issued' -> device() !ok -> self-heal path
	if w := f.beat(ip); w.Code != http.StatusOK {
		t.Fatalf("heartbeat code = %d, want 200 (self-heal); body=%s", w.Code, w.Body)
	}
	if st := f.enrollStatus(t, "macB"); st != "issued" {
		t.Fatalf("enrollment status = %q, want issued (re-marked)", st)
	}
	if o := f.allocOwner(t, ip); o != "macB" {
		t.Fatalf("IP owner = %q, want macB (re-allocated)", o)
	}
	if !f.heartbeatExists(t, ip) {
		t.Fatalf("heartbeat row missing after self-heal")
	}
}

// A REVOKED fingerprint must never self-heal, even with a valid, unexpired cert.
func TestSelfHealRevokedRefused(t *testing.T) {
	f := newCoreFixture(t)
	const ip = "100.64.0.102"
	pem, fp := f.mintLeaf(t, "macR", ip, time.Now().Add(time.Hour))
	f.seedEnroll(t, "denied", "macR", ip, pem, fp)
	if _, err := f.rev.Add(context.Background(), fp, "test", "operator"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	w := f.beat(ip)
	if w.Code == http.StatusOK {
		t.Fatalf("heartbeat succeeded for a revoked cert; want refusal")
	}
	if st := f.enrollStatus(t, "macR"); st == "issued" {
		t.Fatalf("revoked enrollment was re-marked issued; must stay %q", st)
	}
}

// An EXPIRED stored cert must not self-heal (the host must re-enroll/renew).
func TestSelfHealExpiredCertRefused(t *testing.T) {
	f := newCoreFixture(t)
	const ip = "100.64.0.103"
	pem, fp := f.mintLeaf(t, "macE", ip, time.Now().Add(-time.Hour)) // expired
	f.seedEnroll(t, "denied", "macE", ip, pem, fp)
	w := f.beat(ip)
	if w.Code == http.StatusOK {
		t.Fatalf("heartbeat succeeded for an expired cert; want refusal")
	}
	if st := f.enrollStatus(t, "macE"); st == "issued" {
		t.Fatalf("expired-cert enrollment was re-marked issued; must stay %q", st)
	}
}

// No enrollment at the source overlay IP: never fabricate identity — keep the 403.
func TestSelfHealNoEnrollmentRefused(t *testing.T) {
	f := newCoreFixture(t)
	w := f.beat("100.64.0.150")
	if w.Code == http.StatusOK {
		t.Fatalf("heartbeat succeeded with no enrollment; want refusal")
	}
}
