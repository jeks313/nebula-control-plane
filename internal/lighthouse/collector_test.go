package lighthouse

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(t.TempDir() + "/lh.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	return s
}

// mintLighthouseCert signs a leaf cert (group lighthouse) expiring at notAfter and returns the PEM,
// mirroring how genesis/rotate-cert mint via the signer (software backend) so the collector parses
// a byte-for-byte real cert.
func mintLighthouseCert(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	pool := netip.MustParsePrefix("10.44.0.0/16")
	backend, err := signer.NewSoftwareBackend()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	_, caPEM, err := signer.SelfSignCA(backend, signer.CATemplate{
		Name: "harbor-ca", Networks: []netip.Prefix{pool},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	sg, err := signer.New(signer.Config{
		CACertPEM: caPEM, Backend: backend,
		Policy: signer.IssuePolicy{AllowedNetwork: pool, MaxLifetime: 10 * 365 * 24 * time.Hour},
		Audit:  func(context.Context, string, string, string, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	hk, _ := ecdh.P256().GenerateKey(rand.Reader)
	_, pem, err := sg.Issue(context.Background(), "op", signer.Template{
		Name:      "lighthouse-1",
		Networks:  []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr("10.44.0.1"), pool.Bits())},
		Groups:    []string{"lighthouse"},
		NotBefore: now.Add(-5 * time.Minute),
		NotAfter:  notAfter,
		PublicKey: hk.PublicKey().Bytes(),
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return pem
}

// gather registers the collector on a fresh registry and returns name -> samples for one metric.
func gather(t *testing.T, c *Collector, metric string) []*dto.Metric {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatal(err)
	}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() == metric {
			return mf.GetMetric()
		}
	}
	return nil
}

func label(m *dto.Metric, name string) string {
	for _, l := range m.GetLabel() {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}

// TestCollectorCertExpiry: an issued lighthouse enrollment expiring in ~100d yields a
// ncp_lighthouse_cert_expiry_seconds{name} of ~100d. This is the rotation backstop.
func TestCollectorCertExpiry(t *testing.T) {
	s := newTestStore(t)
	pem := mintLighthouseCert(t, time.Now().Add(100*24*time.Hour))
	enroll := func(id, name, groups, ip string, pem []byte) {
		if err := s.DB.Table("enrollments").Create(map[string]any{
			"enrollment_id": id, "device_name": name, "pubkey_hash": id + "-h", "pubkey": []byte("k"), "method": "genesis",
			"status": "issued", "groups": groups, "cert_pem": pem, "overlay_ip": ip,
			"fingerprint": id + "-fp", "created_at": int64(1), "decided_at": int64(1),
		}).Error; err != nil {
			t.Fatal(err)
		}
	}
	enroll("e-lh1", "lighthouse-1", `["lighthouse"]`, "10.44.0.1", pem)
	// A non-lighthouse issued enrollment must NOT be emitted.
	enroll("e-laptop", "laptop-1", `["users"]`, "10.44.64.9", mintLighthouseCert(t, time.Now().Add(30*24*time.Hour)))

	ms := gather(t, NewCollector(s.DB), "ncp_lighthouse_cert_expiry_seconds")
	if len(ms) != 1 {
		t.Fatalf("expected 1 cert-expiry series (lighthouse only), got %d", len(ms))
	}
	if label(ms[0], "name") != "lighthouse-1" {
		t.Fatalf("name label = %q, want lighthouse-1", label(ms[0], "name"))
	}
	if v := ms[0].GetGauge().GetValue(); v < 99*24*3600 || v > 100*24*3600 {
		t.Fatalf("cert expiry = %.0fs, want ~100d", v)
	}
}

// TestCollectorRotationLiveness: RecordRotation feeds last_run/last_rotated/runs_total.
func TestCollectorRotationLiveness(t *testing.T) {
	s := newTestStore(t)
	r := New(s.DB, func(context.Context, string, string, string, string) error { return nil })
	ctx := context.Background()
	if err := r.RecordRotation(ctx, "lighthouse-2", "skip", ""); err != nil {
		t.Fatal(err)
	}
	if err := r.RecordRotation(ctx, "lighthouse-2", "ok", ""); err != nil {
		t.Fatal(err)
	}
	if err := r.RecordRotation(ctx, "lighthouse-2", "fail", "ecs not stable"); err != nil {
		t.Fatal(err)
	}

	c := NewCollector(s.DB)
	lastRun := gather(t, c, "ncp_lighthouse_rotation_last_run_seconds")
	if len(lastRun) != 1 || lastRun[0].GetGauge().GetValue() <= 0 {
		t.Fatalf("last_run not recorded: %+v", lastRun)
	}
	rotated := gather(t, NewCollector(s.DB), "ncp_lighthouse_rotation_last_rotated_seconds")
	if len(rotated) != 1 || rotated[0].GetGauge().GetValue() <= 0 {
		t.Fatalf("last_rotated should be set by the ok run: %+v", rotated)
	}
	runs := gather(t, NewCollector(s.DB), "ncp_lighthouse_rotation_runs_total")
	got := map[string]float64{}
	for _, m := range runs {
		got[label(m, "result")] = m.GetCounter().GetValue()
	}
	if got["ok"] != 1 || got["skip"] != 1 || got["fail"] != 1 {
		t.Fatalf("runs_total = %v, want ok=1 skip=1 fail=1", got)
	}

	// last_result/last_error landed on the row (for the dashboard / RotationFailed forensics).
	var rs RotationStatus
	if err := s.DB.Where("name = ?", "lighthouse-2").First(&rs).Error; err != nil {
		t.Fatal(err)
	}
	if rs.LastResult != "fail" || rs.LastError != "ecs not stable" {
		t.Fatalf("row = %+v, want last_result=fail last_error set", rs)
	}
}
