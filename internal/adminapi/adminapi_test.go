package adminapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/adminapi"
	"github.com/jeks313/nebula-control-plane/internal/lighthouse"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
	"gorm.io/gorm"
)

func newServer(t *testing.T) (*store.Store, http.Handler) {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(t.TempDir() + "/a.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	audit := func(ctx context.Context, a, ac, tgt, d string) error {
		_, e := s.AppendAudit(ctx, a, ac, tgt, d)
		return e
	}
	api := adminapi.New(adminapi.Config{
		Store:       s,
		Identity:    adminapi.DevHeaderProvider{},
		Rollout:     rollout.New(s.DB, audit),
		Lighthouses: lighthouse.New(s.DB, audit),
		Now:         func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	})
	return s, api.Handler()
}

// hbInsert writes a heartbeat row the way coreapi would.
func hbInsert(t *testing.T, db *gorm.DB, ip, name string, certNotAfter, lastSeen time.Time, health string) {
	t.Helper()
	sql := `INSERT INTO heartbeats (overlay_ip, device_name, pilot_version, nebula_version, cert_not_after, applied_bundle_version, clock_offset_ms, health, last_seen)
	        VALUES (?, ?, '1.0', '1.10.3', ?, 1, 0, ?, ?)`
	if err := db.Exec(sql, ip, name, certNotAfter.UnixNano(), health, lastSeen.UnixNano()).Error; err != nil {
		t.Fatal(err)
	}
}

func do(t *testing.T, h http.Handler, method, path, actor string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if actor != "" {
		req.Header.Set("X-Harbor-Dev-Actor", actor)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr, body
}

// TestUnauthenticated: no dev-actor header → 401 problem+json.
func TestUnauthenticated(t *testing.T) {
	_, h := newServer(t)
	rr, body := do(t, h, "GET", "/admin/v1/me", "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if rr.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("content-type = %q, want problem+json", rr.Header().Get("Content-Type"))
	}
	if body["title"] != "unauthenticated" {
		t.Fatalf("problem title = %v", body["title"])
	}
}

// TestMe: the dev actor is reflected back as the identity.
func TestMe(t *testing.T) {
	_, h := newServer(t)
	rr, body := do(t, h, "GET", "/admin/v1/me", "alice")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if body["principal"] != "alice" {
		t.Fatalf("principal = %v, want alice", body["principal"])
	}
	roles, _ := body["roles"].([]any)
	if len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("roles = %v, want [admin]", body["roles"])
	}
}

// TestFleetHealthHealthy: no problems → healthy, no reasons.
func TestFleetHealthHealthy(t *testing.T) {
	s, h := newServer(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	hbInsert(t, s.DB, "100.64.0.2", "web-1", now.Add(30*24*time.Hour), now, "ok")
	rr, body := do(t, h, "GET", "/admin/v1/fleet/health", "alice")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if body["status"] != "healthy" {
		t.Fatalf("status = %v, want healthy", body["status"])
	}
	if reasons, _ := body["reasons"].([]any); len(reasons) != 0 {
		t.Fatalf("healthy fleet should have no reasons, got %v", reasons)
	}
	// Contract: reasons is always a JSON array, never null (else the UI's .map throws).
	if !strings.Contains(rr.Body.String(), `"reasons":[]`) {
		t.Fatalf("reasons must serialize as [], got: %s", rr.Body.String())
	}
}

// TestFleetHealthCritical: an expired cert → critical with CERTS_EXPIRED.
func TestFleetHealthCritical(t *testing.T) {
	s, h := newServer(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	hbInsert(t, s.DB, "100.64.0.2", "web-1", now.Add(-time.Hour), now, "ok")   // expired
	hbInsert(t, s.DB, "100.64.0.3", "web-2", now.Add(24*time.Hour), now, "ok") // expiring (<7d)
	rr, body := do(t, h, "GET", "/admin/v1/fleet/health", "alice")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if body["status"] != "critical" {
		t.Fatalf("status = %v, want critical", body["status"])
	}
	codes := reasonCodes(body)
	if !codes["CERTS_EXPIRED"] || !codes["CERTS_EXPIRING"] {
		t.Fatalf("expected CERTS_EXPIRED + CERTS_EXPIRING, got %v", codes)
	}
}

// TestFleetHealthAuditBreak: a tampered audit row → critical AUDIT_CHAIN_BROKEN.
func TestFleetHealthAuditBreak(t *testing.T) {
	s, h := newServer(t)
	ctx := context.Background()
	_, _ = s.AppendAudit(ctx, "op", "test", "x", "")
	_, _ = s.AppendAudit(ctx, "op", "test", "y", "")
	// Tamper a row so VerifyAudit fails.
	if err := s.DB.Exec("UPDATE audit_log SET target='tampered' WHERE seq=1").Error; err != nil {
		t.Fatal(err)
	}
	rr, body := do(t, h, "GET", "/admin/v1/fleet/health", "alice")
	if rr.Code != http.StatusOK || body["status"] != "critical" {
		t.Fatalf("status = %v (code %d), want critical", body["status"], rr.Code)
	}
	if !reasonCodes(body)["AUDIT_CHAIN_BROKEN"] {
		t.Fatalf("expected AUDIT_CHAIN_BROKEN, got %v", body["reasons"])
	}
	if body["audit_ok"] != false {
		t.Fatalf("audit_ok = %v, want false", body["audit_ok"])
	}
}

// TestDevicesAndAudit: read endpoints return seeded data.
func TestDevicesAndAudit(t *testing.T) {
	s, h := newServer(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	hbInsert(t, s.DB, "100.64.0.2", "web-1", now.Add(30*24*time.Hour), now, "ok")
	_, _ = s.AppendAudit(context.Background(), "alice", "policy-publish", "fw", "")

	_, dev := do(t, h, "GET", "/admin/v1/devices", "alice")
	devs, _ := dev["devices"].([]any)
	if len(devs) != 1 {
		t.Fatalf("devices = %v, want 1", dev["devices"])
	}

	_, au := do(t, h, "GET", "/admin/v1/audit?limit=10", "alice")
	entries, _ := au["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("audit entries = %v, want 1", au["entries"])
	}

	rr, ver := do(t, h, "GET", "/admin/v1/audit/verify", "alice")
	if rr.Code != http.StatusOK || ver["ok"] != true {
		t.Fatalf("audit verify ok = %v (code %d)", ver["ok"], rr.Code)
	}
}

// TestLighthouses: the registry is surfaced.
func TestLighthouses(t *testing.T) {
	s, h := newServer(t)
	reg := lighthouse.New(s.DB, nil)
	if _, err := reg.Add(context.Background(), "100.64.0.1", "lh1", []string{"1.2.3.4:4242"}, "op"); err != nil {
		t.Fatal(err)
	}
	_, body := do(t, h, "GET", "/admin/v1/lighthouses", "alice")
	lhs, _ := body["lighthouses"].([]any)
	if len(lhs) != 1 {
		t.Fatalf("lighthouses = %v, want 1", body["lighthouses"])
	}
}

func reasonCodes(body map[string]any) map[string]bool {
	out := map[string]bool{}
	reasons, _ := body["reasons"].([]any)
	for _, r := range reasons {
		if m, ok := r.(map[string]any); ok {
			if c, ok := m["code"].(string); ok {
				out[c] = true
			}
		}
	}
	return out
}
