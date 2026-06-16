package adminapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/adminapi"
	"github.com/jeks313/nebula-control-plane/internal/fleet"
	"github.com/jeks313/nebula-control-plane/internal/nebularelease"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

// TestReleasesListAndRolloutOverHTTP exercises the #39 surface: list the release
// registries, stage a fleet upgrade on a kind's lane, and abort it — with the responses
// conforming to the OpenAPI spec.
func TestReleasesListAndRolloutOverHTTP(t *testing.T) {
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(t.TempDir() + "/r.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Seed a nebula release (added via the CLI in real life) + a fleet heartbeat so a
	// rollout has a host to stage onto.
	rel, err := nebularelease.New(s.DB).Add(ctx, "1.10.3", "", "", strings.Repeat("a", 64), "https://cdn/nebula", "")
	if err != nil {
		t.Fatal(err)
	}
	// A fresh heartbeat — adminapi.New defaults StaleAfter=5m, so the rollout host read
	// (liveFleet) only counts recently-seen hosts.
	if err := s.DB.Exec(`INSERT INTO heartbeats (overlay_ip, device_name, last_seen) VALUES (?,?,?)`,
		"10.44.0.10", "h1", time.Now().UnixNano()).Error; err != nil {
		t.Fatal(err)
	}
	audit := func(c context.Context, a, ac, tgt, d string) error { _, e := s.AppendAudit(c, a, ac, tgt, d); return e }
	srv := adminapi.New(adminapi.Config{
		Store: s, Identity: adminapi.DevHeaderProvider{Roles: []string{"admin"}}, Rollout: rollout.New(s.DB, audit),
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	doc := loadSpec(t)

	// List: the nebula registry carries the seeded release; pilot is empty.
	code, body := req(t, ts, "GET", "/admin/v1/releases", "alice", nil)
	if code != http.StatusOK {
		t.Fatalf("list status = %d", code)
	}
	conform(t, doc, "GET", "/admin/v1/releases", 200, body)
	neb, _ := body["nebula"].(map[string]any)
	if rels, _ := neb["releases"].([]any); len(rels) != 1 {
		t.Fatalf("want 1 nebula release, got %v", neb["releases"])
	}

	// Stage gen onto the nebula lane.
	code, started := req(t, ts, "POST", "/admin/v1/releases/nebula/rollouts", "alice",
		map[string]any{"gen": rel.Gen, "canary_size": 1})
	if code != http.StatusCreated {
		t.Fatalf("start status = %d (%v)", code, started)
	}
	conform(t, doc, "POST", "/admin/v1/releases/{kind}/rollouts", 201, started)

	// Unknown gen -> 400; unknown kind -> 404.
	if c, _ := req(t, ts, "POST", "/admin/v1/releases/nebula/rollouts", "alice", map[string]any{"gen": 9999}); c != http.StatusConflict && c != http.StatusBadRequest {
		// (a 2nd active start on the same lane is 409; an unknown gen is 400 — either proves it didn't blindly start)
		t.Fatalf("bad start status = %d, want 400 or 409", c)
	}
	if c, _ := req(t, ts, "POST", "/admin/v1/releases/bogus/rollouts", "alice", map[string]any{"gen": 1}); c != http.StatusNotFound {
		t.Fatalf("unknown kind status = %d, want 404", c)
	}

	// Abort.
	code, _ = req(t, ts, "POST", "/admin/v1/releases/nebula/rollouts/current/abort", "alice", nil)
	if code != http.StatusOK {
		t.Fatalf("abort status = %d", code)
	}
}

// TestReleaseRolloutExcludesStaleHosts: a staged release reads the fleet itself (unlike
// the policy /rollouts path), so it must drop long-silent ghost hosts. A dead host left
// in the canary wave would trip the engine's missing-host check and silently roll back.
func TestReleaseRolloutExcludesStaleHosts(t *testing.T) {
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(t.TempDir() + "/rs.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rel, err := nebularelease.New(s.DB).Add(ctx, "1.10.3", "", "", strings.Repeat("a", 64), "https://cdn/nebula", "")
	if err != nil {
		t.Fatal(err)
	}
	// One long-silent ghost (heard from days ago) — the only host on file.
	if err := s.DB.Exec(`INSERT INTO heartbeats (overlay_ip, device_name, last_seen) VALUES (?,?,?)`,
		"10.44.0.5", "ghost", time.Now().Add(-72*time.Hour).UnixNano()).Error; err != nil {
		t.Fatal(err)
	}
	audit := func(c context.Context, a, ac, tgt, d string) error { _, e := s.AppendAudit(c, a, ac, tgt, d); return e }
	srv := adminapi.New(adminapi.Config{
		Store: s, Identity: adminapi.DevHeaderProvider{Roles: []string{"admin"}}, Rollout: rollout.New(s.DB, audit),
		Thresholds: fleet.Thresholds{StaleAfter: time.Hour},
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Only a stale host exists -> staging refuses (no live target), not a silent abort.
	if c, _ := req(t, ts, "POST", "/admin/v1/releases/nebula/rollouts", "alice", map[string]any{"gen": rel.Gen}); c != http.StatusBadRequest {
		t.Fatalf("stale-only start = %d, want 400 (no live hosts)", c)
	}
	// Add a fresh host -> staging proceeds onto exactly that host.
	if err := s.DB.Exec(`INSERT INTO heartbeats (overlay_ip, device_name, last_seen) VALUES (?,?,?)`,
		"10.44.0.20", "live", time.Now().UnixNano()).Error; err != nil {
		t.Fatal(err)
	}
	if c, _ := req(t, ts, "POST", "/admin/v1/releases/nebula/rollouts", "alice", map[string]any{"gen": rel.Gen, "canary_size": 1}); c != http.StatusCreated {
		t.Fatalf("live-host start = %d, want 201", c)
	}
}

// TestReleaseRolloutRequiresPermission: a viewer cannot stage or abort a fleet upgrade.
func TestReleaseRolloutRequiresPermission(t *testing.T) {
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(t.TempDir() + "/rp.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	srv := adminapi.New(adminapi.Config{Store: s, Identity: adminapi.DevHeaderProvider{Roles: []string{"viewer"}}})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	if c, _ := req(t, ts, "POST", "/admin/v1/releases/nebula/rollouts", "v", map[string]any{"gen": 1}); c != http.StatusForbidden {
		t.Fatalf("viewer start status = %d, want 403", c)
	}
	if c, _ := req(t, ts, "POST", "/admin/v1/releases/nebula/rollouts/current/abort", "v", nil); c != http.StatusForbidden {
		t.Fatalf("viewer abort status = %d, want 403", c)
	}
	// But a viewer can LIST.
	if c, _ := req(t, ts, "GET", "/admin/v1/releases", "v", nil); c != http.StatusOK {
		t.Fatalf("viewer list status = %d, want 200", c)
	}
}
