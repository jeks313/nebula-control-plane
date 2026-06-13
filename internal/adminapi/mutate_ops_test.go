package adminapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/adminapi"
	"github.com/jeks313/nebula-control-plane/internal/lighthouse"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

// fullSrv builds an admin server with the rollout + lighthouse engines wired,
// for the A0.4 fleet-management mutations.
func fullSrv(t *testing.T, role string) *httptest.Server {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(t.TempDir() + "/f.db")})
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
	srv := adminapi.New(adminapi.Config{
		Store:       s,
		Identity:    adminapi.DevHeaderProvider{Roles: []string{role}},
		Rollout:     rollout.New(s.DB, audit),
		Lighthouses: lighthouse.New(s.DB, audit),
	})
	return httptest.NewServer(srv.Handler())
}

// TestLighthouseLifecycleOverHTTP: add → swap (add new, remove old) → last-active
// removal blocked → re-address.
func TestLighthouseLifecycleOverHTTP(t *testing.T) {
	ts := fullSrv(t, "admin")
	defer ts.Close()
	doc := loadSpec(t)

	code, lh := req(t, ts, "POST", "/admin/v1/lighthouses", "alice",
		map[string]any{"overlay_ip": "10.44.0.1", "hostname": "lh1", "public_addrs": []string{"1.2.3.4:4242"}})
	if code != http.StatusCreated {
		t.Fatalf("add status = %d (%v)", code, lh)
	}
	conform(t, doc, "POST", "/admin/v1/lighthouses", 201, lh)

	// Removing the only lighthouse is refused (discovery-never-lost invariant).
	if code, _ := req(t, ts, "DELETE", "/admin/v1/lighthouses/10.44.0.1", "alice", nil); code != http.StatusConflict {
		t.Fatalf("remove-last status = %d, want 409", code)
	}
	// Add a second, then retiring the first is allowed.
	req(t, ts, "POST", "/admin/v1/lighthouses", "alice",
		map[string]any{"overlay_ip": "10.44.0.2", "public_addrs": []string{"5.6.7.8:4242"}})
	if code, del := req(t, ts, "DELETE", "/admin/v1/lighthouses/10.44.0.1", "alice", nil); code != http.StatusOK {
		t.Fatalf("remove status = %d (%v)", code, del)
	}
	// Re-address the survivor.
	code, rep := req(t, ts, "PUT", "/admin/v1/lighthouses/10.44.0.2", "alice",
		map[string]any{"public_addrs": []string{"9.9.9.9:4242"}})
	if code != http.StatusOK {
		t.Fatalf("replace status = %d (%v)", code, rep)
	}
	conform(t, doc, "PUT", "/admin/v1/lighthouses/{ip}", 200, rep)
}

// TestRolloutLifecycleOverHTTP: start → current → step → abort → restart.
func TestRolloutLifecycleOverHTTP(t *testing.T) {
	ts := fullSrv(t, "admin")
	defer ts.Close()
	doc := loadSpec(t)

	code, none := req(t, ts, "GET", "/admin/v1/rollouts/current", "alice", nil)
	if code != http.StatusOK || none["active"] != false {
		t.Fatalf("current(none) = %v", none)
	}
	conform(t, doc, "GET", "/admin/v1/rollouts/current", 200, none)

	code, r := req(t, ts, "POST", "/admin/v1/rollouts", "alice",
		map[string]any{"target_version": 2, "prev_version": 1, "hosts": []string{"10.44.0.10", "10.44.0.11"}, "canary_size": 1})
	if code != http.StatusCreated {
		t.Fatalf("start status = %d (%v)", code, r)
	}
	conform(t, doc, "POST", "/admin/v1/rollouts", 201, r)

	// A second start while active is refused.
	if code, _ := req(t, ts, "POST", "/admin/v1/rollouts", "alice",
		map[string]any{"target_version": 3, "hosts": []string{"10.44.0.10"}}); code != http.StatusConflict {
		t.Fatalf("double-start status = %d, want 409", code)
	}
	code, step := req(t, ts, "POST", "/admin/v1/rollouts/current/step", "alice", nil)
	if code != http.StatusOK {
		t.Fatalf("step status = %d", code)
	}
	conform(t, doc, "POST", "/admin/v1/rollouts/current/step", 200, step)

	if code, _ := req(t, ts, "POST", "/admin/v1/rollouts/current/abort", "alice", nil); code != http.StatusOK {
		t.Fatalf("abort status = %d", code)
	}
	// After abort, a new rollout can start.
	if code, _ := req(t, ts, "POST", "/admin/v1/rollouts", "alice",
		map[string]any{"target_version": 3, "hosts": []string{"10.44.0.12"}}); code != http.StatusCreated {
		t.Fatalf("restart-after-abort status = %d, want 201", code)
	}
}

// TestJoinKeysOverHTTP: create (secret once) → list → revoke → duplicate 409.
func TestJoinKeysOverHTTP(t *testing.T) {
	ts := fullSrv(t, "admin")
	defer ts.Close()
	doc := loadSpec(t)

	code, created := req(t, ts, "POST", "/admin/v1/joinkeys", "alice",
		map[string]any{"name": "imac", "groups": []string{"laptops"}, "max_uses": 2})
	if code != http.StatusCreated {
		t.Fatalf("create status = %d (%v)", code, created)
	}
	conform(t, doc, "POST", "/admin/v1/joinkeys", 201, created)
	if sec, _ := created["secret"].(string); sec == "" {
		t.Fatal("create must return the secret once")
	}

	code, list := req(t, ts, "GET", "/admin/v1/joinkeys", "alice", nil)
	if code != http.StatusOK || list["count"].(float64) != 1 {
		t.Fatalf("list = %v", list)
	}
	conform(t, doc, "GET", "/admin/v1/joinkeys", 200, list)

	if code, _ := req(t, ts, "POST", "/admin/v1/joinkeys/imac/revoke", "alice", nil); code != http.StatusOK {
		t.Fatalf("revoke status = %d", code)
	}
	if code, _ := req(t, ts, "POST", "/admin/v1/joinkeys/nope/revoke", "alice", nil); code != http.StatusNotFound {
		t.Fatalf("revoke-missing status = %d, want 404", code)
	}
	// Duplicate name → 409.
	if code, _ := req(t, ts, "POST", "/admin/v1/joinkeys", "alice",
		map[string]any{"name": "imac"}); code != http.StatusConflict {
		t.Fatalf("duplicate-name status = %d, want 409", code)
	}
}

// TestFleetMutationsRequireAdmin: a viewer is 403 on every mutation.
func TestFleetMutationsRequireAdmin(t *testing.T) {
	ts := fullSrv(t, "viewer")
	defer ts.Close()
	cases := []struct {
		method, path string
		body         any
	}{
		{"POST", "/admin/v1/lighthouses", map[string]any{"overlay_ip": "10.44.0.1", "public_addrs": []string{"x:4242"}}},
		{"POST", "/admin/v1/rollouts", map[string]any{"target_version": 2, "hosts": []string{"10.44.0.1"}}},
		{"POST", "/admin/v1/joinkeys", map[string]any{"name": "k"}},
		{"DELETE", "/admin/v1/lighthouses/10.44.0.1", nil},
		{"POST", "/admin/v1/rollouts/current/abort", nil},
	}
	for _, c := range cases {
		if code, _ := req(t, ts, c.method, c.path, "carol", c.body); code != http.StatusForbidden {
			t.Errorf("%s %s as viewer = %d, want 403", c.method, c.path, code)
		}
	}
	// Reads remain allowed.
	if code, _ := req(t, ts, "GET", "/admin/v1/joinkeys", "carol", nil); code != http.StatusOK {
		t.Errorf("viewer GET joinkeys = %d, want 200", code)
	}
}
