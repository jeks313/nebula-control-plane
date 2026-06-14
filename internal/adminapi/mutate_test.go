package adminapi_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/jeks313/nebula-control-plane/internal/adminapi"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

// plainSrv builds an admin server (no seed) with a configurable dev role.
func plainSrv(t *testing.T, role string) *httptest.Server {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(t.TempDir() + "/m.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	srv := adminapi.New(adminapi.Config{Store: s, Identity: adminapi.DevHeaderProvider{Roles: []string{role}}})
	return httptest.NewServer(srv.Handler())
}

func req(t *testing.T, ts *httptest.Server, method, path, actor string, body any) (int, map[string]any) {
	t.Helper()
	var rdr = bytes.NewReader(nil)
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	r, _ := http.NewRequest(method, ts.URL+path, rdr)
	if actor != "" {
		r.Header.Set("X-Harbor-Dev-Actor", actor)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

// TestPolicyDualControlOverHTTP is the A0.3 showcase: propose → self-approve
// blocked → second distinct approver commits → it becomes the active policy.
func TestPolicyDualControlOverHTTP(t *testing.T) {
	ts := plainSrv(t, "admin")
	defer ts.Close()
	doc := loadSpec(t)

	// Propose as alice.
	code, ch := req(t, ts, "POST", "/admin/v1/policy/propose", "alice",
		map[string]any{"policy": "allow web -> db tcp 5432\n"})
	if code != http.StatusCreated {
		t.Fatalf("propose status = %d, want 201 (%v)", code, ch)
	}
	conform(t, doc, "POST", "/admin/v1/policy/propose", 201, ch)
	id := int64(ch["id"].(float64))
	if ch["state"] != "pending" || ch["proposer"] != "alice" {
		t.Fatalf("change = %v", ch)
	}

	// alice cannot approve her own change.
	if code, _ := req(t, ts, "POST", fmt.Sprintf("/admin/v1/approvals/%d/approve", id), "alice", nil); code != http.StatusConflict {
		t.Fatalf("self-approve status = %d, want 409", code)
	}

	// bob (distinct) approves → committed.
	code, out := req(t, ts, "POST", fmt.Sprintf("/admin/v1/approvals/%d/approve", id), "bob", nil)
	if code != http.StatusOK || out["state"] != "committed" {
		t.Fatalf("approve status=%d state=%v, want 200/committed", code, out["state"])
	}
	conform(t, doc, "POST", "/admin/v1/approvals/{id}/approve", 200, out)

	// It's now the active fleet policy.
	code, act := req(t, ts, "GET", "/admin/v1/policy/active", "alice", nil)
	if code != http.StatusOK || act["published"] != true {
		t.Fatalf("active = %v", act)
	}
	conform(t, doc, "GET", "/admin/v1/policy/active", 200, act)

	// The approval detail carries the payload + both sign-offs.
	code, det := req(t, ts, "GET", fmt.Sprintf("/admin/v1/approvals/%d", id), "alice", nil)
	if code != http.StatusOK {
		t.Fatalf("detail status = %d", code)
	}
	conform(t, doc, "GET", "/admin/v1/approvals/{id}", 200, det)
	if sigs, _ := det["signoffs"].([]any); len(sigs) != 2 {
		t.Fatalf("signoffs = %v, want 2 (alice propose + bob approve)", det["signoffs"])
	}
}

// TestProposeRejectsBadPolicy: invalid DSL / invariant violation → 400, no change.
func TestProposeRejectsBadPolicy(t *testing.T) {
	ts := plainSrv(t, "admin")
	defer ts.Close()
	// References the reserved control-plane group → invariant violation.
	if code, _ := req(t, ts, "POST", "/admin/v1/policy/propose", "alice",
		map[string]any{"policy": "allow web -> control-plane tcp 443\n"}); code != http.StatusBadRequest {
		t.Fatalf("invariant-violating propose status = %d, want 400", code)
	}
	if code, _ := req(t, ts, "POST", "/admin/v1/policy/propose", "alice",
		map[string]any{"policy": "this is not valid dsl\n"}); code != http.StatusBadRequest {
		t.Fatalf("garbage propose status = %d, want 400", code)
	}
}

// TestMutationsRequireAdminRole: a read-only (viewer) principal is 403 on mutate.
func TestMutationsRequireAdminRole(t *testing.T) {
	ts := plainSrv(t, "viewer")
	defer ts.Close()
	if code, _ := req(t, ts, "POST", "/admin/v1/policy/propose", "carol",
		map[string]any{"policy": "allow web -> db tcp 5432\n"}); code != http.StatusForbidden {
		t.Fatalf("viewer propose status = %d, want 403", code)
	}
	// Reads still work for a viewer.
	if code, _ := req(t, ts, "GET", "/admin/v1/approvals", "carol", nil); code != http.StatusOK {
		t.Fatalf("viewer list approvals status = %d, want 200", code)
	}
}

// TestCompileLiveAnalysis: compile returns validity + invariants + the per-host
// firewall, and stays 200 on a parse error (live-lint surface).
func TestCompileLiveAnalysis(t *testing.T) {
	ts := plainSrv(t, "admin")
	defer ts.Close()
	doc := loadSpec(t)

	code, res := req(t, ts, "POST", "/admin/v1/policy/compile", "alice",
		map[string]any{"policy": "allow web -> db tcp 5432\n", "groups": []string{"web"}})
	if code != http.StatusOK || res["valid"] != true || res["invariants_ok"] != true {
		t.Fatalf("compile = %v", res)
	}
	conform(t, doc, "POST", "/admin/v1/policy/compile", 200, res)

	code, bad := req(t, ts, "POST", "/admin/v1/policy/compile", "alice",
		map[string]any{"policy": "garbage\n"})
	if code != http.StatusOK || bad["valid"] != false {
		t.Fatalf("compile of garbage = %v (want 200 valid:false)", bad)
	}
}

// TestDenyVetoesOverHTTP: a deny moves the change to denied; approve then 409.
func TestDenyVetoesOverHTTP(t *testing.T) {
	ts := plainSrv(t, "admin")
	defer ts.Close()
	_, ch := req(t, ts, "POST", "/admin/v1/policy/propose", "alice",
		map[string]any{"policy": "allow web -> db tcp 5432\n"})
	id := int64(ch["id"].(float64))

	code, out := req(t, ts, "POST", fmt.Sprintf("/admin/v1/approvals/%d/deny", id), "bob",
		map[string]any{"reason": "looks wrong"})
	if code != http.StatusOK || out["state"] != "denied" {
		t.Fatalf("deny status=%d state=%v, want 200/denied", code, out["state"])
	}
	if code, _ := req(t, ts, "POST", fmt.Sprintf("/admin/v1/approvals/%d/approve", id), "carol", nil); code != http.StatusConflict {
		t.Fatalf("approve after deny status = %d, want 409", code)
	}
}

// conform validates a decoded response body against the documented schema for a
// given operation + status code.
func conform(t *testing.T, doc *openapi3.T, method, path string, code int, body any) {
	t.Helper()
	schema := responseSchema(t, doc, method, path, code)
	if err := schema.VisitJSON(body, openapi3.VisitAsResponse()); err != nil {
		t.Fatalf("%s %s %d body does not conform to schema: %v\nbody: %v", method, path, code, err, body)
	}
}
