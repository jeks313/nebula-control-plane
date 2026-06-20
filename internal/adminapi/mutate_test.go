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

// TestConfigSetPolicyNonPrivileged is the ADR-0011 Phase-1 single-operator showcase:
// PUT a non-privileged policy → 200 (written straight to the config store, no
// dual-control), the version bumps, and it becomes the active fleet policy.
func TestConfigSetPolicyNonPrivileged(t *testing.T) {
	ts := plainSrv(t, "admin")
	defer ts.Close()
	doc := loadSpec(t)

	// A plain (non-privileged) policy DSL — a single operator sets it directly.
	code, row := req(t, ts, "PUT", "/admin/v1/config/policy", "alice", "allow web -> db tcp 5432\n")
	if code != http.StatusOK {
		t.Fatalf("PUT policy status = %d, want 200 (%v)", code, row)
	}
	conform(t, doc, "PUT", "/admin/v1/config/{kind}", 200, row)
	if row["set"] != true || row["version"].(float64) != 1 {
		t.Fatalf("row = %v, want set:true version:1", row)
	}

	// A second write bumps the version.
	code, row2 := req(t, ts, "PUT", "/admin/v1/config/policy", "alice", "allow web -> db tcp 443\n")
	if code != http.StatusOK || row2["version"].(float64) != 2 {
		t.Fatalf("second PUT = %d %v, want 200 version:2", code, row2)
	}

	// GET /config/policy reads the store.
	code, got := req(t, ts, "GET", "/admin/v1/config/policy", "alice", nil)
	if code != http.StatusOK || got["set"] != true || got["version"].(float64) != 2 {
		t.Fatalf("GET config = %d %v", code, got)
	}
	conform(t, doc, "GET", "/admin/v1/config/{kind}", 200, got)

	// It's now the active fleet policy.
	code, act := req(t, ts, "GET", "/admin/v1/policy/active", "alice", nil)
	if code != http.StatusOK || act["published"] != true {
		t.Fatalf("active = %v", act)
	}
	conform(t, doc, "GET", "/admin/v1/policy/active", 200, act)
}

// TestConfigSetPrivilegedRoutesTwoPerson is the ADR-0011 Phase-1 privileged showcase:
// a PUT introducing a privileged grant (cloudtrust auto_issue) does NOT write the
// store directly — it returns 202 + a dual-control Change. Self-approve is blocked; a
// distinct operator approves via /approvals/{id}/approve, and the committer writes the
// store (the change then surfaces at /cloudtrust/active).
func TestConfigSetPrivilegedRoutesTwoPerson(t *testing.T) {
	ts := plainSrv(t, "admin")
	defer ts.Close()
	doc := loadSpec(t)

	// Before: store empty.
	if code, none := req(t, ts, "GET", "/admin/v1/cloudtrust/active", "alice", nil); code != http.StatusOK || none["published"] != false {
		t.Fatalf("active (pre) = %d %v, want published:false", code, none)
	}

	// PUT a PRIVILEGED cloudtrust config (auto_issue=true) → 202 + a pending Change.
	code, ch := req(t, ts, "PUT", "/admin/v1/config/cloudtrust", "alice", map[string]any{
		"default_groups": []string{"fleet"},
		"aws":            []map[string]any{{"account": "111122223333", "groups": []string{"web"}, "auto_issue": true}},
	})
	if code != http.StatusAccepted {
		t.Fatalf("privileged PUT status = %d, want 202 (%v)", code, ch)
	}
	conform(t, doc, "PUT", "/admin/v1/config/{kind}", 202, ch)
	id := int64(ch["id"].(float64))
	if ch["state"] != "pending" || ch["proposer"] != "alice" || ch["kind"] != "cloudtrust.publish" {
		t.Fatalf("change = %v", ch)
	}

	// The store was NOT written directly (still unpublished until the second approval).
	if _, none := req(t, ts, "GET", "/admin/v1/cloudtrust/active", "alice", nil); none["published"] != false {
		t.Fatalf("active after privileged PUT = %v, want still published:false (not direct-written)", none)
	}

	// alice cannot approve her own change.
	if code, _ := req(t, ts, "POST", fmt.Sprintf("/admin/v1/approvals/%d/approve", id), "alice", nil); code != http.StatusConflict {
		t.Fatalf("self-approve status = %d, want 409", code)
	}

	// bob (distinct) approves → committed → the committer writes the config store.
	code, out := req(t, ts, "POST", fmt.Sprintf("/admin/v1/approvals/%d/approve", id), "bob", nil)
	if code != http.StatusOK || out["state"] != "committed" {
		t.Fatalf("approve status=%d state=%v, want 200/committed", code, out["state"])
	}
	conform(t, doc, "POST", "/admin/v1/approvals/{id}/approve", 200, out)

	// It's now the active cloud-trust config (the committer landed it in the store).
	code, act := req(t, ts, "GET", "/admin/v1/cloudtrust/active", "alice", nil)
	if code != http.StatusOK || act["published"] != true {
		t.Fatalf("active = %v", act)
	}
	conform(t, doc, "GET", "/admin/v1/cloudtrust/active", 200, act)
}

// TestConfigSetRejectsInvalid: invalid DSL / invariant violation / S8 combo → 400 with
// the exact error, and nothing is written (the load-bearing inline-validation carry-over).
func TestConfigSetRejectsInvalid(t *testing.T) {
	ts := plainSrv(t, "admin")
	defer ts.Close()
	// Policy referencing the reserved control-plane group → invariant violation 400.
	if code, _ := req(t, ts, "PUT", "/admin/v1/config/policy", "alice",
		"allow web -> control-plane tcp 443\n"); code != http.StatusBadRequest {
		t.Fatalf("invariant-violating policy PUT = %d, want 400", code)
	}
	// Garbage DSL → 400.
	if code, _ := req(t, ts, "PUT", "/admin/v1/config/policy", "alice",
		"this is not valid dsl\n"); code != http.StatusBadRequest {
		t.Fatalf("garbage policy PUT = %d, want 400", code)
	}
	// usertrust auto_issue + reserved group → ErrAutoIssuePrivileged fires INLINE (400),
	// never reaching the privileged two-person route.
	if code, b := req(t, ts, "PUT", "/admin/v1/config/usertrust", "alice", map[string]any{
		"idp_entries": []map[string]any{
			{"realm": "corp", "directory_group": "admins", "mesh_groups": []string{"control-plane"}, "auto_issue": true},
		},
	}); code != http.StatusBadRequest {
		t.Fatalf("auto_issue+reserved usertrust PUT = %d, want 400 (%v)", code, b)
	}
}

// TestConfigSetRequiresManagePerm: a viewer (no :manage permission) is 403; reads work.
func TestConfigSetRequiresManagePerm(t *testing.T) {
	ts := plainSrv(t, "viewer")
	defer ts.Close()
	if code, _ := req(t, ts, "PUT", "/admin/v1/config/policy", "carol",
		"allow web -> db tcp 5432\n"); code != http.StatusForbidden {
		t.Fatalf("viewer config PUT status = %d, want 403", code)
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

// TestDenyVetoesOverHTTP: a deny moves a privileged-routed change to denied; approve
// then 409. The change is opened via a PRIVILEGED cloudtrust PUT (202).
func TestDenyVetoesOverHTTP(t *testing.T) {
	ts := plainSrv(t, "admin")
	defer ts.Close()
	_, ch := req(t, ts, "PUT", "/admin/v1/config/cloudtrust", "alice", map[string]any{
		"aws": []map[string]any{{"account": "111122223333", "groups": []string{"web"}, "auto_issue": true}},
	})
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
