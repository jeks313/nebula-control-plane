package adminapi_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/adminapi"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

// TestUserTrustDualControlOverHTTP is the ADR-0004 admin-API showcase, mirroring the
// cloud-trust flow: propose an SSO user-trust config → self-approve blocked → a second
// distinct approver commits → GET /usertrust/active returns it (so SSO can reach issuance,
// closing B2). Both the propose 201 and the active 200 bodies are conformance-checked
// against the OpenAPI schema (the anti-drift guard for the new schemas).
func TestUserTrustDualControlOverHTTP(t *testing.T) {
	ts := plainSrv(t, "admin")
	defer ts.Close()
	doc := loadSpec(t)

	// Active is {published:false} before anything is published.
	code, none := req(t, ts, "GET", "/admin/v1/usertrust/active", "alice", nil)
	if code != http.StatusOK || none["published"] != false {
		t.Fatalf("active (pre-publish) = %d %v, want 200 published:false", code, none)
	}
	conform(t, doc, "GET", "/admin/v1/usertrust/active", 200, none)

	// Propose as alice.
	code, ch := req(t, ts, "POST", "/admin/v1/usertrust/propose", "alice", map[string]any{
		"default_groups": []string{"fleet"},
		"idp_entries": []map[string]any{
			{"realm": "corp", "directory_group": "corp-eng", "mesh_groups": []string{"eng"}, "auto_issue": false},
		},
	})
	if code != http.StatusCreated {
		t.Fatalf("propose status = %d, want 201 (%v)", code, ch)
	}
	conform(t, doc, "POST", "/admin/v1/usertrust/propose", 201, ch)
	id := int64(ch["id"].(float64))
	if ch["state"] != "pending" || ch["proposer"] != "alice" || ch["kind"] != "usertrust.publish" {
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

	// It's now the active user-trust config (the seam SSO issuance reads).
	code, act := req(t, ts, "GET", "/admin/v1/usertrust/active", "alice", nil)
	if code != http.StatusOK || act["published"] != true {
		t.Fatalf("active = %v", act)
	}
	conform(t, doc, "GET", "/admin/v1/usertrust/active", 200, act)
	entries, _ := act["idp_entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("active idp_entries = %v, want 1", act["idp_entries"])
	}
}

// TestUserTrustProposeRejectsDuplicateGroup: a config with a duplicate (realm,
// directory_group) — the S3 AD-group uniqueness violation the committer's Validate
// enforces — is rejected at propose with a 400, and no change is opened.
func TestUserTrustProposeRejectsDuplicateGroup(t *testing.T) {
	ts := plainSrv(t, "admin")
	defer ts.Close()

	code, _ := req(t, ts, "POST", "/admin/v1/usertrust/propose", "alice", map[string]any{
		"default_groups": []string{"fleet"},
		"idp_entries": []map[string]any{
			{"realm": "corp", "directory_group": "corp-eng", "mesh_groups": []string{"eng"}},
			{"realm": "corp", "directory_group": "corp-eng", "mesh_groups": []string{"ops"}},
		},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("duplicate-group propose status = %d, want 400", code)
	}

	// An entry that grants nothing (no mesh_groups + no default_groups) is also rejected.
	code, _ = req(t, ts, "POST", "/admin/v1/usertrust/propose", "alice", map[string]any{
		"idp_entries": []map[string]any{
			{"realm": "corp", "directory_group": "corp-eng"},
		},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("grants-nothing propose status = %d, want 400", code)
	}

	// Empty config (no entries) is rejected too.
	code, _ = req(t, ts, "POST", "/admin/v1/usertrust/propose", "alice", map[string]any{})
	if code != http.StatusBadRequest {
		t.Fatalf("empty propose status = %d, want 400", code)
	}
}

// TestUserTrustProposeRequiresPerm: a viewer (no usertrust:propose permission) is 403;
// reads (active) still work. Mirrors the cloud-trust / policy RBAC gate.
func TestUserTrustProposeRequiresPerm(t *testing.T) {
	ts := plainSrv(t, "viewer")
	defer ts.Close()
	if code, _ := req(t, ts, "POST", "/admin/v1/usertrust/propose", "carol", map[string]any{
		"idp_entries": []map[string]any{
			{"realm": "corp", "directory_group": "corp-eng", "mesh_groups": []string{"eng"}},
		},
	}); code != http.StatusForbidden {
		t.Fatalf("viewer propose status = %d, want 403", code)
	}
	// An operator also lacks usertrust:propose (admin-only, like cloudtrust/policy).
	op := plainSrv(t, "operator")
	defer op.Close()
	if code, _ := req(t, op, "POST", "/admin/v1/usertrust/propose", "dave", map[string]any{
		"idp_entries": []map[string]any{
			{"realm": "corp", "directory_group": "corp-eng", "mesh_groups": []string{"eng"}},
		},
	}); code != http.StatusForbidden {
		t.Fatalf("operator propose status = %d, want 403 (usertrust:propose is admin-only)", code)
	}
	// Reads still work for a viewer.
	if code, _ := req(t, ts, "GET", "/admin/v1/usertrust/active", "carol", nil); code != http.StatusOK {
		t.Fatalf("viewer active status = %d, want 200", code)
	}
}

// TestUserTrustProposeStepUp: with MFAFreshness enabled, propose (authority-granting)
// requires recent MFA — no/stale MFA → 403 step_up_required; fresh MFA → 201.
func TestUserTrustProposeStepUp(t *testing.T) {
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(t.TempDir() + "/ut-mfa.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	mfa := map[string]*time.Time{}
	srv := adminapi.New(adminapi.Config{
		Store: s, Identity: mfaProvider{mfa},
		MFAFreshness: 15 * time.Minute,
		Now:          func() time.Time { return now },
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	body := map[string]any{
		"idp_entries": []map[string]any{
			{"realm": "corp", "directory_group": "corp-eng", "mesh_groups": []string{"eng"}},
		},
	}

	// No MFA → step-up required.
	mfa["alice"] = nil
	code, b := req(t, ts, "POST", "/admin/v1/usertrust/propose", "alice", body)
	if code != http.StatusForbidden || b["code"] != "step_up_required" {
		t.Fatalf("propose (no MFA) = %d code=%v, want 403 step_up_required", code, b["code"])
	}

	// Fresh MFA → 201.
	fresh := now.Add(-time.Minute)
	mfa["alice"] = &fresh
	code, ch := req(t, ts, "POST", "/admin/v1/usertrust/propose", "alice", body)
	if code != http.StatusCreated {
		t.Fatalf("propose (fresh MFA) = %d, want 201 (%v)", code, ch)
	}
}
