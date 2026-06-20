package adminapi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/adminapi"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

// TestUserTrustConfigSetOverHTTP is the ADR-0004 + ADR-0011 Phase-1 admin-API
// showcase: a non-privileged SSO user-trust config (auto_issue:false, non-reserved
// mesh groups) is set by a single operator via PUT → 200 (no dual-control) → GET
// /usertrust/active returns it (so SSO can reach issuance, closing B2). Both the PUT
// 200 and the active 200 bodies are conformance-checked against the OpenAPI schema.
func TestUserTrustConfigSetOverHTTP(t *testing.T) {
	ts := plainSrv(t, "admin")
	defer ts.Close()
	doc := loadSpec(t)

	// Active is {published:false} before anything is set.
	code, none := req(t, ts, "GET", "/admin/v1/usertrust/active", "alice", nil)
	if code != http.StatusOK || none["published"] != false {
		t.Fatalf("active (pre-publish) = %d %v, want 200 published:false", code, none)
	}
	conform(t, doc, "GET", "/admin/v1/usertrust/active", 200, none)

	// Single-operator PUT of a non-privileged config → 200 (written straight to store).
	code, row := req(t, ts, "PUT", "/admin/v1/config/usertrust", "alice", map[string]any{
		"default_groups": []string{"fleet"},
		"idp_entries": []map[string]any{
			{"realm": "corp", "directory_group": "corp-eng", "mesh_groups": []string{"eng"}, "auto_issue": false},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200 (%v)", code, row)
	}
	conform(t, doc, "PUT", "/admin/v1/config/{kind}", 200, row)
	if row["set"] != true {
		t.Fatalf("row = %v, want set:true", row)
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

// TestUserTrustConfigSetRejectsDuplicateGroup: a config with a duplicate (realm,
// directory_group) — the S3 AD-group uniqueness violation Validate enforces — is
// rejected INLINE at the PUT with a 400, and nothing is written.
func TestUserTrustConfigSetRejectsDuplicateGroup(t *testing.T) {
	ts := plainSrv(t, "admin")
	defer ts.Close()

	code, _ := req(t, ts, "PUT", "/admin/v1/config/usertrust", "alice", map[string]any{
		"default_groups": []string{"fleet"},
		"idp_entries": []map[string]any{
			{"realm": "corp", "directory_group": "corp-eng", "mesh_groups": []string{"eng"}},
			{"realm": "corp", "directory_group": "corp-eng", "mesh_groups": []string{"ops"}},
		},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("duplicate-group PUT status = %d, want 400", code)
	}

	// An entry that grants nothing (no mesh_groups + no default_groups) is also rejected.
	code, _ = req(t, ts, "PUT", "/admin/v1/config/usertrust", "alice", map[string]any{
		"idp_entries": []map[string]any{
			{"realm": "corp", "directory_group": "corp-eng"},
		},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("grants-nothing PUT status = %d, want 400", code)
	}

	// Empty config (no entries) is rejected too.
	code, _ = req(t, ts, "PUT", "/admin/v1/config/usertrust", "alice", map[string]any{})
	if code != http.StatusBadRequest {
		t.Fatalf("empty PUT status = %d, want 400", code)
	}
}

// TestUserTrustConfigSetRequiresPerm: a viewer (no usertrust:manage permission) is 403;
// an operator (which ADR 0011 Phase 1 GRANTS usertrust:manage) succeeds; reads work.
func TestUserTrustConfigSetRequiresPerm(t *testing.T) {
	ts := plainSrv(t, "viewer")
	defer ts.Close()
	if code, _ := req(t, ts, "PUT", "/admin/v1/config/usertrust", "carol", map[string]any{
		"idp_entries": []map[string]any{
			{"realm": "corp", "directory_group": "corp-eng", "mesh_groups": []string{"eng"}},
		},
	}); code != http.StatusForbidden {
		t.Fatalf("viewer PUT status = %d, want 403", code)
	}
	// An operator HOLDS usertrust:manage (ADR 0011 Phase 1) — a non-privileged write succeeds.
	op := plainSrv(t, "operator")
	defer op.Close()
	if code, _ := req(t, op, "PUT", "/admin/v1/config/usertrust", "dave", map[string]any{
		"idp_entries": []map[string]any{
			{"realm": "corp", "directory_group": "corp-eng", "mesh_groups": []string{"eng"}},
		},
	}); code != http.StatusOK {
		t.Fatalf("operator PUT status = %d, want 200 (usertrust:manage)", code)
	}
	// Reads still work for a viewer.
	if code, _ := req(t, ts, "GET", "/admin/v1/usertrust/active", "carol", nil); code != http.StatusOK {
		t.Fatalf("viewer active status = %d, want 200", code)
	}
}

// TestUserTrustConfigSetStepUp: with MFAFreshness enabled, the config PUT requires
// recent MFA — no/stale MFA → 403 step_up_required; fresh MFA → 200.
func TestUserTrustConfigSetStepUp(t *testing.T) {
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
	code, b := req(t, ts, "PUT", "/admin/v1/config/usertrust", "alice", body)
	if code != http.StatusForbidden || b["code"] != "step_up_required" {
		t.Fatalf("PUT (no MFA) = %d code=%v, want 403 step_up_required", code, b["code"])
	}

	// Fresh MFA → 200.
	fresh := now.Add(-time.Minute)
	mfa["alice"] = &fresh
	code, ch := req(t, ts, "PUT", "/admin/v1/config/usertrust", "alice", body)
	if code != http.StatusOK {
		t.Fatalf("PUT (fresh MFA) = %d, want 200 (%v)", code, ch)
	}
}
