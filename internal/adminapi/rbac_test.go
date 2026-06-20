package adminapi_test

import (
	"net/http"
	"testing"
)

// TestRBACOperator proves the role matrix as amended by ADR 0011 Phase 1: an operator
// may run day-2 fleet ops (lighthouse/rollout/joinkey/enroll) AND write declarative
// config directly (the :manage perms), but is still forbidden the privileged sign-off
// (dual-control approvals), which is admin-only.
func TestRBACOperator(t *testing.T) {
	ts := fullSrv(t, "operator")
	defer ts.Close()

	// Allowed: lighthouse management.
	if code, _ := req(t, ts, "POST", "/admin/v1/lighthouses", "otto",
		map[string]any{"overlay_ip": "10.44.0.1", "public_addrs": []string{"1.2.3.4:4242"}}); code != http.StatusCreated {
		t.Fatalf("operator lighthouse add = %d, want 201", code)
	}
	// Allowed: join-key management.
	if code, _ := req(t, ts, "POST", "/admin/v1/joinkeys", "otto",
		map[string]any{"name": "k1"}); code != http.StatusCreated {
		t.Fatalf("operator joinkey create = %d, want 201", code)
	}

	// Allowed (ADR 0011 Phase 1): the operator writes non-privileged config directly.
	if code, _ := req(t, ts, "PUT", "/admin/v1/config/policy", "otto",
		"allow web -> db tcp 5432\n"); code != http.StatusOK {
		t.Fatalf("operator config PUT = %d, want 200 (policy:manage)", code)
	}
	// Forbidden: approving a dual-control change is admin-only (403 before any
	// not-found lookup — the permission gate runs first). The operator can OPEN a
	// privileged change but cannot sign it off.
	if code, _ := req(t, ts, "POST", "/admin/v1/approvals/1/approve", "otto", nil); code != http.StatusForbidden {
		t.Fatalf("operator approval approve = %d, want 403", code)
	}
}

// TestRBACViewer: a viewer can read but performs no mutation.
func TestRBACViewer(t *testing.T) {
	ts := fullSrv(t, "viewer")
	defer ts.Close()

	if code, _ := req(t, ts, "GET", "/admin/v1/lighthouses", "vera", nil); code != http.StatusOK {
		t.Fatalf("viewer list lighthouses = %d, want 200", code)
	}
	if code, _ := req(t, ts, "POST", "/admin/v1/lighthouses", "vera",
		map[string]any{"overlay_ip": "10.44.0.9", "public_addrs": []string{"1.2.3.4:4242"}}); code != http.StatusForbidden {
		t.Fatalf("viewer lighthouse add = %d, want 403", code)
	}
	if code, _ := req(t, ts, "POST", "/admin/v1/joinkeys", "vera", map[string]any{"name": "x"}); code != http.StatusForbidden {
		t.Fatalf("viewer joinkey create = %d, want 403", code)
	}
}

// TestRBACAdminSuperuser: admin retains every permission (superuser).
func TestRBACAdminSuperuser(t *testing.T) {
	ts := fullSrv(t, "admin")
	defer ts.Close()
	if code, _ := req(t, ts, "POST", "/admin/v1/lighthouses", "ada",
		map[string]any{"overlay_ip": "10.44.0.1", "public_addrs": []string{"1.2.3.4:4242"}}); code != http.StatusCreated {
		t.Fatalf("admin lighthouse add = %d, want 201", code)
	}
	if code, _ := req(t, ts, "PUT", "/admin/v1/config/policy", "ada",
		"allow web -> db tcp 5432\n"); code != http.StatusOK {
		t.Fatalf("admin config PUT = %d, want 200", code)
	}
}
