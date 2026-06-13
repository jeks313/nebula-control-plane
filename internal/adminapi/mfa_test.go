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

// mfaProvider is a test IdentityProvider with per-actor, test-controlled MFA time.
type mfaProvider struct{ mfa map[string]*time.Time }

func (p mfaProvider) Identify(r *http.Request) (adminapi.Identity, bool) {
	actor := r.Header.Get("X-Harbor-Dev-Actor")
	if actor == "" {
		return adminapi.Identity{}, false
	}
	return adminapi.Identity{Principal: actor, Roles: []string{adminapi.RoleAdmin}, MFAAt: p.mfa[actor]}, true
}

// TestStepUpMFA: with MFAFreshness enabled, the authority-GRANTING dual-control
// actions (policy propose, approve) require recent MFA, while deny (the safe veto)
// does not.
func TestStepUpMFA(t *testing.T) {
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(t.TempDir() + "/mfa.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	fresh := now
	mfa := map[string]*time.Time{"alice": &fresh} // alice stays freshly-MFA'd
	srv := adminapi.New(adminapi.Config{
		Store: s, Identity: mfaProvider{mfa},
		MFAFreshness: 15 * time.Minute,
		Now:          func() time.Time { return now },
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Propose is gated: alice (fresh MFA) succeeds.
	code, ch := req(t, ts, "POST", "/admin/v1/policy/propose", "alice",
		map[string]any{"policy": "allow web -> db tcp 5432\n"})
	if code != http.StatusCreated {
		t.Fatalf("propose (fresh MFA) = %d, want 201 (%v)", code, ch)
	}
	id := int64(ch["id"].(float64))
	approve := fmt.Sprintf("/admin/v1/approvals/%d/approve", id)

	// bob with NO MFA cannot approve — step-up required (distinguishable code).
	mfa["bob"] = nil
	code, body := req(t, ts, "POST", approve, "bob", nil)
	if code != http.StatusForbidden || body["code"] != "step_up_required" {
		t.Fatalf("approve (no MFA) = %d code=%v, want 403 step_up_required", code, body["code"])
	}

	// bob with STALE MFA (older than the window) is still blocked.
	stale := now.Add(-time.Hour)
	mfa["bob"] = &stale
	code, body = req(t, ts, "POST", approve, "bob", nil)
	if code != http.StatusForbidden || body["code"] != "step_up_required" {
		t.Fatalf("approve (stale MFA) = %d code=%v, want 403 step_up_required", code, body["code"])
	}

	// bob with a FUTURE-dated MFA (clock skew / bad timestamp) is blocked too — a
	// future instant must not pass the freshness gate (and must not be eternal).
	future := now.Add(time.Hour)
	mfa["bob"] = &future
	code, body = req(t, ts, "POST", approve, "bob", nil)
	if code != http.StatusForbidden || body["code"] != "step_up_required" {
		t.Fatalf("approve (future MFA) = %d code=%v, want 403 step_up_required", code, body["code"])
	}

	// bob with FRESH MFA approves → committed (the gate passes after step-up).
	freshBob := now.Add(-time.Minute)
	mfa["bob"] = &freshBob
	code, out := req(t, ts, "POST", approve, "bob", nil)
	if code != http.StatusOK || out["state"] != "committed" {
		t.Fatalf("approve (fresh MFA) = %d state=%v, want 200/committed", code, out["state"])
	}

	// Deny is NOT gated: a second change can be vetoed without any MFA (so a bad
	// change can always be stopped even when MFA is stale).
	_, ch2 := req(t, ts, "POST", "/admin/v1/policy/propose", "alice",
		map[string]any{"policy": "allow web -> db tcp 443\n"})
	id2 := int64(ch2["id"].(float64))
	mfa["carol"] = nil // no MFA at all
	code, _ = req(t, ts, "POST", fmt.Sprintf("/admin/v1/approvals/%d/deny", id2), "carol",
		map[string]any{"reason": "looks wrong"})
	if code != http.StatusOK {
		t.Fatalf("deny (no MFA) = %d, want 200 — deny must not be step-up gated", code)
	}
}

// TestStepUpDisabled: with MFAFreshness == 0, step-up is off and approvals work
// with no MFA at all (preserves dev / no-IdP behavior).
func TestStepUpDisabled(t *testing.T) {
	ts := plainSrv(t, "admin") // builds adminapi.New with MFAFreshness unset (0)
	defer ts.Close()
	code, ch := req(t, ts, "POST", "/admin/v1/policy/propose", "alice",
		map[string]any{"policy": "allow web -> db tcp 5432\n"})
	if code != http.StatusCreated {
		t.Fatalf("propose (step-up off) = %d, want 201", code)
	}
	id := int64(ch["id"].(float64))
	if code, out := req(t, ts, "POST", fmt.Sprintf("/admin/v1/approvals/%d/approve", id), "bob", nil); code != http.StatusOK || out["state"] != "committed" {
		t.Fatalf("approve (step-up off) = %d, want 200/committed", code)
	}
}
