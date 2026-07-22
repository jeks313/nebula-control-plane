package adminapi_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/ca"
	"github.com/jeks313/nebula-control-plane/internal/signer"
)

// mkCAPEM self-signs a P256 CA and returns its PEM (for seeding the CA-rotation registry).
func mkCAPEM(t *testing.T, name string) string {
	t.Helper()
	b, _ := signer.NewSoftwareBackend()
	now := time.Now()
	_, pem, err := signer.SelfSignCA(b, signer.CATemplate{
		Name: name, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(5 * 365 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("self-sign %s: %v", name, err)
	}
	return string(pem)
}

// TestCADashboardEndpoint: GET /admin/v1/ca returns the rotation lifecycle with the derived signals
// (active flagged, non-retired trusted, a state rollup), and GET /admin/v1/ca/{id}/adoption reports
// the activate-gate progress (vacuously fully adopted on an empty fleet) with 400/404 on bad ids.
func TestCADashboardEndpoint(t *testing.T) {
	s, h := newServer(t)
	ctx := context.Background()
	reg := ca.New(s.DB, nil)
	if _, _, err := reg.SeedActive(ctx, "ca-1", mkCAPEM(t, "ca-1"), "kms:ca1", "boot"); err != nil {
		t.Fatal(err)
	}
	ca2, err := reg.Stage(ctx, "ca-2", mkCAPEM(t, "ca-2"), "kms:ca2", "op")
	if err != nil {
		t.Fatal(err)
	}

	rr, body := do(t, h, "GET", "/admin/v1/ca", "alice")
	if rr.Code != 200 {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	cas, _ := body["cas"].([]any)
	if len(cas) != 2 {
		t.Fatalf("cas len=%d, want 2", len(cas))
	}
	byName := map[string]map[string]any{}
	for _, c := range cas {
		m := c.(map[string]any)
		byName[m["name"].(string)] = m
	}
	if byName["ca-1"]["is_active"] != true || byName["ca-1"]["trusted"] != true || byName["ca-1"]["state"] != "active" {
		t.Fatalf("ca-1 = %v, want active + trusted", byName["ca-1"])
	}
	if byName["ca-2"]["state"] != "staged" || byName["ca-2"]["is_active"] != false || byName["ca-2"]["trusted"] != true {
		t.Fatalf("ca-2 = %v, want staged (trusted, not active)", byName["ca-2"])
	}
	summary := body["summary"].(map[string]any)
	if int(summary["total"].(float64)) != 2 || int(summary["active"].(float64)) != 1 || int(summary["staged"].(float64)) != 1 {
		t.Fatalf("summary=%v", summary)
	}

	// Adoption for the staged CA: no live hosts -> vacuously fully adopted, 0 live.
	rr2, body2 := do(t, h, "GET", "/admin/v1/ca/"+strconv.FormatInt(ca2.ID, 10)+"/adoption", "alice")
	if rr2.Code != 200 {
		t.Fatalf("adoption status=%d body=%s", rr2.Code, rr2.Body.String())
	}
	if body2["fully_adopted"] != true {
		t.Fatalf("adoption fully_adopted=%v, want true (empty fleet)", body2["fully_adopted"])
	}
	if int(body2["live"].(float64)) != 0 {
		t.Fatalf("adoption live=%v, want 0", body2["live"])
	}

	// A non-numeric id -> 400; an unknown id -> 404.
	if bad, _ := do(t, h, "GET", "/admin/v1/ca/abc/adoption", "alice"); bad.Code != 400 {
		t.Fatalf("bad id status=%d, want 400", bad.Code)
	}
	if missing, _ := do(t, h, "GET", "/admin/v1/ca/9999/adoption", "alice"); missing.Code != 404 {
		t.Fatalf("unknown id status=%d, want 404", missing.Code)
	}
}
