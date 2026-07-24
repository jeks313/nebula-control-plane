package adminapi_test

import (
	"context"
	"strconv"
	"testing"

	"github.com/slackhq/nebula/cert"

	"github.com/jeks313/nebula-control-plane/internal/configkey"
	"github.com/jeks313/nebula-control-plane/internal/signer"
)

// mkConfigPubPEM mints a fresh P256 software config-signing key and returns its public-key PEM (for
// seeding the config-key-rotation registry).
func mkConfigPubPEM(t *testing.T) string {
	t.Helper()
	b, err := signer.NewSoftwareBackend()
	if err != nil {
		t.Fatalf("software backend: %v", err)
	}
	pub, err := b.PublicKey()
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	return string(cert.MarshalSigningPublicKeyToPEM(cert.Curve_P256, pub))
}

// TestConfigKeyDashboardEndpoint: GET /admin/v1/config-key returns the rotation lifecycle with the
// derived signals (active flagged, non-retired trusted, backend-present, a state rollup), and GET
// /admin/v1/config-key/{id}/adoption reports the activate/drain-gate progress (vacuously fully
// adopted on an empty fleet) with 400/404 on bad ids.
func TestConfigKeyDashboardEndpoint(t *testing.T) {
	s, h := newServer(t)
	ctx := context.Background()
	reg := configkey.New(s.DB, nil)
	if _, _, err := reg.SeedActive(ctx, "config-1", mkConfigPubPEM(t), "kms:ck1", "boot"); err != nil {
		t.Fatal(err)
	}
	ck2, err := reg.Stage(ctx, "config-2", mkConfigPubPEM(t), "", "op") // trust-only (no backend)
	if err != nil {
		t.Fatal(err)
	}

	rr, body := do(t, h, "GET", "/admin/v1/config-key", "alice")
	if rr.Code != 200 {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	keys, _ := body["config_keys"].([]any)
	if len(keys) != 2 {
		t.Fatalf("config_keys len=%d, want 2", len(keys))
	}
	byName := map[string]map[string]any{}
	for _, c := range keys {
		m := c.(map[string]any)
		byName[m["name"].(string)] = m
	}
	if byName["config-1"]["is_active"] != true || byName["config-1"]["trusted"] != true ||
		byName["config-1"]["state"] != "active" || byName["config-1"]["has_backend"] != true {
		t.Fatalf("config-1 = %v, want active + trusted + backend", byName["config-1"])
	}
	if byName["config-2"]["state"] != "staged" || byName["config-2"]["is_active"] != false ||
		byName["config-2"]["trusted"] != true || byName["config-2"]["has_backend"] != false {
		t.Fatalf("config-2 = %v, want staged (trusted, not active, trust-only)", byName["config-2"])
	}
	summary := body["summary"].(map[string]any)
	if int(summary["total"].(float64)) != 2 || int(summary["active"].(float64)) != 1 || int(summary["staged"].(float64)) != 1 {
		t.Fatalf("summary=%v", summary)
	}

	// Adoption for the staged key: no live hosts -> vacuously fully adopted, 0 live.
	rr2, body2 := do(t, h, "GET", "/admin/v1/config-key/"+strconv.FormatInt(ck2.ID, 10)+"/adoption", "alice")
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
	if bad, _ := do(t, h, "GET", "/admin/v1/config-key/abc/adoption", "alice"); bad.Code != 400 {
		t.Fatalf("bad id status=%d, want 400", bad.Code)
	}
	if missing, _ := do(t, h, "GET", "/admin/v1/config-key/9999/adoption", "alice"); missing.Code != 404 {
		t.Fatalf("unknown id status=%d, want 404", missing.Code)
	}
}
