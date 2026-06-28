package adminapi_test

import (
	"context"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/gatewayhealth"
	"gorm.io/gorm"
)

func seedGateway(t *testing.T, db *gorm.DB, name string) {
	t.Helper()
	if err := db.Exec("INSERT INTO gateways (name,url,cert_pem,state,created_at,updated_at) VALUES (?,?,?,?,?,?)",
		name, "https://"+name+":9443", "dummy", "active", 0, 0).Error; err != nil {
		t.Fatal(err)
	}
}

// TestGatewaysEndpoint: the four health states (healthy/degraded/down/unknown) are computed
// from the registry ∪ gateway_health, with the down case being the wedge that was invisible.
func TestGatewaysEndpoint(t *testing.T) {
	s, h := newServer(t)
	now := time.Unix(1_700_000_000, 0) // matches newServer's clock
	gh := gatewayhealth.New(s.DB)
	ctx := context.Background()

	seedGateway(t, s.DB, "gw-up")
	seedGateway(t, s.DB, "gw-degraded")
	seedGateway(t, s.DB, "gw-down")
	seedGateway(t, s.DB, "gw-unknown") // registered, no health row -> unknown

	if err := gh.Record(ctx, "gw-up", true, "", 0, now); err != nil {
		t.Fatal(err)
	}
	// recent success + a current failure -> degraded
	_ = gh.Record(ctx, "gw-degraded", true, "", 0, now.Add(-10*time.Second))
	_ = gh.Record(ctx, "gw-degraded", false, "blip", 1, now)
	// last success well past gatewayDownAfter (60s) -> down
	_ = gh.Record(ctx, "gw-down", true, "", 0, now.Add(-120*time.Second))

	rr, body := do(t, h, "GET", "/admin/v1/gateways", "alice")
	if rr.Code != 200 {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	gws, _ := body["gateways"].([]any)
	got := map[string]string{}
	for _, g := range gws {
		m := g.(map[string]any)
		got[m["name"].(string)] = m["status"].(string)
	}
	want := map[string]string{"gw-up": "healthy", "gw-degraded": "degraded", "gw-down": "down", "gw-unknown": "unknown"}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("gateway %s status=%q, want %q (all=%v)", k, got[k], v, got)
		}
	}
	summary := body["summary"].(map[string]any)
	if int(summary["total"].(float64)) != 4 || int(summary["down"].(float64)) != 1 ||
		int(summary["healthy"].(float64)) != 1 || int(summary["degraded"].(float64)) != 1 || int(summary["unknown"].(float64)) != 1 {
		t.Fatalf("summary=%v", summary)
	}
}
