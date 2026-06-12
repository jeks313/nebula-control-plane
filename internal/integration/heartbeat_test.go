package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/coreapi"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

// TestHeartbeatPersistsAndCommands is the M4.6 acceptance: a heartbeat persists
// the device's state and Core replies on the typed command channel; an unknown
// overlay IP is rejected.
func TestHeartbeatPersistsAndCommands(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()

	// Enroll a host so it has an identity at an overlay IP.
	secret, _, _ := joinkey.Create(ctx, e.store, joinkey.Params{Name: "k", Groups: []string{"web"}, MaxUses: 0, AutoIssue: true}, time.Now())
	res, err := e.cons.Process(ctx, e.candidate(t, secret, "host-hb"))
	if err != nil || res.Status != "issued" {
		t.Fatalf("enroll: %v %s", err, res.Status)
	}
	ip := res.OverlayIP

	// Core API with a near-expiry renew backstop (huge threshold -> always fires).
	api := coreapi.New(coreapi.Config{
		Store: e.store, Signer: e.sg, ConfigBackend: e.cfgB, ConfigKeyID: e.configKeyID,
		CABundlePEM: e.caPEM, Pool: e.pool, CertLifetime: 24 * time.Hour,
		Lighthouses:           []bundle.Lighthouse{{OverlayIP: "100.64.0.1", PublicAddrs: []string{"1.2.3.4:4242"}}},
		RenewCommandThreshold: 1000 * 24 * time.Hour,
	}).Handler()

	hb := wire.HeartbeatRequest{
		ProtocolVersion: wire.ProtocolVersion, Type: "heartbeat",
		CertNotAfter: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		PilotVersion: "1.2.3", NebulaVersion: "1.10.3", Health: "ok",
	}
	body, _ := json.Marshal(hb)
	r := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", strings.NewReader(string(body)))
	r.RemoteAddr = ip + ":40000"
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("heartbeat status = %d; %s", rec.Code, rec.Body)
	}

	// Typed command channel returns a renew (near-expiry backstop).
	var resp wire.HeartbeatResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Commands) != 1 || resp.Commands[0].Type != wire.CmdRenew {
		t.Fatalf("commands = %+v, want [renew]", resp.Commands)
	}

	// Persisted (fleet visibility).
	var stored coreapi.Heartbeat
	if err := e.store.DB.Where("overlay_ip = ?", ip).First(&stored).Error; err != nil {
		t.Fatalf("heartbeat not persisted: %v", err)
	}
	if stored.PilotVersion != "1.2.3" || stored.DeviceName != "host-hb" || stored.Health != "ok" {
		t.Fatalf("persisted heartbeat wrong: %+v", stored)
	}

	// An unknown overlay IP is rejected (tunnel-identity auth).
	r2 := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", strings.NewReader(string(body)))
	r2.RemoteAddr = "100.64.9.9:40000"
	rec2 := httptest.NewRecorder()
	api.ServeHTTP(rec2, r2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("unknown-IP heartbeat = %d, want 403", rec2.Code)
	}
}
