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
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

func configReq(t *testing.T, h http.Handler, srcIP string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/v1/config", nil)
	r.RemoteAddr = srcIP + ":41000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// enrolledHost auto-issues a host and returns its overlay IP + issued cert PEM.
func enrolledHost(t *testing.T, e enrollEnv, name string) (ip, certPEM string) {
	t.Helper()
	ctx := context.Background()
	secret, _, _ := joinkey.Create(ctx, e.store, joinkey.Params{Name: name, Groups: []string{"web"}, MaxUses: 0, AutoIssue: true}, time.Now())
	res, err := e.cons.Process(ctx, e.candidate(t, secret, name))
	if err != nil || res.Status != "issued" {
		t.Fatalf("enroll %s: %v %s", name, err, res.Status)
	}
	return res.OverlayIP, string(res.CertPEM)
}

// TestConfigFetchNoReissueCarriesBlocklist is the M7.1b acceptance for GET
// /v1/config: a config-only refresh returns the host's CURRENT signed bundle
// (with the live blocklist) built from its EXISTING cert — no key rotation, no
// re-issue — so a blocklist change can be applied fast without loading the Signer.
func TestConfigFetchNoReissueCarriesBlocklist(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	api := e.coreAPI()

	ip, enrolledCert := enrolledHost(t, e, "host-cfg")

	// First fetch: same identity, SAME cert (config-only), empty blocklist.
	rec := configReq(t, api, ip)
	if rec.Code != http.StatusOK {
		t.Fatalf("config status = %d; %s", rec.Code, rec.Body)
	}
	var cr wire.ConfigResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &cr); err != nil {
		t.Fatal(err)
	}
	b, err := bundle.Verify(cr.Bundle, e.pinned)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if b.Device.OverlayIP != ip {
		t.Fatalf("config bundle for the wrong host: %+v", b.Device)
	}
	if b.Certificate != enrolledCert {
		t.Fatal("GET /v1/config must return the host's EXISTING cert (config-only, no re-issue)")
	}
	if len(b.Blocklist) != 0 {
		t.Fatalf("no revocations yet — blocklist should be empty, got %v", b.Blocklist)
	}

	// Blocklist a peer; the next config fetch carries it (the fast-path content),
	// still with no cert re-issue, and renders into pki.blocklist.
	fp := strings.Repeat("ab", 32)
	if _, err := e.rev.Add(ctx, fp, "compromised", "admin"); err != nil {
		t.Fatal(err)
	}
	rec = configReq(t, api, ip)
	if rec.Code != http.StatusOK {
		t.Fatalf("config status = %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cr); err != nil {
		t.Fatal(err)
	}
	b, err = bundle.Verify(cr.Bundle, e.pinned)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Blocklist) != 1 || b.Blocklist[0] != fp {
		t.Fatalf("config blocklist = %v, want [%s]", b.Blocklist, fp)
	}
	if b.Certificate != enrolledCert {
		t.Fatal("a config refresh must never re-issue the cert")
	}
	cfg, err := bundle.RenderNebulaConfig(b, "/ca.crt", "/host.crt", "/host.key")
	if err != nil {
		t.Fatal(err)
	}
	if s := string(cfg); !strings.Contains(s, "blocklist:") || !strings.Contains(s, fp) {
		t.Fatalf("rendered config missing pki.blocklist %s:\n%s", fp, s)
	}
}

// TestHeartbeatDrivesBlocklistConvergence is the M7.1b acceptance for the fast
// push: when a blocklist-lane rollout is in flight, a host that has not yet
// applied the new blocklist version is told (over the heartbeat channel) to
// apply_bundle — independent of any policy rollout, and at heartbeat cadence.
func TestHeartbeatDrivesBlocklistConvergence(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	api := e.coreAPI()

	ip, _ := enrolledHost(t, e, "host-bl")

	// Blocklist a peer + stage a blocklist-lane rollout that includes our host.
	fp := strings.Repeat("cd", 32)
	if _, err := e.rev.Add(ctx, fp, "compromised", "admin"); err != nil {
		t.Fatal(err)
	}
	eng := rollout.New(e.store.DB, nil)
	if _, err := eng.Start(ctx, rollout.StartConfig{
		Lane: rollout.LaneBlocklist, TargetVersion: 1, PrevVersion: 0, Hosts: []string{ip},
		CanarySize: 1, Observe: 10 * time.Minute, MissingAfter: 3 * time.Minute, Actor: "admin",
	}); err != nil {
		t.Fatalf("start blocklist rollout: %v", err)
	}

	// The host heartbeats still on blocklist v0 -> Core commands apply_bundle.
	resp := heartbeatReq(t, api, ip, wire.HeartbeatRequest{
		ProtocolVersion: wire.ProtocolVersion, Type: "heartbeat", Health: "ok",
		AppliedBundleVersion: 1, AppliedBlocklistVersion: 0,
	})
	if !hasCmd(resp.Commands, wire.CmdApplyBundle) {
		t.Fatalf("commands = %+v, want an apply_bundle (host is behind on the blocklist lane)", resp.Commands)
	}

	// After it reports the new blocklist version, no more apply_bundle.
	resp = heartbeatReq(t, api, ip, wire.HeartbeatRequest{
		ProtocolVersion: wire.ProtocolVersion, Type: "heartbeat", Health: "ok",
		AppliedBundleVersion: 1, AppliedBlocklistVersion: 1,
	})
	if hasCmd(resp.Commands, wire.CmdApplyBundle) {
		t.Fatalf("host converged on blocklist v1 must get no apply_bundle, got %+v", resp.Commands)
	}
}

func heartbeatReq(t *testing.T, h http.Handler, srcIP string, req wire.HeartbeatRequest) wire.HeartbeatResponse {
	t.Helper()
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", strings.NewReader(string(body)))
	r.RemoteAddr = srcIP + ":42000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("heartbeat status = %d; %s", rec.Code, rec.Body)
	}
	var resp wire.HeartbeatResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func hasCmd(cmds []wire.Command, typ string) bool {
	for _, c := range cmds {
		if c.Type == typ {
			return true
		}
	}
	return false
}
