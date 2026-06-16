package coreapi

import (
	"context"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/pilotrelease"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
)

// TestPilotReleasePerHostStaging is the ADR 0003 Phase 3c stamping acceptance (the
// mirror of TestNebulaReleasePerHostStaging): with a pilot rollout in flight, Core
// stamps the in-wave host the new generation's tuple and everyone else the previous —
// the per-host gating that makes the pilot canary real. No rollout -> static config.
func TestPilotReleasePerHostStaging(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()
	reg := pilotrelease.New(s.DB)
	g1, _ := reg.Add(ctx, "1.3.0", "", "", tSHA1, "https://art/pilot/1.3.0", "")
	g2, _ := reg.Add(ctx, "1.4.0", "", "", tSHA2, "https://art/pilot/1.4.0", "")

	eng := rollout.New(s.DB, nil)
	const canary, other = "100.64.0.1", "100.64.0.2"
	if _, err := eng.Start(ctx, rollout.StartConfig{
		Lane: rollout.LanePilot, TargetVersion: int(g2.Gen), PrevVersion: int(g1.Gen),
		Hosts: []string{canary, other}, CanarySize: 1, Observe: time.Minute, MissingAfter: time.Minute,
	}); err != nil {
		t.Fatalf("start pilot rollout: %v", err)
	}

	srv := New(Config{
		Rollout: eng, PilotReleases: reg,
		PilotVersion: "static", PilotSHA256: "staticsha", PilotURL: "static-url",
	})

	if v, sh, u := srv.pilotRelease(ctx, canary, "", ""); v != "1.4.0" || sh != tSHA2 || u != "https://art/pilot/1.4.0" {
		t.Fatalf("canary tuple = (%s,%s,%s), want gen2", v, sh, u)
	}
	if v, sh, u := srv.pilotRelease(ctx, other, "", ""); v != "1.3.0" || sh != tSHA1 || u != "https://art/pilot/1.3.0" {
		t.Fatalf("out-of-wave tuple = (%s,%s,%s), want gen1", v, sh, u)
	}

	// No pilot rollout governs (fresh DB) -> static fallback.
	s2 := testDB(t)
	bare := New(Config{Rollout: rollout.New(s2.DB, nil), PilotReleases: pilotrelease.New(s2.DB),
		PilotVersion: "static", PilotSHA256: "staticsha", PilotURL: "static-url"})
	if v, _, _ := bare.pilotRelease(ctx, "100.64.0.9", "", ""); v != "static" {
		t.Fatalf("ungoverned pilot tuple = %q, want static fallback", v)
	}
}
