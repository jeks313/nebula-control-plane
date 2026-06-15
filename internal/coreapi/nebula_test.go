package coreapi

import (
	"context"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/nebularelease"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

const (
	tSHA1 = "1111111111111111111111111111111111111111111111111111111111111111"
	tSHA2 = "2222222222222222222222222222222222222222222222222222222222222222"
)

func testDB(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(t.TempDir() + "/c.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestNebulaReleasePerHostStaging is the ADR 0003 Phase 1c stamping acceptance: with
// a nebula rollout in flight, Core stamps the IN-WAVE host the new generation's tuple
// and everyone else the previous generation's — the per-host content gating that makes
// the canary real. With no rollout, it falls back to the static config (1a/1b).
func TestNebulaReleasePerHostStaging(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()
	reg := nebularelease.New(s.DB)
	g1, _ := reg.Add(ctx, "1.0.0", tSHA1, "https://art/1.0.0", "")
	g2, _ := reg.Add(ctx, "2.0.0", tSHA2, "https://art/2.0.0", "")

	eng := rollout.New(s.DB, nil)
	const canary, other = "100.64.0.1", "100.64.0.2"
	if _, err := eng.Start(ctx, rollout.StartConfig{
		Lane: rollout.LaneNebula, TargetVersion: int(g2.Gen), PrevVersion: int(g1.Gen),
		Hosts: []string{canary, other}, CanarySize: 1, Observe: time.Minute, MissingAfter: time.Minute,
	}); err != nil {
		t.Fatalf("start nebula rollout: %v", err)
	}

	srv := New(Config{
		Rollout: eng, NebulaReleases: reg,
		NebulaVersion: "static", NebulaSHA256: "staticsha", NebulaURL: "static-url",
	})

	// In-wave canary -> the NEW generation's tuple.
	if v, sh, u := srv.nebulaRelease(ctx, canary); v != "2.0.0" || sh != tSHA2 || u != "https://art/2.0.0" {
		t.Fatalf("canary tuple = (%s,%s,%s), want gen2", v, sh, u)
	}
	// Out-of-wave host -> the PREV generation's tuple (stays on the old version).
	if v, sh, u := srv.nebulaRelease(ctx, other); v != "1.0.0" || sh != tSHA1 || u != "https://art/1.0.0" {
		t.Fatalf("out-of-wave tuple = (%s,%s,%s), want gen1", v, sh, u)
	}
	// A host that is NOT a rollout member (e.g. enrolled after Start) holds on prev too
	// — the ErrRecordNotFound branch, distinct from a transient DB error.
	if v, _, _ := srv.nebulaRelease(ctx, "100.64.0.99"); v != "1.0.0" {
		t.Fatalf("non-member host tuple = %q, want gen1 (prev) during an active rollout", v)
	}
}

// TestNebulaReleaseFallbackAndUnpinned covers the two edge tuples: no nebula rollout
// at all -> the static config (back-compat), and the prev of a FIRST rollout (gen 0)
// -> unpinned (empty), so Core leaves an out-of-wave host's nebula alone.
func TestNebulaReleaseFallbackAndUnpinned(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()
	reg := nebularelease.New(s.DB)
	eng := rollout.New(s.DB, nil)

	srv := New(Config{
		Rollout: eng, NebulaReleases: reg,
		NebulaVersion: "static", NebulaSHA256: "staticsha", NebulaURL: "static-url",
	})

	// No nebula rollout governs -> static config fallback.
	if v, sh, u := srv.nebulaRelease(ctx, "100.64.0.9"); v != "static" || sh != "staticsha" || u != "static-url" {
		t.Fatalf("ungoverned tuple = (%s,%s,%s), want static fallback", v, sh, u)
	}

	// A FIRST rollout (prev gen 0): an out-of-wave host maps to gen 0 -> unpinned.
	g1, _ := reg.Add(ctx, "1.0.0", tSHA1, "https://art/1.0.0", "")
	if _, err := eng.Start(ctx, rollout.StartConfig{
		Lane: rollout.LaneNebula, TargetVersion: int(g1.Gen), PrevVersion: 0,
		Hosts: []string{"100.64.0.1", "100.64.0.2"}, CanarySize: 1, Observe: time.Minute, MissingAfter: time.Minute,
	}); err != nil {
		t.Fatalf("start: %v", err)
	}
	if v, sh, u := srv.nebulaRelease(ctx, "100.64.0.2"); v != "" || sh != "" || u != "" {
		t.Fatalf("out-of-wave of a first rollout = (%s,%s,%s), want unpinned (empty)", v, sh, u)
	}
}
