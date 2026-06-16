package coreapi

import (
	"context"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/nebularelease"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

const (
	tSHA1 = "1111111111111111111111111111111111111111111111111111111111111111"
	tSHA2 = "2222222222222222222222222222222222222222222222222222222222222222"
	tSHA3 = "3333333333333333333333333333333333333333333333333333333333333333"
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
	g1, _ := reg.Add(ctx, "1.0.0", "", "", tSHA1, "https://art/1.0.0", "")
	g2, _ := reg.Add(ctx, "2.0.0", "", "", tSHA2, "https://art/2.0.0", "")

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
	if v, sh, u := srv.nebulaRelease(ctx, canary, "", ""); v != "2.0.0" || sh != tSHA2 || u != "https://art/2.0.0" {
		t.Fatalf("canary tuple = (%s,%s,%s), want gen2", v, sh, u)
	}
	// Out-of-wave host -> the PREV generation's tuple (stays on the old version).
	if v, sh, u := srv.nebulaRelease(ctx, other, "", ""); v != "1.0.0" || sh != tSHA1 || u != "https://art/1.0.0" {
		t.Fatalf("out-of-wave tuple = (%s,%s,%s), want gen1", v, sh, u)
	}
	// A host that is NOT a rollout member (e.g. enrolled after Start) holds on prev too
	// — the ErrRecordNotFound branch, distinct from a transient DB error.
	if v, _, _ := srv.nebulaRelease(ctx, "100.64.0.99", "", ""); v != "1.0.0" {
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
	if v, sh, u := srv.nebulaRelease(ctx, "100.64.0.9", "", ""); v != "static" || sh != "staticsha" || u != "static-url" {
		t.Fatalf("ungoverned tuple = (%s,%s,%s), want static fallback", v, sh, u)
	}

	// A FIRST rollout (prev gen 0): an out-of-wave host maps to gen 0 -> unpinned.
	g1, _ := reg.Add(ctx, "1.0.0", "", "", tSHA1, "https://art/1.0.0", "")
	if _, err := eng.Start(ctx, rollout.StartConfig{
		Lane: rollout.LaneNebula, TargetVersion: int(g1.Gen), PrevVersion: 0,
		Hosts: []string{"100.64.0.1", "100.64.0.2"}, CanarySize: 1, Observe: time.Minute, MissingAfter: time.Minute,
	}); err != nil {
		t.Fatalf("start: %v", err)
	}
	if v, sh, u := srv.nebulaRelease(ctx, "100.64.0.2", "", ""); v != "" || sh != "" || u != "" {
		t.Fatalf("out-of-wave of a first rollout = (%s,%s,%s), want unpinned (empty)", v, sh, u)
	}
}

// TestNebulaReleasePerArchStaging is the ADR 0003 per-arch URL acceptance: with a
// nebula rollout governing a generation that has a DEFAULT linux/amd64 artifact plus
// a darwin/arm64 child artifact, Core stamps each in-wave host its OWN arch's
// (sha256, url) — same version, different binary — while a host whose arch the
// generation has NO artifact for is left ALONE (empty tuple), not served a wrong-arch
// binary or the static fallback. Both nebulaRelease and assembleBundle are checked.
func TestNebulaReleasePerArchStaging(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()
	reg := nebularelease.New(s.DB)

	// gen 1's default artifact is linux/amd64 (the parent Release); darwin/arm64 is an
	// additional per-arch child for the same generation + version.
	g1, err := reg.Add(ctx, "1.0.0", "linux", "amd64", tSHA1, "https://art/1.0.0/linux-amd64", "")
	if err != nil {
		t.Fatalf("add default release: %v", err)
	}
	if _, err := reg.AddArtifact(ctx, int(g1.Gen), "darwin", "arm64", tSHA3, "https://art/1.0.0/darwin-arm64"); err != nil {
		t.Fatalf("add darwin/arm64 artifact: %v", err)
	}

	eng := rollout.New(s.DB, nil)
	const linuxHost, darwinHost, winHost = "100.64.0.1", "100.64.0.2", "100.64.0.3"
	// CanarySize == len(hosts) -> all three are in wave 0, so every member resolves to
	// the target generation; only the per-arch lookup distinguishes them.
	if _, err := eng.Start(ctx, rollout.StartConfig{
		Lane: rollout.LaneNebula, TargetVersion: int(g1.Gen), PrevVersion: 0,
		Hosts: []string{linuxHost, darwinHost, winHost}, CanarySize: 3,
		Observe: time.Minute, MissingAfter: time.Minute,
	}); err != nil {
		t.Fatalf("start nebula rollout: %v", err)
	}

	srv := New(Config{
		Rollout: eng, NebulaReleases: reg,
		NebulaVersion: "static", NebulaSHA256: "staticsha", NebulaURL: "static-url",
	})

	// linux/amd64 host -> the DEFAULT artifact (the parent row's sha+url).
	if v, sh, u := srv.nebulaRelease(ctx, linuxHost, "linux", "amd64"); v != "1.0.0" || sh != tSHA1 || u != "https://art/1.0.0/linux-amd64" {
		t.Fatalf("linux/amd64 tuple = (%s,%s,%s), want the default artifact", v, sh, u)
	}
	// darwin/arm64 host -> its OWN child artifact: same version, that arch's sha+url.
	if v, sh, u := srv.nebulaRelease(ctx, darwinHost, "darwin", "arm64"); v != "1.0.0" || sh != tSHA3 || u != "https://art/1.0.0/darwin-arm64" {
		t.Fatalf("darwin/arm64 tuple = (%s,%s,%s), want the darwin child artifact", v, sh, u)
	}
	// windows/amd64 host -> the generation has NO artifact for that arch: leave it ALONE
	// (empty), NOT the wrong-arch default and NOT the static fallback.
	if v, sh, u := srv.nebulaRelease(ctx, winHost, "windows", "amd64"); v != "" || sh != "" || u != "" {
		t.Fatalf("windows/amd64 (no artifact) tuple = (%s,%s,%s), want unpinned (empty)", v, sh, u)
	}

	// assembleBundle reads the host's enrollment goos/goarch and stamps the SAME per-arch
	// tuple into the issued bundle — the path a real renew/refresh travels.
	for _, tc := range []struct {
		name, ip, goos, goarch, wantSHA, wantURL string
	}{
		{"linux/amd64 -> default artifact", linuxHost, "linux", "amd64", tSHA1, "https://art/1.0.0/linux-amd64"},
		{"darwin/arm64 -> child artifact", darwinHost, "darwin", "arm64", tSHA3, "https://art/1.0.0/darwin-arm64"},
	} {
		dev := enrollment.Enrollment{OverlayIP: tc.ip, DeviceName: "d-" + tc.ip, GOOS: tc.goos, GOARCH: tc.goarch}
		b := srv.assembleBundle(ctx, dev, nil, "cert-pem", time.Now())
		if b.NebulaVersion != "1.0.0" || b.NebulaSHA256 != tc.wantSHA || b.NebulaURL != tc.wantURL {
			t.Fatalf("%s: bundle nebula tuple = (%s,%s,%s), want (1.0.0,%s,%s)",
				tc.name, b.NebulaVersion, b.NebulaSHA256, b.NebulaURL, tc.wantSHA, tc.wantURL)
		}
	}
	// And the no-artifact arch leaves the bundle's nebula tuple empty (host stays put).
	devNoArt := enrollment.Enrollment{OverlayIP: winHost, DeviceName: "d-win", GOOS: "windows", GOARCH: "amd64"}
	if b := srv.assembleBundle(ctx, devNoArt, nil, "cert-pem", time.Now()); b.NebulaVersion != "" || b.NebulaSHA256 != "" || b.NebulaURL != "" {
		t.Fatalf("no-artifact arch bundle nebula tuple = (%s,%s,%s), want empty",
			b.NebulaVersion, b.NebulaSHA256, b.NebulaURL)
	}
}
