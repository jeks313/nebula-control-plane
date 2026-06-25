package rollout_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/rollout"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
	"github.com/jeks313/nebula-control-plane/internal/wire"
	"gorm.io/gorm"
)

func newEngine(t *testing.T) (*rollout.Engine, *gorm.DB, *fakeClock) {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(t.TempDir() + "/r.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	audit := func(ctx context.Context, a, ac, tgt, d string) error {
		_, e := s.AppendAudit(ctx, a, ac, tgt, d)
		return e
	}
	eng := rollout.New(s.DB, audit)
	eng.SetClock(clk.now)
	return eng, s.DB, clk
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }

// heartbeat upserts a heartbeats row the way coreapi would.
func heartbeat(t *testing.T, db *gorm.DB, ip string, version int, health string, lastSeen time.Time) {
	t.Helper()
	sql := `INSERT INTO heartbeats (overlay_ip, device_name, applied_bundle_version, health, last_seen)
	        VALUES (?, ?, ?, ?, ?)
	        ON CONFLICT(overlay_ip) DO UPDATE SET applied_bundle_version=excluded.applied_bundle_version,
	          health=excluded.health, last_seen=excluded.last_seen`
	if err := db.Exec(sql, ip, ip, version, health, lastSeen.UnixNano()).Error; err != nil {
		t.Fatal(err)
	}
}

// heartbeatBL upserts a heartbeat reporting an applied BLOCKLIST-lane version.
func heartbeatBL(t *testing.T, db *gorm.DB, ip string, blVersion int, health string, lastSeen time.Time) {
	t.Helper()
	sql := `INSERT INTO heartbeats (overlay_ip, device_name, applied_blocklist_version, health, last_seen)
	        VALUES (?, ?, ?, ?, ?)
	        ON CONFLICT(overlay_ip) DO UPDATE SET applied_blocklist_version=excluded.applied_blocklist_version,
	          health=excluded.health, last_seen=excluded.last_seen`
	if err := db.Exec(sql, ip, ip, blVersion, health, lastSeen.UnixNano()).Error; err != nil {
		t.Fatal(err)
	}
}

// TestConcurrentLanesAndBlocklistFreeze is the M7.1b acceptance: a blocklist-lane
// rollout runs CONCURRENTLY with a policy rollout (the engine no longer refuses a
// 2nd active rollout on a different lane), the two lanes track convergence on
// independent version axes, and on an unhealthy canary the blocklist lane FREEZES
// — it issues no content-revert command (unlike the policy lane).
func TestConcurrentLanesAndBlocklistFreeze(t *testing.T) {
	eng, db, clk := newEngine(t)
	ctx := context.Background()
	hosts := []string{"100.64.0.1", "100.64.0.2"}

	// A policy rollout is in flight (default lane).
	if _, err := eng.Start(ctx, rollout.StartConfig{
		TargetVersion: 2, PrevVersion: 1, Hosts: hosts,
		CanarySize: 1, Observe: 10 * time.Minute, MissingAfter: 3 * time.Minute, Actor: "alice",
	}); err != nil {
		t.Fatalf("policy start: %v", err)
	}
	// A blocklist rollout starts CONCURRENTLY — a different lane is NOT refused.
	if _, err := eng.Start(ctx, rollout.StartConfig{
		Lane: rollout.LaneBlocklist, TargetVersion: 1, PrevVersion: 0, Hosts: hosts,
		CanarySize: 1, Observe: 10 * time.Minute, MissingAfter: 3 * time.Minute, Actor: "alice",
	}); err != nil {
		t.Fatalf("blocklist start concurrent with policy must succeed, got %v", err)
	}
	// A 2nd blocklist rollout IS refused (one active per lane).
	if _, err := eng.Start(ctx, rollout.StartConfig{
		Lane: rollout.LaneBlocklist, TargetVersion: 2, PrevVersion: 1, Hosts: hosts,
		Observe: time.Minute, MissingAfter: time.Minute,
	}); !errors.Is(err, rollout.ErrActiveExists) {
		t.Fatalf("2nd blocklist start err = %v, want ErrActiveExists", err)
	}

	if v := eng.BlocklistVersion(ctx); v != 1 {
		t.Fatalf("BlocklistVersion = %d, want 1", v)
	}

	// Each lane independently drives its canary to its own target version.
	if cmd, ok := eng.BlocklistCommandFor(ctx, "100.64.0.1", 0); !ok || cmd.Type != wire.CmdApplyBundle || cmd.BundleVersion != 1 {
		t.Fatalf("blocklist canary cmd = %+v ok=%v, want apply_bundle v1", cmd, ok)
	}
	if cmd, ok := eng.CommandFor(ctx, "100.64.0.1", 1); !ok || cmd.BundleVersion != 2 {
		t.Fatalf("policy canary cmd = %+v ok=%v, want apply_bundle v2", cmd, ok)
	}

	// Blocklist canary applied v1 but reports UNHEALTHY -> the blocklist lane freezes.
	heartbeatBL(t, db, "100.64.0.1", 1, "unhealthy", clk.now())
	if _, err := eng.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	r, _, _ := eng.StatusLane(ctx, rollout.LaneBlocklist)
	if r.State != rollout.StateRolledBack {
		t.Fatalf("blocklist lane state = %s, want rolledback (frozen)", r.State)
	}
	// FREEZE: no content-revert command on the blocklist lane (the set stays latest;
	// an operator lifts a bad entry). Contrast with the policy lane, which reverts.
	if cmd, ok := eng.BlocklistCommandFor(ctx, "100.64.0.1", 1); ok {
		t.Fatalf("blocklist freeze must issue NO revert command, got %+v", cmd)
	}
}

// heartbeatNeb upserts a heartbeat reporting an applied NEBULA-lane generation.
func heartbeatNeb(t *testing.T, db *gorm.DB, ip string, nebGen int, health string, lastSeen time.Time) {
	t.Helper()
	sql := `INSERT INTO heartbeats (overlay_ip, device_name, applied_nebula_version, health, last_seen)
	        VALUES (?, ?, ?, ?, ?)
	        ON CONFLICT(overlay_ip) DO UPDATE SET applied_nebula_version=excluded.applied_nebula_version,
	          health=excluded.health, last_seen=excluded.last_seen`
	if err := db.Exec(sql, ip, ip, nebGen, health, lastSeen.UnixNano()).Error; err != nil {
		t.Fatal(err)
	}
}

// TestNebulaLaneStagesConvergesAndReverts is the ADR 0003 Phase 1c acceptance: a
// nebula RELEASE generation is staged via its own lane — in-wave hosts get the new
// generation while everyone else stays on prev (so Core stamps the right tuple per
// host), a healthy canary widens then completes (whole fleet on target), and a
// rollback reverts touched hosts to the prev generation (a bad nebula downgrades,
// unlike the blocklist lane which freezes).
func TestNebulaLaneStagesConvergesAndReverts(t *testing.T) {
	eng, db, clk := newEngine(t)
	ctx := context.Background()
	hosts := []string{"100.64.0.1", "100.64.0.2"}

	// Stage gen 2 over gen 1: canary = host[0], wave 1 = host[1].
	if _, err := eng.Start(ctx, rollout.StartConfig{
		Lane: rollout.LaneNebula, TargetVersion: 2, PrevVersion: 1, Hosts: hosts,
		CanarySize: 1, Observe: 10 * time.Minute, MissingAfter: 3 * time.Minute, Actor: "alice",
	}); err != nil {
		t.Fatalf("nebula start: %v", err)
	}

	// Per-host stamping: the canary gets the NEW gen, the out-of-wave host stays prev.
	if g, ok := eng.NebulaGenFor(ctx, "100.64.0.1"); !ok || g != 2 {
		t.Fatalf("canary NebulaGenFor = %d ok=%v, want gen 2", g, ok)
	}
	if g, ok := eng.NebulaGenFor(ctx, "100.64.0.2"); !ok || g != 1 {
		t.Fatalf("out-of-wave NebulaGenFor = %d ok=%v, want gen 1 (prev)", g, ok)
	}
	// The canary is told to converge (it still runs gen 1); the apply_bundle re-fetch
	// delivers the gen-2 tuple.
	if cmd, ok := eng.NebulaCommandFor(ctx, "100.64.0.1", 1); !ok || cmd.Type != wire.CmdApplyBundle {
		t.Fatalf("canary cmd = %+v ok=%v, want apply_bundle", cmd, ok)
	}

	// Canary reports running gen 2, healthy -> widen to wave 1.
	heartbeatNeb(t, db, "100.64.0.1", 2, "healthy", clk.now())
	if changed, _ := eng.Evaluate(ctx); !changed {
		t.Fatal("healthy nebula canary should widen")
	}
	if g, _ := eng.NebulaGenFor(ctx, "100.64.0.2"); g != 2 {
		t.Fatalf("after widen, host2 NebulaGenFor = %d, want gen 2", g)
	}

	// host2 converges -> completed -> the whole fleet is on gen 2.
	heartbeatNeb(t, db, "100.64.0.2", 2, "healthy", clk.now())
	if _, err := eng.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	if r, _, _ := eng.StatusLane(ctx, rollout.LaneNebula); r.State != rollout.StateCompleted {
		t.Fatalf("nebula rollout state = %s, want completed", r.State)
	}
	if g := eng.CurrentNebulaGen(ctx); g != 2 {
		t.Fatalf("CurrentNebulaGen = %d, want 2 (the completed target)", g)
	}

	// Now stage a bad gen 3 over the live gen 2; the canary goes unhealthy.
	if _, err := eng.Start(ctx, rollout.StartConfig{
		Lane: rollout.LaneNebula, TargetVersion: 3, PrevVersion: eng.CurrentNebulaGen(ctx), Hosts: hosts,
		CanarySize: 1, Observe: 10 * time.Minute, MissingAfter: 3 * time.Minute, Actor: "alice",
	}); err != nil {
		t.Fatalf("nebula start gen3: %v", err)
	}
	heartbeatNeb(t, db, "100.64.0.1", 3, "unhealthy", clk.now())
	if _, err := eng.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	if r, _, _ := eng.StatusLane(ctx, rollout.LaneNebula); r.State != rollout.StateRolledBack {
		t.Fatalf("bad nebula canary should roll back, got %s", r.State)
	}
	// Revert: the touched canary is stamped prev (gen 2) and commanded back to it
	// (the nebula lane downgrades, unlike the blocklist freeze).
	if g, _ := eng.NebulaGenFor(ctx, "100.64.0.1"); g != 2 {
		t.Fatalf("after rollback, canary NebulaGenFor = %d, want gen 2 (prev)", g)
	}
	if cmd, ok := eng.NebulaCommandFor(ctx, "100.64.0.1", 3); !ok || cmd.BundleVersion != 2 {
		t.Fatalf("rollback revert cmd = %+v ok=%v, want apply_bundle to gen 2", cmd, ok)
	}
	// The live desired gen is unchanged by the failed rollout.
	if g := eng.CurrentNebulaGen(ctx); g != 2 {
		t.Fatalf("CurrentNebulaGen after rollback = %d, want 2", g)
	}
}

func start(t *testing.T, eng *rollout.Engine, hosts []string) {
	t.Helper()
	_, err := eng.Start(context.Background(), rollout.StartConfig{
		TargetVersion: 2, PrevVersion: 1, Hosts: hosts,
		CanarySize: 1, WaveSize: 0, // canary=host[0], wave 1 = the rest
		Observe: 10 * time.Minute, MissingAfter: 3 * time.Minute, Actor: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestHealthyCanaryWidensThenCompletes is the happy path: a healthy canary
// widens to wave 1, which then converges and completes.
func TestHealthyCanaryWidensThenCompletes(t *testing.T) {
	eng, db, clk := newEngine(t)
	ctx := context.Background()
	start(t, eng, []string{"100.64.0.1", "100.64.0.2", "100.64.0.3"})

	// Canary applies target + healthy.
	heartbeat(t, db, "100.64.0.1", 2, "healthy", clk.now())
	if changed, _ := eng.Evaluate(ctx); !changed {
		t.Fatal("healthy canary should advance the rollout")
	}
	r, _, _ := eng.Status(ctx)
	if r.State != rollout.StateWidening || r.ActiveWave != 1 {
		t.Fatalf("after canary: state=%s wave=%d, want widening/1", r.State, r.ActiveWave)
	}

	// Wave 1 converges.
	heartbeat(t, db, "100.64.0.2", 2, "healthy", clk.now())
	heartbeat(t, db, "100.64.0.3", 2, "healthy", clk.now())
	if changed, _ := eng.Evaluate(ctx); !changed {
		t.Fatal("healthy wave 1 should complete the rollout")
	}
	r, _, _ = eng.Status(ctx)
	if r.State != rollout.StateCompleted {
		t.Fatalf("state=%s, want completed", r.State)
	}
}

// TestBadCanaryAutoRollsBack is the 6.6 acceptance: an unhealthy canary
// auto-rolls-back and freezes with no operator action, and the canary host is
// then commanded back to prev.
func TestBadCanaryAutoRollsBack(t *testing.T) {
	eng, db, clk := newEngine(t)
	ctx := context.Background()
	start(t, eng, []string{"100.64.0.1", "100.64.0.2", "100.64.0.3"})

	// Canary applied the target but reports unhealthy.
	heartbeat(t, db, "100.64.0.1", 2, "unhealthy", clk.now())
	changed, err := eng.Evaluate(ctx)
	if err != nil || !changed {
		t.Fatalf("bad canary should change state: changed=%v err=%v", changed, err)
	}
	r, _, _ := eng.Status(ctx)
	if r.State != rollout.StateRolledBack {
		t.Fatalf("state=%s, want rolledback", r.State)
	}

	// The canary is now commanded back to prev (it's still on target=2).
	cmd, ok := eng.CommandFor(ctx, "100.64.0.1", 2)
	if !ok || cmd.Type != wire.CmdApplyBundle || cmd.BundleVersion != 1 {
		t.Fatalf("revert command = %+v ok=%v, want apply_bundle v1", cmd, ok)
	}
	// Wave 1 (never activated) is left alone.
	if _, ok := eng.CommandFor(ctx, "100.64.0.2", 1); ok {
		t.Fatal("un-activated wave host must not be commanded")
	}
}

// TestSilentCanaryAutoRollsBack: a canary that never heartbeats on the target,
// past the missing-after threshold, is treated as down and rolled back.
func TestSilentCanaryAutoRollsBack(t *testing.T) {
	eng, _, clk := newEngine(t)
	ctx := context.Background()
	start(t, eng, []string{"100.64.0.1", "100.64.0.2"})

	// Before the grace period: no heartbeat yet -> keep observing.
	if changed, _ := eng.Evaluate(ctx); changed {
		t.Fatal("must not judge a host down before missing-after elapses")
	}
	// After the threshold with still no heartbeat -> rollback.
	clk.add(4 * time.Minute)
	changed, err := eng.Evaluate(ctx)
	if err != nil || !changed {
		t.Fatalf("silent canary past threshold should roll back: changed=%v err=%v", changed, err)
	}
	r, _, _ := eng.Status(ctx)
	if r.State != rollout.StateRolledBack {
		t.Fatalf("state=%s, want rolledback", r.State)
	}
}

// TestStaleLaterWaveDoesNotRollBack is the regression guard for the missing-host bug: after the
// canary validates the update, a LATER wave whose hosts have been silent since before the rollout
// (decommissioned / unreachable leftovers) must NOT roll the fleet back — they are EXCLUDED, and
// the rollout completes. (Previously any `missing` host was a blanket rollback trigger, so one
// stale leftover torpedoed every rollout — exactly what reverted harbor's relay on the live poc.)
func TestStaleLaterWaveDoesNotRollBack(t *testing.T) {
	eng, db, clk := newEngine(t)
	ctx := context.Background()
	start(t, eng, []string{"100.64.0.1", "100.64.0.2", "100.64.0.3"})

	// Wave-1 hosts (.2, .3) are STALE — last heartbeat long before the rollout, then silent.
	heartbeat(t, db, "100.64.0.2", 1, "ok", clk.now().Add(-2*time.Hour))
	heartbeat(t, db, "100.64.0.3", 1, "ok", clk.now().Add(-2*time.Hour))

	// Canary (.1) applies the target + healthy -> advances to wave 1.
	heartbeat(t, db, "100.64.0.1", 2, "ok", clk.now())
	if changed, _ := eng.Evaluate(ctx); !changed {
		t.Fatal("healthy canary should advance the rollout")
	}
	if r, _, _ := eng.Status(ctx); r.State != rollout.StateWidening || r.ActiveWave != 1 {
		t.Fatalf("after canary: state=%s wave=%d, want widening/1", r.State, r.ActiveWave)
	}

	// Past MissingAfter, wave 1 is all stale/missing -> excluded (NOT a rollback); the rollout
	// completes because nothing reachable is left to converge.
	clk.add(4 * time.Minute)
	changed, err := eng.Evaluate(ctx)
	if err != nil || !changed {
		t.Fatalf("stale wave should resolve (advance/complete): changed=%v err=%v", changed, err)
	}
	r, _, _ := eng.Status(ctx)
	if r.State == rollout.StateRolledBack {
		t.Fatal("stale later-wave hosts must NOT roll the fleet back")
	}
	if r.State != rollout.StateCompleted {
		t.Fatalf("rollout should complete with the stale wave excluded; state=%s", r.State)
	}
}

// TestCompletedRolloutCatchesUpStraggler: after a rollout COMPLETES (a stale host was excluded),
// that host is still driven to the target gen when it next checks in — the completed target is the
// fleet-wide FLOOR, not just an in-flight goal. Without this, an excluded/intermittent host (e.g.
// an off-cloud node that missed the rollout window) would stay on the old gen forever, since an
// update command otherwise only comes from an ACTIVE rollout.
func TestCompletedRolloutCatchesUpStraggler(t *testing.T) {
	eng, db, clk := newEngine(t)
	ctx := context.Background()
	start(t, eng, []string{"100.64.0.1", "100.64.0.2"})

	// Wave-1 host (.2) is stale -> excluded; canary (.1) converges -> the rollout completes.
	heartbeat(t, db, "100.64.0.2", 1, "ok", clk.now().Add(-2*time.Hour))
	heartbeat(t, db, "100.64.0.1", 2, "ok", clk.now())
	if _, err := eng.Evaluate(ctx); err != nil { // canary converges -> widen to wave 1
		t.Fatal(err)
	}
	clk.add(4 * time.Minute)
	if _, err := eng.Evaluate(ctx); err != nil { // wave 1 stale -> excluded -> completed
		t.Fatal(err)
	}
	if r, _, _ := eng.Status(ctx); r.State != rollout.StateCompleted {
		t.Fatalf("precondition: rollout should have completed; state=%s", r.State)
	}

	// The straggler (.2) checks back in still on the old gen -> driven up to the target.
	cmd, ok := eng.CommandFor(ctx, "100.64.0.2", 1)
	if !ok || cmd.Type != wire.CmdApplyBundle || cmd.BundleVersion != 2 {
		t.Fatalf("straggler command = %+v ok=%v, want apply_bundle v2 (catch up to the completed floor)", cmd, ok)
	}
	// Once it's on the target, no further command.
	if _, ok := eng.CommandFor(ctx, "100.64.0.2", 2); ok {
		t.Fatal("a straggler already on the target must get no command")
	}
}

// TestCommandDrivesCanaryToTarget: an in-wave host not yet on target is told to
// apply it; once on target it gets no command.
func TestCommandDrivesCanaryToTarget(t *testing.T) {
	eng, _, _ := newEngine(t)
	ctx := context.Background()
	start(t, eng, []string{"100.64.0.1", "100.64.0.2"})

	cmd, ok := eng.CommandFor(ctx, "100.64.0.1", 1)
	if !ok || cmd.Type != wire.CmdApplyBundle || cmd.BundleVersion != 2 {
		t.Fatalf("canary command = %+v ok=%v, want apply_bundle v2", cmd, ok)
	}
	if _, ok := eng.CommandFor(ctx, "100.64.0.1", 2); ok {
		t.Fatal("host already on target must get no command")
	}
	// A wave-1 host is not yet activated -> no command.
	if _, ok := eng.CommandFor(ctx, "100.64.0.2", 1); ok {
		t.Fatal("un-activated wave host must not be commanded")
	}
}

// TestVersionForStaging: in-wave hosts get target, others get prev.
func TestVersionForStaging(t *testing.T) {
	eng, _, _ := newEngine(t)
	ctx := context.Background()
	start(t, eng, []string{"100.64.0.1", "100.64.0.2"})

	if v, ok := eng.VersionFor(ctx, "100.64.0.1"); !ok || v != 2 {
		t.Fatalf("canary version = %d ok=%v, want 2", v, ok)
	}
	if v, ok := eng.VersionFor(ctx, "100.64.0.2"); !ok || v != 1 {
		t.Fatalf("not-yet-rolled host version = %d ok=%v, want 1 (stable)", v, ok)
	}
	// A non-member host stays stable too.
	if v, ok := eng.VersionFor(ctx, "100.64.0.99"); !ok || v != 1 {
		t.Fatalf("non-member version = %d ok=%v, want 1", v, ok)
	}
}

// TestOnlyOneActive: a second Start while one is active is refused.
func TestOnlyOneActive(t *testing.T) {
	eng, _, _ := newEngine(t)
	ctx := context.Background()
	start(t, eng, []string{"100.64.0.1"})
	_, err := eng.Start(ctx, rollout.StartConfig{
		TargetVersion: 3, PrevVersion: 2, Hosts: []string{"100.64.0.2"},
		Observe: time.Minute, MissingAfter: time.Minute,
	})
	if !errors.Is(err, rollout.ErrActiveExists) {
		t.Fatalf("second start err = %v, want ErrActiveExists", err)
	}
}
