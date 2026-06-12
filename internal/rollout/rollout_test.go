package rollout_test

import (
	"context"
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
	if err != rollout.ErrActiveExists {
		t.Fatalf("second start err = %v, want ErrActiveExists", err)
	}
}
