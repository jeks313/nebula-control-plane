package main

import (
	"context"
	"encoding/json"
	"flag"
	"path/filepath"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/cloudtrust"
	"github.com/jeks313/nebula-control-plane/internal/config"
	"github.com/jeks313/nebula-control-plane/internal/dualcontrol"
	"github.com/jeks313/nebula-control-plane/internal/policy"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

// commitLegacyChange commits a dual-control change of kind on a controller whose
// committer re-validates ONLY (the pre-Phase-1 wiring) — it does NOT write the config
// store. This reproduces an existing mesh's state on the FIRST boot after migration
// 000027: a committed config lives on the dual-control ledger, but the new config store
// is still empty. (The production committers — registerStoreCommitter /
// adminapi.registerConfigCommitter — DO write the store; the dead package-level
// RegisterCommitter funcs they replaced were inlined here when removed, FIX 3.)
func commitLegacyChange(t *testing.T, s *store.Store, kind string, payload []byte) {
	t.Helper()
	ctx := context.Background()
	audit := func(c context.Context, a, ac, tg, d string) error { _, e := s.AppendAudit(c, a, ac, tg, d); return e }
	dc := dualcontrol.New(dualcontrol.Config{DB: s.DB, Audit: audit})
	dc.Register(kind, func(_ context.Context, ch dualcontrol.Change) error {
		switch kind {
		case policy.PublishKind:
			p, err := policy.Parse(string(ch.Payload))
			if err != nil {
				return err
			}
			return policy.CheckInvariants(p)
		case cloudtrust.PublishKind:
			_, err := cloudtrust.Parse(ch.Payload)
			return err
		default:
			return nil
		}
	})
	ch, err := dc.Propose(ctx, kind, "legacy "+kind, payload, "alice")
	if err != nil {
		t.Fatalf("propose %s: %v", kind, err)
	}
	if committed, err := dc.Approve(ctx, ch.ID, "bob"); err != nil || committed.State != "committed" {
		t.Fatalf("approve %s: %v state=%v", kind, err, committed.State)
	}
}

// TestSeedConfigStoreFromLegacyLedger is the ADR-0011 Phase-1 boot data-migration
// (C8): an EMPTY config store + a committed dual-control change in the legacy ledger →
// boot-seed carries the latest committed payload into the store; the enforcement
// reader then resolves the config from the store. A second seed is idempotent.
func TestSeedConfigStoreFromLegacyLedger(t *testing.T) {
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(filepath.Join(t.TempDir(), "seed.db"))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Simulate the LEGACY world: a committed policy.publish change on the approvals
	// ledger, WITHOUT writing the config store (the pre-Phase-1 wiring).
	commitLegacyChange(t, s, policy.PublishKind, []byte("allow web -> db tcp 5432\n"))

	// The new config store is still EMPTY (the legacy committer didn't write it).
	cs := config.New(s.DB, nil)
	if row, _ := cs.Get(ctx, policy.PublishKind); row != nil {
		t.Fatalf("config store unexpectedly populated before seed: %+v", row)
	}

	// Boot-seed: carries the latest committed payload into the store.
	var seedErrs []string
	seedConfigStore(ctx, s, func(kind string, err error) { seedErrs = append(seedErrs, kind+": "+err.Error()) })
	if len(seedErrs) != 0 {
		t.Fatalf("seed reported errors: %v", seedErrs)
	}

	row, err := cs.Get(ctx, policy.PublishKind)
	if err != nil || row == nil {
		t.Fatalf("config store not seeded: row=%v err=%v", row, err)
	}
	if string(row.Payload) != "allow web -> db tcp 5432\n" || row.UpdatedBy != "migration" {
		t.Fatalf("seeded row = %+v, want the legacy payload by 'migration'", row)
	}

	// The enforcement reader resolves the active policy from the store now.
	if p, ok := activePolicy(ctx, s); !ok || len(p.Rules) != 1 {
		t.Fatalf("activePolicy after seed = %+v ok=%v, want 1 rule", p, ok)
	}

	// Idempotent: a second seed is a no-op (does not bump the version).
	seedConfigStore(ctx, s, func(kind string, err error) { t.Fatalf("second seed errored on %s: %v", kind, err) })
	row2, _ := cs.Get(ctx, policy.PublishKind)
	if row2.Version != 1 {
		t.Fatalf("second seed bumped version to %d, want still 1 (idempotent)", row2.Version)
	}
}

func seedTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(filepath.Join(t.TempDir(), "seed.db"))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestAdminAPIBootSeedsBeforeEnforcementSnapshot is the FIX-1 regression: on the FIRST
// boot after migration 000027 of an EXISTING mesh, the admin-api enrollment build
// snapshots the enforcement config (cf.policy(s) / cf.cloudTrust(s)) at consumer-build
// time. If the boot-seed (carrying the legacy committed config into the empty config
// store) runs AFTER that build, the consumer captures Policy=nil / CloudTrust=nil for
// the whole process lifetime — AWS attestation disabled (deny) and Pilot's local-default
// firewall — a silent fail-closed regression. cmdAdminAPI now seeds BEFORE building, so
// the resolvers the consumer reads return the seeded (non-nil) config.
//
// This drives the resolver methods directly (no CA/queue/HTTP machinery): they ARE what
// cf.buildConsumer reads at build time, so a non-nil result here is exactly the value the
// consumer would snapshot.
func TestAdminAPIBootSeedsBeforeEnforcementSnapshot(t *testing.T) {
	s := seedTestStore(t)
	ctx := context.Background()

	// An existing mesh: a committed policy AND cloud-trust config on the legacy ledger,
	// with the new config store still empty (the first-boot-after-migration state).
	commitLegacyChange(t, s, policy.PublishKind, []byte("allow web -> db tcp 5432\n"))
	ctCfg, _ := json.Marshal(cloudtrust.Config{
		DefaultGroups: []string{"fleet"},
		AWS:           []cloudtrust.AWSAccount{{Account: "111122223333", Groups: []string{"workloads"}}},
	})
	commitLegacyChange(t, s, cloudtrust.PublishKind, ctCfg)

	// The consumer build reads cf.policy(s)/cf.cloudTrust(s) under -policy-db/-cloudtrust-db.
	fs := flag.NewFlagSet("core", flag.ContinueOnError)
	cf := addCoreFlags(fs)
	if err := fs.Set("policy-db", "true"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Set("cloudtrust-db", "true"); err != nil {
		t.Fatal(err)
	}

	// BEFORE the seed (the OLD ordering: cf.build() then seed) both snapshots are nil —
	// the fail-closed regression this fix prevents.
	if p := cf.policy(s); p != nil {
		t.Fatalf("precondition: policy snapshot should be nil before seed (empty store), got %+v", p)
	}
	if c := cf.cloudTrust(s); c != nil {
		t.Fatalf("precondition: cloud-trust snapshot should be nil before seed (empty store), got %+v", c)
	}

	// The fix: seed BEFORE the consumer build (cmdAdminAPI ordering).
	seedConfigStore(ctx, s, func(kind string, err error) { t.Fatalf("seed errored on %s: %v", kind, err) })

	// AFTER the seed the snapshots the consumer captures are non-nil (seeded), not nil.
	p := cf.policy(s)
	if p == nil {
		t.Fatal("policy snapshot is nil after seed — admin-api would run Pilot local-default firewall (fail-closed regression)")
	}
	if len(p.Rules) != 1 {
		t.Fatalf("seeded policy = %+v, want 1 rule", p)
	}
	c := cf.cloudTrust(s)
	if c == nil {
		t.Fatal("cloud-trust snapshot is nil after seed — admin-api would deny all AWS attestation (fail-closed regression)")
	}
	if len(c.AWS) != 1 || c.AWS[0].Account != "111122223333" {
		t.Fatalf("seeded cloud-trust = %+v, want the legacy AWS account", c)
	}
}

// TestSeedConfigStoreSkipsInvalidLegacyConfig is the FIX-2 strictness check: a legacy
// committed config that no longer passes the current validators (strictness drift) must
// be SKIPPED with a warning, not seeded — the reader's fail-closed stays the backstop.
// Here a legacy policy references the reserved control-plane group; that bypassed the
// committer in this test's legacy simulation (it is rejected by CheckInvariants, which
// the seed now re-runs), so the seed must refuse it.
func TestSeedConfigStoreSkipsInvalidLegacyConfig(t *testing.T) {
	s := seedTestStore(t)
	ctx := context.Background()

	// Commit a strictness-drifted legacy policy WITHOUT the invariant check, so it lands on
	// the ledger exactly as a config committed under looser rules would have.
	audit := func(c context.Context, a, ac, tg, d string) error { _, e := s.AppendAudit(c, a, ac, tg, d); return e }
	dc := dualcontrol.New(dualcontrol.Config{DB: s.DB, Audit: audit})
	dc.Register(policy.PublishKind, func(_ context.Context, ch dualcontrol.Change) error {
		_, perr := policy.Parse(string(ch.Payload)) // Parse only — NO CheckInvariants (looser legacy rule)
		return perr
	})
	bad := []byte("allow web -> control-plane tcp 443\n") // references a reserved group (invariant violation)
	ch, err := dc.Propose(ctx, policy.PublishKind, "drifted policy", bad, "alice")
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if committed, err := dc.Approve(ctx, ch.ID, "bob"); err != nil || committed.State != "committed" {
		t.Fatalf("approve: %v state=%v", err, committed.State)
	}

	// Seed must SKIP it with a warning (not seed an invalid config, not fail boot).
	var warned []string
	seedConfigStore(ctx, s, func(kind string, err error) { warned = append(warned, kind+": "+err.Error()) })
	if len(warned) != 1 {
		t.Fatalf("expected exactly one warning for the invalid policy, got %v", warned)
	}

	// The config store stays EMPTY for this kind — nothing invalid was planted.
	if row, _ := config.New(s.DB, nil).Get(ctx, policy.PublishKind); row != nil {
		t.Fatalf("invalid legacy policy was seeded anyway: %+v", row)
	}
}
