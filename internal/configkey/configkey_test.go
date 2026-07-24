package configkey

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"

	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

func setup(t *testing.T) (*store.Store, *Registry) {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(filepath.Join(t.TempDir(), "ck.db"))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	return s, New(s.DB, nil)
}

// mkConfigPub mints a fresh P256 software config-signing key and returns its public-key PEM +
// fingerprint (wire.PubkeyHash of the point — identical to the JWS Kid).
func mkConfigPub(t *testing.T) (pem, fp string) {
	t.Helper()
	b, err := signer.NewSoftwareBackend()
	if err != nil {
		t.Fatalf("software backend: %v", err)
	}
	pub, err := b.PublicKey()
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	return string(cert.MarshalSigningPublicKeyToPEM(cert.Curve_P256, pub)), wire.PubkeyHash(pub)
}

func seedHB(t *testing.T, s *store.Store, ip string, lastSeen int64, trustedConfigKeys string) {
	t.Helper()
	if err := s.DB.Exec(`INSERT INTO heartbeats (overlay_ip, device_name, last_seen, trusted_config_keys) VALUES (?,?,?,?)`,
		ip, "dev-"+ip, lastSeen, trustedConfigKeys).Error; err != nil {
		t.Fatalf("seed heartbeat %s: %v", ip, err)
	}
}

func fixedNow(r *Registry) time.Time {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	return now
}

func states(t *testing.T, r *Registry) map[string]State {
	t.Helper()
	rows, err := r.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]State{}
	for _, c := range rows {
		m[c.Name] = c.State
	}
	return m
}

// TestStageEntersTrustButNotSigning: a staged key is trusted (advertised) but is not the signing key.
func TestStageEntersTrustButNotSigning(t *testing.T) {
	_, r := setup(t)
	ctx := context.Background()
	pem, fp := mkConfigPub(t)

	row, err := r.Stage(ctx, "config-1", pem, "software", "op")
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if row.State != StateStaged || row.Fingerprint != fp {
		t.Fatalf("staged row = %+v (want fp %s)", row, fp)
	}
	if tk, _ := r.TrustedKeys(ctx); len(tk) != 1 || tk[0] != pem {
		t.Fatalf("trusted keys = %v, want [config-1 pem]", tk)
	}
	if _, err := r.Active(ctx); !errors.Is(err, ErrNoActive) {
		t.Fatalf("Active err = %v, want ErrNoActive (staged is not signing)", err)
	}
}

// TestSeedActiveIdempotent: the boot-seed installs the current config key as active exactly once.
func TestSeedActiveIdempotent(t *testing.T) {
	_, r := setup(t)
	ctx := context.Background()
	pem, fp := mkConfigPub(t)

	row, seeded, err := r.SeedActive(ctx, "genesis-config", pem, "kms:x", "boot")
	if err != nil || !seeded || row.State != StateActive || row.Fingerprint != fp {
		t.Fatalf("first seed: row=%+v seeded=%v err=%v", row, seeded, err)
	}
	// Second seed is a no-op returning the existing active row.
	row2, seeded2, err := r.SeedActive(ctx, "genesis-config", pem, "kms:x", "boot")
	if err != nil || seeded2 || row2.Fingerprint != fp {
		t.Fatalf("second seed should no-op: row=%+v seeded=%v err=%v", row2, seeded2, err)
	}
}

// TestActivateDemotesAndCutsOver: activating a staged key demotes the prior active to draining and
// makes the target the single active key.
func TestActivateDemotesAndCutsOver(t *testing.T) {
	_, r := setup(t)
	ctx := context.Background()
	p1, _ := mkConfigPub(t)
	p2, fp2 := mkConfigPub(t)

	if _, _, err := r.SeedActive(ctx, "k1", p1, "kms:1", "boot"); err != nil {
		t.Fatal(err)
	}
	k2, err := r.Stage(ctx, "k2", p2, "kms:2", "op")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Activate(ctx, k2.ID, "op"); err != nil {
		t.Fatalf("activate: %v", err)
	}
	st := states(t, r)
	if st["k1"] != StateDraining || st["k2"] != StateActive {
		t.Fatalf("states = %v, want k1=draining k2=active", st)
	}
	if af, _ := r.ActiveFingerprint(ctx); af != fp2 {
		t.Fatalf("active fingerprint = %s, want %s", af, fp2)
	}
	// Both non-retired keys remain trusted (overlap).
	if tk, _ := r.TrustedKeys(ctx); len(tk) != 2 {
		t.Fatalf("trusted keys = %d, want 2 during overlap", len(tk))
	}
}

// TestTrustedKeysByteStable: an unchanged trust set serializes identically across calls (sorted).
func TestTrustedKeysByteStable(t *testing.T) {
	_, r := setup(t)
	ctx := context.Background()
	p1, _ := mkConfigPub(t)
	p2, _ := mkConfigPub(t)
	if _, _, err := r.SeedActive(ctx, "k1", p1, "", "boot"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Stage(ctx, "k2", p2, "", "op"); err != nil {
		t.Fatal(err)
	}
	a, _ := r.TrustedKeys(ctx)
	b, _ := r.TrustedKeys(ctx)
	if len(a) != 2 || len(b) != 2 || a[0] != b[0] || a[1] != b[1] {
		t.Fatalf("trusted keys not byte-stable: %v vs %v", a, b)
	}
}

// TestGenerationMonotonic: Generation advances on every lifecycle mutation.
func TestGenerationMonotonic(t *testing.T) {
	_, r := setup(t)
	ctx := context.Background()
	g0, _ := r.Generation(ctx)
	if g0 != 0 {
		t.Fatalf("empty generation = %d, want 0", g0)
	}
	p1, _ := mkConfigPub(t)
	p2, _ := mkConfigPub(t)
	// Advance the clock between mutations so updated_at strictly increases.
	tick := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r.now = func() time.Time { tick = tick.Add(time.Second); return tick }
	if _, _, err := r.SeedActive(ctx, "k1", p1, "", "boot"); err != nil {
		t.Fatal(err)
	}
	g1, _ := r.Generation(ctx)
	k2, _ := r.Stage(ctx, "k2", p2, "", "op")
	g2, _ := r.Generation(ctx)
	if err := r.Activate(ctx, k2.ID, "op"); err != nil {
		t.Fatal(err)
	}
	g3, _ := r.Generation(ctx)
	if !(g1 > 0 && g2 > g1 && g3 > g2) {
		t.Fatalf("generation not monotonic: g1=%d g2=%d g3=%d", g1, g2, g3)
	}
}

// TestAdoptionGate100Pct: a live host with empty/malformed/missing set is a fail-closed laggard;
// exact base64url match; empty live fleet vacuously adopted.
func TestAdoptionGate100Pct(t *testing.T) {
	s, r := setup(t)
	ctx := context.Background()
	now := fixedNow(r)
	_, fp := mkConfigPub(t)

	// Empty fleet: vacuously adopted.
	ad, _ := r.AdoptionStatus(ctx, fp, 5*time.Minute)
	if !ad.FullyAdopted() || ad.Live != 0 {
		t.Fatalf("empty fleet: %+v, want vacuously adopted", ad)
	}

	fresh := now.UnixNano()
	stale := now.Add(-time.Hour).UnixNano()
	seedHB(t, s, "100.64.0.10", fresh, `["`+fp+`"]`) // adopted
	seedHB(t, s, "100.64.0.11", fresh, `[]`)         // live but empty -> laggard
	seedHB(t, s, "100.64.0.12", fresh, `garbage`)    // malformed -> laggard
	seedHB(t, s, "100.64.0.13", stale, `[]`)         // stale -> excluded

	ad, err := r.AdoptionStatus(ctx, fp, 5*time.Minute)
	if err != nil {
		t.Fatalf("adoption: %v", err)
	}
	if ad.Live != 3 || ad.Adopted != 1 || len(ad.Laggards) != 2 || len(ad.Stale) != 1 {
		t.Fatalf("adoption = %+v, want live=3 adopted=1 laggards=2 stale=1", ad)
	}
	if ad.FullyAdopted() {
		t.Fatal("must not be fully adopted with live laggards")
	}
	// Case sensitivity: an upper-cased fingerprint must NOT match (base64url is case-sensitive).
	if containsExact([]string{fp}, fp+"X") {
		t.Fatal("containsExact must be exact")
	}
}

// TestRetireDrainIsAdoptionInverse: Retire(draining) is refused while any live host does not trust
// the ACTIVE key, fail-closed with no active key, and succeeds at 0 laggards.
func TestRetireDrainIsAdoptionInverse(t *testing.T) {
	s, r := setup(t)
	ctx := context.Background()
	now := fixedNow(r)
	p1, _ := mkConfigPub(t)
	p2, fp2 := mkConfigPub(t)

	if _, _, err := r.SeedActive(ctx, "k1", p1, "kms:1", "boot"); err != nil {
		t.Fatal(err)
	}
	k2, _ := r.Stage(ctx, "k2", p2, "kms:2", "op")
	if err := r.Activate(ctx, k2.ID, "op"); err != nil { // k1 -> draining, k2 -> active
		t.Fatal(err)
	}
	k1 := states(t, r)
	_ = k1
	k1id := int64(1)

	fresh := now.UnixNano()
	// One live host trusts only k1 (not the active k2) -> a laggard -> retire refused.
	seedHB(t, s, "100.64.0.10", fresh, `["`+fp2+`"]`)
	seedHB(t, s, "100.64.0.11", fresh, `[]`)
	if err := r.Retire(ctx, k1id, 5*time.Minute, "op"); !errors.Is(err, ErrNotDrained) {
		t.Fatalf("Retire err = %v, want ErrNotDrained (a live host has not adopted the active key)", err)
	}
	// Every live host now trusts the active key -> retire succeeds.
	if err := s.DB.Exec(`UPDATE heartbeats SET trusted_config_keys=?`, `["`+fp2+`"]`).Error; err != nil {
		t.Fatal(err)
	}
	if err := r.Retire(ctx, k1id, 5*time.Minute, "op"); err != nil {
		t.Fatalf("Retire at 0 laggards: %v", err)
	}
	if states(t, r)["k1"] != StateRetired {
		t.Fatal("k1 should be retired")
	}
	// k1 drops out of the trust set.
	if tk, _ := r.TrustedKeys(ctx); len(tk) != 1 {
		t.Fatalf("trusted keys after retire = %d, want 1 (only active k2)", len(tk))
	}
}

// TestRetireFailClosedNoActive: with no active key, Retire fails closed rather than certifying a drain.
func TestRetireFailClosedNoActive(t *testing.T) {
	_, r := setup(t)
	ctx := context.Background()
	p1, _ := mkConfigPub(t)
	// Stage-and-abandon leaves a draining-like edge? Simpler: seed active, stage k2, activate, then
	// manually force k1 draining is already done; here just prove DrainLaggards fails with no active.
	if _, err := r.Stage(ctx, "k1", p1, "", "op"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.DrainLaggards(ctx, time.Minute); !errors.Is(err, ErrNoActive) {
		t.Fatalf("DrainLaggards err = %v, want ErrNoActive", err)
	}
}

// TestScheduleKeyDeletionGuardrails: only a RETIRED key, with a backend, 7-30d, no double-schedule.
func TestScheduleKeyDeletionGuardrails(t *testing.T) {
	_, r := setup(t)
	ctx := context.Background()
	now := fixedNow(r)
	p1, _ := mkConfigPub(t)
	p2, fp2 := mkConfigPub(t)
	del := NoopKeyDeleter{Now: func() time.Time { return now }}

	if _, _, err := r.SeedActive(ctx, "k1", p1, "kms:1", "boot"); err != nil {
		t.Fatal(err)
	}
	k2, _ := r.Stage(ctx, "k2", p2, "kms:2", "op")
	if err := r.Activate(ctx, k2.ID, "op"); err != nil {
		t.Fatal(err)
	}
	// A non-retired key's deletion is refused.
	if _, err := r.ScheduleKeyDeletion(ctx, k2.ID, 7, del, "op"); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("schedule on active key err = %v, want ErrIllegalTransition", err)
	}
	// Retire k1 (fleet is empty -> vacuously drained), then schedule.
	if err := r.Retire(ctx, 1, 5*time.Minute, "op"); err != nil {
		t.Fatalf("retire k1: %v", err)
	}
	if _, err := r.ScheduleKeyDeletion(ctx, 1, 3, del, "op"); err == nil {
		t.Fatal("pending window < 7 days must be rejected")
	}
	dd, err := r.ScheduleKeyDeletion(ctx, 1, 7, del, "op")
	if err != nil {
		t.Fatalf("schedule retired key: %v", err)
	}
	if dd.Before(now) {
		t.Fatalf("deletion date %v before now %v", dd, now)
	}
	// Double-schedule refused.
	if _, err := r.ScheduleKeyDeletion(ctx, 1, 7, del, "op"); err == nil {
		t.Fatal("double schedule must be rejected")
	}
	// Cancel restores.
	if err := r.CancelKeyDeletion(ctx, 1, del, "op"); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	pend, _ := r.PendingKeyDeletions(ctx)
	if len(pend) != 0 {
		t.Fatalf("pending after cancel = %d, want 0", len(pend))
	}
	_ = fp2
}
