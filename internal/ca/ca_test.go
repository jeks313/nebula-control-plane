package ca

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

func setup(t *testing.T) (*store.Store, *Registry) {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(filepath.Join(t.TempDir(), "ca.db"))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	return s, New(s.DB, nil)
}

// mkCA mints a real self-signed P256 Nebula CA cert and returns its PEM + fingerprint.
func mkCA(t *testing.T, name string) (pem, fp string) {
	t.Helper()
	b, _ := signer.NewSoftwareBackend()
	now := time.Now()
	c, p, err := signer.SelfSignCA(b, signer.CATemplate{
		Name: name, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("self-sign CA %s: %v", name, err)
	}
	f, _ := c.Fingerprint()
	return string(p), f
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

// TestStageEntersTrustButNotActive: a staged CA is trusted (in the bundle) but is not the
// signing CA — the "trust before you sign" property (§4.6 step 2).
func TestStageEntersTrustButNotActive(t *testing.T) {
	_, r := setup(t)
	ctx := context.Background()
	pem, fp := mkCA(t, "ca-1")

	row, err := r.Stage(ctx, "ca-1", pem, "software", "op")
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if row.State != StateStaged || row.Fingerprint != fp {
		t.Fatalf("staged row = %+v", row)
	}
	if tb, _ := r.TrustBundle(ctx); len(tb) != 1 || tb[0] != pem {
		t.Fatalf("trust bundle = %v, want [ca-1 pem]", tb)
	}
	if _, err := r.Active(ctx); !errors.Is(err, ErrNoActive) {
		t.Fatalf("Active err = %v, want ErrNoActive (staged is not signing)", err)
	}
}

// TestSeedActiveIdempotent: the boot-seed installs the current CA as active exactly once.
func TestSeedActiveIdempotent(t *testing.T) {
	_, r := setup(t)
	ctx := context.Background()
	pem, fp := mkCA(t, "ca-genesis")

	row, seeded, err := r.SeedActive(ctx, "ca-genesis", pem, "software", "boot")
	if err != nil || !seeded {
		t.Fatalf("first seed: seeded=%v err=%v", seeded, err)
	}
	if row.State != StateActive {
		t.Fatalf("seeded state = %s, want active", row.State)
	}
	act, err := r.Active(ctx)
	if err != nil || act.Fingerprint != fp {
		t.Fatalf("active = %+v err=%v", act, err)
	}
	// Second seed is a no-op (table non-empty), returns the existing active, seeds nothing.
	pem2, _ := mkCA(t, "ca-other")
	row2, seeded2, err := r.SeedActive(ctx, "ca-other", pem2, "software", "boot")
	if err != nil || seeded2 {
		t.Fatalf("second seed should be a no-op: seeded=%v err=%v", seeded2, err)
	}
	if row2.Fingerprint != fp {
		t.Fatalf("second seed returned %s, want the existing active %s", row2.Fingerprint, fp)
	}
	if rows, _ := r.List(ctx); len(rows) != 1 {
		t.Fatalf("want exactly 1 CA row after two seeds, got %d", len(rows))
	}
}

// TestActivateCutover: staged CA2 becomes active and CA1 is demoted to draining, both
// still trusted (§4.6 step 3). Exactly one active throughout.
func TestActivateCutover(t *testing.T) {
	_, r := setup(t)
	ctx := context.Background()
	pem1, _ := mkCA(t, "ca-1")
	pem2, fp2 := mkCA(t, "ca-2")

	ca1, _, _ := r.SeedActive(ctx, "ca-1", pem1, "software", "boot")
	ca2, err := r.Stage(ctx, "ca-2", pem2, "kms:arn", "op")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Activate(ctx, ca2.ID, "op"); err != nil {
		t.Fatalf("activate ca-2: %v", err)
	}
	st := states(t, r)
	if st["ca-1"] != StateDraining || st["ca-2"] != StateActive {
		t.Fatalf("states after cutover = %v, want ca-1 draining / ca-2 active", st)
	}
	act, _ := r.Active(ctx)
	if act.Fingerprint != fp2 {
		t.Fatalf("active fp = %s, want ca-2 %s", act.Fingerprint, fp2)
	}
	// Both remain trusted during the overlap.
	tb, _ := r.TrustBundle(ctx)
	want := []string{pem1, pem2}
	sort.Strings(want)
	if len(tb) != 2 || tb[0] != want[0] || tb[1] != want[1] {
		t.Fatalf("trust bundle = %v, want both CAs sorted", tb)
	}
	_ = ca1
}

// TestActivateOnlyStaged: activating a non-staged CA is an illegal transition.
func TestActivateOnlyStaged(t *testing.T) {
	_, r := setup(t)
	ctx := context.Background()
	pem, _ := mkCA(t, "ca-1")
	ca1, _, _ := r.SeedActive(ctx, "ca-1", pem, "software", "boot") // active
	if err := r.Activate(ctx, ca1.ID, "op"); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("activate an active CA err = %v, want ErrIllegalTransition", err)
	}
	if _, err := r.Get(ctx, 9999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get missing err = %v, want ErrNotFound", err)
	}
	if err := r.Activate(ctx, 9999, "op"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("activate missing err = %v, want ErrNotFound", err)
	}
}

// TestRetire: a draining CA with a live dependent is refused; a non-draining CA cannot be
// retired; once the last live leaf is gone the drained CA retires and leaves the trust bundle.
// The live-dependent count is now computed by Retire itself (M8.3), not passed in.
func TestRetire(t *testing.T) {
	s, r := setup(t)
	ctx := context.Background()
	pem1, _, ca1cert, bk1 := mkCAWithBackend(t, "ca-1")
	pem2, _, _, _ := mkCAWithBackend(t, "ca-2")
	ca1, _, _ := r.SeedActive(ctx, "ca-1", pem1, "software", "boot")
	ca2, _ := r.Stage(ctx, "ca-2", pem2, "kms", "op")
	_ = r.Activate(ctx, ca2.ID, "op") // ca-1 -> draining, ca-2 -> active

	// A live leaf still chains to ca-1 -> retire refused (fail-closed drain gate).
	seedEnroll(t, s.DB, "e-live", "issued", mkLeafPEM(t, ca1cert, bk1, "host", time.Now().Add(24*time.Hour)), ca1.Fingerprint)
	if err := r.Retire(ctx, ca1.ID, "op"); !errors.Is(err, ErrHasDependents) {
		t.Fatalf("retire with a live dependent err = %v, want ErrHasDependents", err)
	}
	// A draining CA (here ca-2 is active) cannot be retired.
	if err := r.Retire(ctx, ca2.ID, "op"); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("retire the active CA err = %v, want ErrIllegalTransition", err)
	}
	// The last dependent migrates off ca-1 (renewed to ca-2 / decommissioned) -> retire succeeds.
	if err := s.DB.Table("enrollments").Where("enrollment_id = ?", "e-live").Update("status", "denied").Error; err != nil {
		t.Fatalf("drain the dependent: %v", err)
	}
	if err := r.Retire(ctx, ca1.ID, "op"); err != nil {
		t.Fatalf("retire drained ca-1: %v", err)
	}
	if st := states(t, r); st["ca-1"] != StateRetired {
		t.Fatalf("ca-1 state = %s, want retired", st["ca-1"])
	}
	if tb, _ := r.TrustBundle(ctx); len(tb) != 1 || tb[0] != pem2 {
		t.Fatalf("trust bundle after retire = %v, want only ca-2", tb)
	}
}

// TestAbandonStaged: a staged CA can be cancelled (staged -> retired); a non-staged CA cannot.
func TestAbandonStaged(t *testing.T) {
	_, r := setup(t)
	ctx := context.Background()
	pem, _ := mkCA(t, "ca-x")
	ca, _ := r.Stage(ctx, "ca-x", pem, "kms", "op")
	if err := r.Abandon(ctx, ca.ID, "op"); err != nil {
		t.Fatalf("abandon staged: %v", err)
	}
	if st := states(t, r); st["ca-x"] != StateRetired {
		t.Fatalf("ca-x state = %s, want retired", st["ca-x"])
	}
	if tb, _ := r.TrustBundle(ctx); len(tb) != 0 {
		t.Fatalf("trust bundle = %v, want empty (abandoned)", tb)
	}
	// Abandoning it again (now retired) is illegal.
	if err := r.Abandon(ctx, ca.ID, "op"); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("abandon retired err = %v, want ErrIllegalTransition", err)
	}
}

// TestStageValidation: garbage PEM and duplicates are rejected at the write path.
func TestStageValidation(t *testing.T) {
	_, r := setup(t)
	ctx := context.Background()
	if _, err := r.Stage(ctx, "bad", "not a pem", "kms", "op"); !errors.Is(err, ErrInvalidCert) {
		t.Fatalf("stage garbage err = %v, want ErrInvalidCert", err)
	}
	if _, err := r.Stage(ctx, "", "x", "kms", "op"); !errors.Is(err, ErrEmptyName) {
		t.Fatalf("stage empty name err = %v, want ErrEmptyName", err)
	}
	pem, _ := mkCA(t, "ca-dup")
	if _, err := r.Stage(ctx, "ca-dup", pem, "kms", "op"); err != nil {
		t.Fatal(err)
	}
	// Same fingerprint (same PEM), different name -> duplicate.
	if _, err := r.Stage(ctx, "ca-dup-2", pem, "kms", "op"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("stage duplicate fingerprint err = %v, want ErrDuplicate", err)
	}
	// Same name, different cert -> duplicate.
	pem2, _ := mkCA(t, "whatever")
	if _, err := r.Stage(ctx, "ca-dup", pem2, "kms", "op"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("stage duplicate name err = %v, want ErrDuplicate", err)
	}
}
