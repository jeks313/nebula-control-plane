package config

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

func setup(t *testing.T) (*store.Store, *[]string) {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(filepath.Join(t.TempDir(), "c.db"))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	var actions []string
	return s, &actions
}

func newStore(s *store.Store, actions *[]string) *Store {
	audit := func(_ context.Context, _, action, _, _ string) error {
		*actions = append(*actions, action)
		return nil
	}
	return New(s.DB, audit)
}

const kind = "policy.publish"

// TestGetAbsentReturnsNilNil: Get on an unwritten kind is (nil, nil) — absent is not
// an error.
func TestGetAbsentReturnsNilNil(t *testing.T) {
	s, actions := setup(t)
	cs := newStore(s, actions)
	row, err := cs.Get(context.Background(), kind)
	if err != nil {
		t.Fatalf("Get absent: unexpected err %v", err)
	}
	if row != nil {
		t.Fatalf("Get absent = %v, want nil", row)
	}
}

// TestSetIncrementsVersionAndAudits: each Set bumps the version, persists the payload,
// and writes exactly one audit row per write (atomic — same tx).
func TestSetIncrementsVersionAndAudits(t *testing.T) {
	s, actions := setup(t)
	cs := newStore(s, actions)
	ctx := context.Background()

	row, err := cs.Set(ctx, kind, []byte("v1"), "alice")
	if err != nil {
		t.Fatalf("Set #1: %v", err)
	}
	if row.Version != 1 || string(row.Payload) != "v1" || row.UpdatedBy != "alice" {
		t.Fatalf("Set #1 row = %+v, want version 1 payload v1 by alice", row)
	}

	row2, err := cs.Set(ctx, kind, []byte("v2"), "bob")
	if err != nil {
		t.Fatalf("Set #2: %v", err)
	}
	if row2.Version != 2 || string(row2.Payload) != "v2" || row2.UpdatedBy != "bob" {
		t.Fatalf("Set #2 row = %+v, want version 2 payload v2 by bob", row2)
	}

	got, err := cs.Get(ctx, kind)
	if err != nil || got == nil {
		t.Fatalf("Get after Set: %v %v", got, err)
	}
	if got.Version != 2 || string(got.Payload) != "v2" {
		t.Fatalf("Get after Set = %+v, want version 2 payload v2", got)
	}

	// One audit row per Set (atomic — the audit is in the same tx).
	count := 0
	for _, a := range *actions {
		if a == ActionSet {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("audit %q count = %d, want 2 (one per Set)", ActionSet, count)
	}
}

// TestSetSurfacesAuditFailure: an audit-append failure surfaces as a Set error (the
// row write itself committed first — the audit hash-chain runs its own serialized tx,
// matching every other audited writer in the codebase).
func TestSetSurfacesAuditFailure(t *testing.T) {
	s, _ := setup(t)
	failAudit := func(_ context.Context, _, _, _, _ string) error {
		return context.Canceled // simulate an audit failure
	}
	cs := New(s.DB, failAudit)
	ctx := context.Background()

	if _, err := cs.Set(ctx, kind, []byte("v1"), "alice"); err == nil {
		t.Fatal("Set with a failing audit: expected an error, got nil")
	}
}

// TestSeedIfEmptyOnlyIfAbsent: SeedIfEmpty inserts when absent (returns true) and is a
// no-op when a row already exists (returns false, leaves the existing row untouched).
func TestSeedIfEmptyOnlyIfAbsent(t *testing.T) {
	s, actions := setup(t)
	cs := newStore(s, actions)
	ctx := context.Background()

	seeded, err := cs.SeedIfEmpty(ctx, kind, []byte("seed"), "migration")
	if err != nil || !seeded {
		t.Fatalf("SeedIfEmpty (absent) = %v %v, want true nil", seeded, err)
	}
	row, _ := cs.Get(ctx, kind)
	if row == nil || string(row.Payload) != "seed" || row.Version != 1 {
		t.Fatalf("seeded row = %+v, want payload seed version 1", row)
	}

	// A second seed is a no-op — the existing row is untouched.
	seeded, err = cs.SeedIfEmpty(ctx, kind, []byte("OTHER"), "migration")
	if err != nil || seeded {
		t.Fatalf("SeedIfEmpty (present) = %v %v, want false nil", seeded, err)
	}
	row, _ = cs.Get(ctx, kind)
	if string(row.Payload) != "seed" {
		t.Fatalf("seed overwrote existing row: %+v", row)
	}

	// SeedIfEmpty does not audit (distinct from operator Set).
	for _, a := range *actions {
		if a == ActionSet {
			t.Fatalf("SeedIfEmpty wrote an audit row (%q) — it must not", a)
		}
	}
}

// TestErrNoKind: an empty kind is rejected on every entry point.
func TestErrNoKind(t *testing.T) {
	s, actions := setup(t)
	cs := newStore(s, actions)
	ctx := context.Background()
	if _, err := cs.Get(ctx, ""); err != ErrNoKind {
		t.Fatalf("Get empty kind = %v, want ErrNoKind", err)
	}
	if _, err := cs.Set(ctx, "", []byte("x"), "a"); err != ErrNoKind {
		t.Fatalf("Set empty kind = %v, want ErrNoKind", err)
	}
	if _, err := cs.SeedIfEmpty(ctx, "", []byte("x"), "a"); err != ErrNoKind {
		t.Fatalf("SeedIfEmpty empty kind = %v, want ErrNoKind", err)
	}
}
