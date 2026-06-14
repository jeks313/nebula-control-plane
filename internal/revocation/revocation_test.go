package revocation

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

func setup(t *testing.T) (*store.Store, *[]string) {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(filepath.Join(t.TempDir(), "r.db"))})
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

func newReg(s *store.Store, actions *[]string) *Registry {
	audit := func(_ context.Context, _, action, _, _ string) error {
		*actions = append(*actions, action)
		return nil
	}
	return New(s.DB, audit)
}

// TestAddListLiftActive covers the basic lifecycle: add blocklists a fingerprint,
// list shows it, lift removes it from the active set (kept as history), and each
// state-changing op is audited.
func TestAddListLiftActive(t *testing.T) {
	s, actions := setup(t)
	r := newReg(s, actions)
	ctx := context.Background()

	if _, err := r.Add(ctx, "aaaa", "compromised", "admin"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if fps, _ := r.ActiveFingerprints(ctx); len(fps) != 1 || fps[0] != "aaaa" {
		t.Fatalf("active = %v, want [aaaa]", fps)
	}
	if rows, _ := r.List(ctx); len(rows) != 1 || rows[0].State != StateActive || rows[0].Reason != "compromised" {
		t.Fatalf("list = %+v", rows)
	}

	if err := r.Lift(ctx, "aaaa", "admin"); err != nil {
		t.Fatalf("lift: %v", err)
	}
	if fps, _ := r.ActiveFingerprints(ctx); len(fps) != 0 {
		t.Fatalf("active after lift = %v, want []", fps)
	}
	if rows, _ := r.List(ctx); len(rows) != 1 || rows[0].State != StateLifted {
		t.Fatalf("lifted row = %+v", rows)
	}

	// Two state changes (add + lift) → two audit rows.
	if got := *actions; len(got) != 2 || got[0] != "revocation-add" || got[1] != "revocation-lift" {
		t.Fatalf("audit actions = %v, want [revocation-add revocation-lift]", got)
	}
}

// TestAddIdempotentAndReactivate: re-adding an active fingerprint is rejected
// (ErrAlreadyActive), and adding a previously-lifted one re-activates it.
func TestAddIdempotentAndReactivate(t *testing.T) {
	s, actions := setup(t)
	r := newReg(s, actions)
	ctx := context.Background()

	if _, err := r.Add(ctx, "bbbb", "x", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(ctx, "bbbb", "again", "admin"); !errors.Is(err, ErrAlreadyActive) {
		t.Fatalf("re-add active err = %v, want ErrAlreadyActive", err)
	}
	if err := r.Lift(ctx, "bbbb", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(ctx, "bbbb", "reblock", "admin"); err != nil {
		t.Fatalf("re-activate after lift: %v", err)
	}
	if fps, _ := r.ActiveFingerprints(ctx); len(fps) != 1 || fps[0] != "bbbb" {
		t.Fatalf("active after reactivate = %v, want [bbbb]", fps)
	}
	// Still exactly one row (re-activated in place, not duplicated).
	if rows, _ := r.List(ctx); len(rows) != 1 {
		t.Fatalf("want 1 row after reactivate, got %d", len(rows))
	}
}

// TestNormalizationAndSortDeterminism: fingerprints are lowercased/trimmed (so
// the same cert maps to one row) and ActiveFingerprints is sorted (so an
// unchanged blocklist yields a byte-identical bundle and never trips drift).
func TestNormalizationAndSortDeterminism(t *testing.T) {
	s, actions := setup(t)
	r := newReg(s, actions)
	ctx := context.Background()

	// Mixed case + surrounding space normalizes to lowercase hex.
	if _, err := r.Add(ctx, "  ABCD  ", "", "admin"); err != nil {
		t.Fatal(err)
	}
	// A second add of the same cert in a different case is a duplicate, not a new row.
	if _, err := r.Add(ctx, "abcd", "", "admin"); !errors.Is(err, ErrAlreadyActive) {
		t.Fatalf("case-variant re-add err = %v, want ErrAlreadyActive (normalized dup)", err)
	}

	// Insert out of order; ActiveFingerprints must come back sorted ascending.
	for _, fp := range []string{"ffff", "0000"} {
		if _, err := r.Add(ctx, fp, "", "admin"); err != nil {
			t.Fatal(err)
		}
	}
	fps, _ := r.ActiveFingerprints(ctx)
	if strings.Join(fps, ",") != "0000,abcd,ffff" {
		t.Fatalf("active = %v, want sorted [0000 abcd ffff]", fps)
	}
}

func TestAddEmptyFingerprintRejected(t *testing.T) {
	s, actions := setup(t)
	r := newReg(s, actions)
	if _, err := r.Add(context.Background(), "   ", "", "admin"); !errors.Is(err, ErrNoFingerprint) {
		t.Fatalf("err = %v, want ErrNoFingerprint", err)
	}
}
