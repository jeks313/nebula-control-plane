package joinkey

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := store.DefaultSQLiteDSN(filepath.Join(t.TempDir(), "h.db"))
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCreateAndConsumeOnce(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	secret, jk, err := Create(ctx, s, Params{Name: "k1", Groups: []string{"web"}, MaxUses: 1}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if jk.AutoIssue {
		t.Fatal("auto_issue must default to false")
	}
	got, err := ValidateAndConsume(ctx, s, secret, time.Now())
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if g := got.GroupList(); len(g) != 1 || g[0] != "web" {
		t.Fatalf("groups = %v", g)
	}
	// Second use of a one-time key is exhausted.
	if _, err := ValidateAndConsume(ctx, s, secret, time.Now()); !errors.Is(err, ErrExhausted) {
		t.Fatalf("err = %v, want ErrExhausted", err)
	}
}

func TestReusableKey(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	secret, _, _ := Create(ctx, s, Params{Name: "reusable", MaxUses: 0}, time.Now())
	for i := 0; i < 5; i++ {
		if _, err := ValidateAndConsume(ctx, s, secret, time.Now()); err != nil {
			t.Fatalf("use %d: %v", i, err)
		}
	}
}

func TestExpiredKey(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	secret, _, _ := Create(ctx, s, Params{Name: "exp", MaxUses: 0, TTL: time.Minute}, time.Now())
	future := time.Now().Add(2 * time.Minute)
	if _, err := ValidateAndConsume(ctx, s, secret, future); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

func TestRevokeBlocksUse(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	secret, _, _ := Create(ctx, s, Params{Name: "rev", MaxUses: 0}, time.Now())
	if err := Revoke(ctx, s, "rev"); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateAndConsume(ctx, s, secret, time.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound after revoke", err)
	}
	if err := Revoke(ctx, s, "rev"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("re-revoke err = %v, want ErrNotFound", err)
	}
}

func TestUnknownSecret(t *testing.T) {
	s := newStore(t)
	if _, err := ValidateAndConsume(context.Background(), s, "njk_bogus", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
