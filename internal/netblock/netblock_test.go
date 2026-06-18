package netblock

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := store.DefaultSQLiteDSN(filepath.Join(t.TempDir(), "harbor.db"))
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

// fakeAllocs is a test allocationLister returning a fixed live set.
type fakeAllocs struct{ live []netip.Addr }

func (f *fakeAllocs) LiveAddrs(ctx context.Context) ([]netip.Addr, error) { return f.live, nil }

func newRegistry(t *testing.T, pool string, allocs allocationLister) *Registry {
	t.Helper()
	return New(newStore(t).DB, mustP(pool), nil, allocs, nil)
}

func TestRegistryAddListResolve(t *testing.T) {
	ctx := context.Background()
	r := newRegistry(t, "10.44.0.0/16", nil)
	if _, err := r.Seed(ctx, NameDefault, mustP("10.44.64.0/18"), KindDefault, "fallback", "genesis"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(ctx, "office", mustP("10.44.20.0/24"), "office vpn", "op"); err != nil {
		t.Fatal(err)
	}

	// Resolve by name, and "" -> default.
	got, err := r.Resolve(ctx, "office")
	if err != nil || got != mustP("10.44.20.0/24") {
		t.Fatalf("Resolve(office) = %s, %v", got, err)
	}
	def, err := r.Resolve(ctx, "")
	if err != nil || def != mustP("10.44.64.0/18") {
		t.Fatalf(`Resolve("") = %s, %v; want default`, def, err)
	}
	if _, err := r.Resolve(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Resolve(nope) err = %v, want ErrNotFound", err)
	}

	// Carves returns only named.
	carves, err := r.Carves(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(carves) != 1 || carves[0] != mustP("10.44.20.0/24") {
		t.Fatalf("Carves = %v, want [10.44.20.0/24]", carves)
	}

	rows, err := r.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("List len = %d, want 2", len(rows))
	}
}

func TestRegistryValidation(t *testing.T) {
	ctx := context.Background()
	r := newRegistry(t, "10.44.0.0/16", nil)
	if _, err := r.Add(ctx, "ok", mustP("10.44.10.0/24"), "", "op"); err != nil {
		t.Fatal(err)
	}

	// Out of pool.
	if _, err := r.Add(ctx, "elsewhere", mustP("10.99.0.0/24"), "", "op"); !errors.Is(err, ErrOutOfPool) {
		t.Fatalf("out-of-pool err = %v, want ErrOutOfPool", err)
	}
	// Overlap with the existing carve.
	if _, err := r.Add(ctx, "overlap", mustP("10.44.10.128/25"), "", "op"); !errors.Is(err, ErrOverlap) {
		t.Fatalf("overlap err = %v, want ErrOverlap", err)
	}
	// Duplicate name.
	if _, err := r.Add(ctx, "ok", mustP("10.44.11.0/24"), "", "op"); !errors.Is(err, ErrExists) {
		t.Fatalf("dup name err = %v, want ErrExists", err)
	}
	// Empty name.
	if _, err := r.Add(ctx, "", mustP("10.44.12.0/24"), "", "op"); !errors.Is(err, ErrNoName) {
		t.Fatalf("empty name err = %v, want ErrNoName", err)
	}
	// Reserved names rejected via Add.
	if _, err := r.Add(ctx, NameCentral, mustP("10.44.0.0/27"), "", "op"); !errors.Is(err, ErrReservedKind) {
		t.Fatalf("central via Add err = %v, want ErrReservedKind", err)
	}
}

func TestRegistryProtectedAndStranding(t *testing.T) {
	ctx := context.Background()
	// One live allocation at 10.44.20.5 (inside the office block).
	allocs := &fakeAllocs{live: []netip.Addr{netip.MustParseAddr("10.44.20.5")}}
	r := newRegistry(t, "10.44.0.0/16", allocs)
	if _, err := r.Seed(ctx, NameCentral, mustP("10.44.0.0/27"), KindReserved, "", "genesis"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(ctx, "office", mustP("10.44.20.0/24"), "", "op"); err != nil {
		t.Fatal(err)
	}

	// Protected central refuses edit + remove.
	if _, err := r.Update(ctx, NameCentral, mustP("10.44.0.0/26"), "", "op"); !errors.Is(err, ErrProtected) {
		t.Fatalf("update central err = %v, want ErrProtected", err)
	}
	if err := r.Remove(ctx, NameCentral, "op"); !errors.Is(err, ErrProtected) {
		t.Fatalf("remove central err = %v, want ErrProtected", err)
	}

	// Editing office to a range that excludes the live alloc is blocked.
	if _, err := r.Update(ctx, "office", mustP("10.44.21.0/24"), "", "op"); !errors.Is(err, ErrStranded) {
		t.Fatalf("stranding edit err = %v, want ErrStranded", err)
	}
	// Removing office (which holds a live alloc) is blocked.
	if err := r.Remove(ctx, "office", "op"); !errors.Is(err, ErrStranded) {
		t.Fatalf("stranding remove err = %v, want ErrStranded", err)
	}
	// A widening edit that still contains the live alloc is allowed.
	if _, err := r.Update(ctx, "office", mustP("10.44.20.0/23"), "", "op"); err != nil {
		t.Fatalf("widening edit err = %v, want nil", err)
	}
}

func TestRegistryRemoveCleanBlock(t *testing.T) {
	ctx := context.Background()
	r := newRegistry(t, "10.44.0.0/16", &fakeAllocs{})
	if _, err := r.Add(ctx, "tmp", mustP("10.44.30.0/24"), "", "op"); err != nil {
		t.Fatal(err)
	}
	if err := r.Remove(ctx, "tmp", "op"); err != nil {
		t.Fatalf("remove clean block err = %v", err)
	}
	if _, err := r.Get(ctx, "tmp"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after remove err = %v, want ErrNotFound", err)
	}
}

func TestRegistrySeedIdempotent(t *testing.T) {
	ctx := context.Background()
	r := newRegistry(t, "10.44.0.0/16", nil)
	a, err := r.Seed(ctx, NameDefault, mustP("10.44.64.0/18"), KindDefault, "", "genesis")
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.Seed(ctx, NameDefault, mustP("10.44.64.0/18"), KindDefault, "", "genesis")
	if err != nil {
		t.Fatalf("re-seed err = %v, want nil (idempotent)", err)
	}
	if a.ID != b.ID {
		t.Fatalf("re-seed created a new row (%d != %d)", a.ID, b.ID)
	}
}

func TestRegistryGrow(t *testing.T) {
	ctx := context.Background()
	r := newRegistry(t, "10.44.0.0/16", &fakeAllocs{})
	if _, err := r.Add(ctx, "office", mustP("10.44.1.0/27"), "", "op"); err != nil {
		t.Fatal(err)
	}
	// Buddy 10.44.1.32/27 is free -> grow to /26 in place (same network address).
	grown, err := r.Grow(ctx, "office", "op")
	if err != nil {
		t.Fatalf("grow err = %v", err)
	}
	if grown != mustP("10.44.1.0/26") {
		t.Fatalf("grown = %s, want 10.44.1.0/26", grown)
	}
	got, _ := r.Resolve(ctx, "office")
	if got != mustP("10.44.1.0/26") {
		t.Fatalf("resolve after grow = %s, want 10.44.1.0/26", got)
	}

	// Grow again -> /25 (buddy 10.44.1.64/26 free).
	grown, err = r.Grow(ctx, "office", "op")
	if err != nil || grown != mustP("10.44.1.0/25") {
		t.Fatalf("second grow = %s, %v; want 10.44.1.0/25", grown, err)
	}
}

func TestRegistryGrowBlockedByOccupiedBuddy(t *testing.T) {
	ctx := context.Background()
	r := newRegistry(t, "10.44.0.0/16", &fakeAllocs{})
	if _, err := r.Add(ctx, "office", mustP("10.44.1.0/27"), "", "op"); err != nil {
		t.Fatal(err)
	}
	// Carve the buddy 10.44.1.32/27 with another block -> grow must fail.
	if _, err := r.Add(ctx, "neighbor", mustP("10.44.1.32/27"), "", "op"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Grow(ctx, "office", "op"); !errors.Is(err, ErrPoolFull) {
		t.Fatalf("grow with occupied buddy err = %v, want ErrPoolFull", err)
	}
}

func TestRegistryCacheInvalidation(t *testing.T) {
	ctx := context.Background()
	r := newRegistry(t, "10.44.0.0/16", nil)
	if _, err := r.Seed(ctx, NameDefault, mustP("10.44.64.0/18"), KindDefault, "", "genesis"); err != nil {
		t.Fatal(err)
	}
	// Warm the cache.
	if _, err := r.Carves(ctx); err != nil {
		t.Fatal(err)
	}
	// Add a carve -> cache must reflect it immediately.
	if _, err := r.Add(ctx, "office", mustP("10.44.20.0/24"), "", "op"); err != nil {
		t.Fatal(err)
	}
	carves, err := r.Carves(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(carves) != 1 {
		t.Fatalf("after add, Carves len = %d, want 1 (cache not invalidated?)", len(carves))
	}
}
