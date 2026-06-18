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
	// An unknown name now falls back to default (D20), not ErrNotFound.
	if got, err := r.Resolve(ctx, "nope"); err != nil || got != mustP("10.44.64.0/18") {
		t.Fatalf("Resolve(nope) = %s, %v; want default 10.44.64.0/18 (fallback)", got, err)
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

// TestRegistrySnapshotGenGuard exercises the lost-update race directly: a mutation
// that bumps r.gen while a snapshot is in flight (between the unlocked List and the
// re-acquire) must NOT let the stale snapshot poison the cache — the next reader must
// see the mutation. We simulate the in-flight snapshot by manipulating r.gen under the
// lock the same way invalidate() does, then assert a freshly built cache published with
// a now-stale startGen is rejected.
func TestRegistrySnapshotGenGuard(t *testing.T) {
	ctx := context.Background()
	r := newRegistry(t, "10.44.0.0/16", nil)
	if _, err := r.Add(ctx, "a", mustP("10.44.1.0/24"), "", "op"); err != nil {
		t.Fatal(err)
	}
	// Warm + read the cache once.
	if _, err := r.Carves(ctx); err != nil {
		t.Fatal(err)
	}

	// Capture the current gen, then simulate a snapshot that started against this gen
	// while a mutation invalidates mid-build.
	r.mu.Lock()
	startGen := r.gen
	r.mu.Unlock()

	// A concurrent mutation invalidates: cache=nil, gen++.
	r.invalidate()

	// Now a stale snapshot finishing its build sees gen != startGen and must leave the
	// cache nil. Build a bogus stale cache and try to publish it under the stale gen.
	stale := &resolverCache{byName: map[string]netip.Prefix{}, rows: map[string]Netblock{}}
	r.mu.Lock()
	if r.gen == startGen {
		r.cache = stale
	}
	cacheAfter := r.cache
	r.mu.Unlock()
	if cacheAfter != nil {
		t.Fatalf("stale snapshot poisoned the cache; want cache=nil so the next reader rebuilds")
	}

	// The next real read must rebuild from the table and still see the carve.
	carves, err := r.Carves(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(carves) != 1 || carves[0] != mustP("10.44.1.0/24") {
		t.Fatalf("after gen-guarded invalidate, Carves = %v, want [10.44.1.0/24]", carves)
	}
}

func TestRegistryResolveUnknownFallsBackToDefault(t *testing.T) {
	ctx := context.Background()
	r := newRegistry(t, "10.44.0.0/16", nil)
	if _, err := r.Seed(ctx, NameDefault, mustP("10.44.64.0/18"), KindDefault, "fallback", "genesis"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(ctx, "office", mustP("10.44.20.0/24"), "", "op"); err != nil {
		t.Fatal(err)
	}

	// An unknown/deleted/typo'd non-empty name resolves to the default CIDR (D20) —
	// it must NOT return ErrNotFound (that would break enrollment for a stale binding).
	got, err := r.Resolve(ctx, "does-not-exist")
	if err != nil {
		t.Fatalf("Resolve(does-not-exist) err = %v, want nil (fall back to default)", err)
	}
	if got != mustP("10.44.64.0/18") {
		t.Fatalf("Resolve(does-not-exist) = %s, want default 10.44.64.0/18", got)
	}

	// ResolveFull on an unknown name resolves to default's identity, and crucially
	// Named=false so an unknown binding is NOT auto-grow-eligible.
	full, err := r.ResolveFull(ctx, "does-not-exist")
	if err != nil {
		t.Fatalf("ResolveFull(does-not-exist) err = %v, want nil", err)
	}
	if full.Name != NameDefault || full.CIDR != mustP("10.44.64.0/18") {
		t.Fatalf("ResolveFull(does-not-exist) = %+v, want default block", full)
	}
	if full.Named {
		t.Fatalf("ResolveFull(does-not-exist).Named = true, want false (unknown name must not be auto-grow-eligible)")
	}

	// Deleting a referenced block also falls back (the runtime-fallback contract).
	if err := r.Remove(ctx, "office", "op"); err != nil {
		t.Fatal(err)
	}
	got, err = r.Resolve(ctx, "office")
	if err != nil || got != mustP("10.44.64.0/18") {
		t.Fatalf("Resolve(office) after delete = %s, %v; want default", got, err)
	}
}

func TestRegistryResolveErrNotFoundWhenDefaultMissing(t *testing.T) {
	ctx := context.Background()
	r := newRegistry(t, "10.44.0.0/16", nil)
	// No default seeded: a name miss has nowhere to fall back to.
	if _, err := r.Resolve(ctx, "office"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Resolve with no default err = %v, want ErrNotFound", err)
	}
	if _, err := r.ResolveFull(ctx, "office"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ResolveFull with no default err = %v, want ErrNotFound", err)
	}
}

// countingAudit records every (action) it sees, for the audit-count assertions.
type countingAudit struct{ actions []string }

func (c *countingAudit) fn(ctx context.Context, actor, action, target, details string) error {
	c.actions = append(c.actions, action)
	return nil
}

func (c *countingAudit) count(action string) int {
	n := 0
	for _, a := range c.actions {
		if a == action {
			n++
		}
	}
	return n
}

func TestRegistryAuditOnGrowNotOnCRUD(t *testing.T) {
	ctx := context.Background()
	ca := &countingAudit{}
	r := New(newStore(t).DB, mustP("10.44.0.0/16"), nil, &fakeAllocs{}, ca.fn)

	if _, err := r.Add(ctx, "office", mustP("10.44.1.0/27"), "", "op"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Update(ctx, "office", mustP("10.44.1.0/27"), "edited", "op"); err != nil {
		t.Fatal(err)
	}
	// CRUD must NOT be audited by the registry (the handler audits with the principal).
	if got := ca.count("netblock-add") + ca.count("netblock-update"); got != 0 {
		t.Fatalf("registry audited CRUD %d time(s), want 0 (handler owns CRUD audit)", got)
	}

	// Grow MUST be audited by the registry (auto-grow has no handler/principal).
	if _, err := r.Grow(ctx, "office", "ipam-autogrow"); err != nil {
		t.Fatal(err)
	}
	if got := ca.count("netblock-autogrow"); got != 1 {
		t.Fatalf("Grow audited %d time(s), want exactly 1", got)
	}

	if err := r.Remove(ctx, "office", "op"); err != nil {
		t.Fatal(err)
	}
	if got := ca.count("netblock-remove"); got != 0 {
		t.Fatalf("registry audited remove %d time(s), want 0", got)
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
