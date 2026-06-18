package ipam

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// fakeResolver is an in-memory NetblockResolver + IDResolver + NetblockGrower for
// exercising the allocator's netblock-aware paths without the DB-backed registry
// (which would create an import cycle: netblock imports ipam).
type fakeResolver struct {
	byName map[string]Resolved
	grows  int
}

func (f *fakeResolver) Resolve(ctx context.Context, name string) (netip.Prefix, error) {
	r, err := f.ResolveFull(ctx, name)
	return r.CIDR, err
}

func (f *fakeResolver) ResolveFull(ctx context.Context, name string) (Resolved, error) {
	if name == "" {
		name = NameDefault
	}
	r, ok := f.byName[name]
	if !ok {
		return Resolved{}, errors.New("fake: unknown netblock " + name)
	}
	return r, nil
}

func (f *fakeResolver) Carves(ctx context.Context) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, r := range f.byName {
		if r.Named {
			out = append(out, r.CIDR)
		}
	}
	return out, nil
}

// Grow doubles a named block in place (test stand-in for the registry's buddy
// check) by counting up; the block's CIDR widens one bit per call.
func (f *fakeResolver) Grow(ctx context.Context, name, actor string) (netip.Prefix, error) {
	r := f.byName[name]
	if r.CIDR.Bits() <= 0 {
		return netip.Prefix{}, errors.New("fake: cannot grow")
	}
	next := netip.PrefixFrom(r.CIDR.Addr(), r.CIDR.Bits()-1).Masked()
	if next.Addr() != r.CIDR.Addr() {
		return netip.Prefix{}, errors.New("fake: not lower half")
	}
	r.CIDR = next
	f.byName[name] = r
	f.grows++
	return next, nil
}

func TestAllocateWithResolverProvenance(t *testing.T) {
	ctx := context.Background()
	res := &fakeResolver{byName: map[string]Resolved{
		NameDefault: {ID: 2, Name: NameDefault, CIDR: netip.MustParsePrefix("10.44.64.0/18")},
		"office":    {ID: 3, Name: "office", CIDR: netip.MustParsePrefix("10.44.20.0/24"), Named: true},
	}}
	a := newAllocator(t, Pool{Prefix: netip.MustParsePrefix("10.44.0.0/16")}).WithResolver(res)

	ip, err := a.Allocate(ctx, "host-1", "office", "token")
	if err != nil {
		t.Fatal(err)
	}
	if !netip.MustParsePrefix("10.44.20.0/24").Contains(ip) {
		t.Fatalf("office alloc %s not in 10.44.20.0/24", ip)
	}
	// Provenance: netblock_id + method persisted.
	var got Allocation
	if err := a.db.Where("ip = ?", ip.String()).First(&got).Error; err != nil {
		t.Fatal(err)
	}
	if got.NetblockID != 3 || got.Method != "token" {
		t.Fatalf("provenance = (id %d, method %q), want (3, token)", got.NetblockID, got.Method)
	}

	// Empty name -> default block.
	defIP, err := a.Allocate(ctx, "host-2", "", "aws-sigv4")
	if err != nil {
		t.Fatal(err)
	}
	if !netip.MustParsePrefix("10.44.64.0/18").Contains(defIP) {
		t.Fatalf("default alloc %s not in 10.44.64.0/18", defIP)
	}
}

// TestDefaultFillSkipsNamedCarves: a 'named' carve nested inside the default range
// must never be bled into when filling 'default'.
func TestDefaultFillSkipsNamedCarves(t *testing.T) {
	ctx := context.Background()
	// default = 10.44.0.0/24; a named carve 10.44.0.0/26 sits inside it.
	res := &fakeResolver{byName: map[string]Resolved{
		NameDefault: {ID: 1, Name: NameDefault, CIDR: netip.MustParsePrefix("10.44.0.0/24")},
		"carve":     {ID: 2, Name: "carve", CIDR: netip.MustParsePrefix("10.44.0.0/26"), Named: true},
	}}
	a := newAllocator(t, Pool{Prefix: netip.MustParsePrefix("10.44.0.0/16")}).WithResolver(res)

	ip, err := a.Allocate(ctx, "host-1", "", "token")
	if err != nil {
		t.Fatal(err)
	}
	// The first free default address must be ABOVE the /26 carve (10.44.0.64).
	if ip != netip.MustParseAddr("10.44.0.64") {
		t.Fatalf("default fill = %s, want 10.44.0.64 (skipping the /26 carve)", ip)
	}
}

// TestAutoGrowOnExhaustion: a full named block grows into its free buddy and the
// allocation then succeeds in the grown range.
func TestAutoGrowOnExhaustion(t *testing.T) {
	ctx := context.Background()
	// office = /29 -> usable .1..7 (network .0 skipped). Fill all 7, then the 8th
	// triggers a grow to /28 and succeeds.
	res := &fakeResolver{byName: map[string]Resolved{
		"office": {ID: 5, Name: "office", CIDR: netip.MustParsePrefix("10.44.8.0/29"), Named: true},
	}}
	a := newAllocator(t, Pool{Prefix: netip.MustParsePrefix("10.44.0.0/16")}).WithResolver(res)

	for i := 0; i < 7; i++ {
		if _, err := a.Allocate(ctx, "h"+string(rune('a'+i)), "office", "token"); err != nil {
			t.Fatalf("alloc %d: %v", i, err)
		}
	}
	if res.grows != 0 {
		t.Fatalf("grew before exhaustion (grows=%d)", res.grows)
	}
	// 8th allocation: /29 is full -> auto-grow to /28, allocate in the new upper half.
	ip, err := a.Allocate(ctx, "h8", "office", "token")
	if err != nil {
		t.Fatalf("auto-grow alloc: %v", err)
	}
	if res.grows != 1 {
		t.Fatalf("expected exactly 1 grow, got %d", res.grows)
	}
	if !netip.MustParsePrefix("10.44.8.0/28").Contains(ip) {
		t.Fatalf("grown alloc %s not in 10.44.8.0/28", ip)
	}
	if ip != netip.MustParseAddr("10.44.8.8") {
		t.Fatalf("grown alloc = %s, want 10.44.8.8 (first addr in the new buddy)", ip)
	}
}

// TestNoAutoGrowForDefault: default/central (Named=false) never auto-grow — a full
// block returns ErrPoolExhausted.
func TestNoAutoGrowForDefault(t *testing.T) {
	ctx := context.Background()
	res := &fakeResolver{byName: map[string]Resolved{
		NameDefault: {ID: 1, Name: NameDefault, CIDR: netip.MustParsePrefix("10.44.0.0/30")}, // .1..3
	}}
	a := newAllocator(t, Pool{Prefix: netip.MustParsePrefix("10.44.0.0/16")}).WithResolver(res)
	for i := 0; i < 3; i++ {
		if _, err := a.Allocate(ctx, "d"+string(rune('a'+i)), "", "token"); err != nil {
			t.Fatalf("alloc %d: %v", i, err)
		}
	}
	if _, err := a.Allocate(ctx, "overflow", "", "token"); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("default overflow err = %v, want ErrPoolExhausted", err)
	}
	if res.grows != 0 {
		t.Fatalf("default must not auto-grow (grows=%d)", res.grows)
	}
}

func TestAllocateSpecificMethod(t *testing.T) {
	ctx := context.Background()
	a := newAllocator(t, Pool{Prefix: netip.MustParsePrefix("10.44.0.0/16")})
	if err := a.AllocateSpecific(ctx, "lighthouse", netip.MustParseAddr("10.44.0.1"), "genesis"); err != nil {
		t.Fatal(err)
	}
	var got Allocation
	if err := a.db.Where("ip = ?", "10.44.0.1").First(&got).Error; err != nil {
		t.Fatal(err)
	}
	if got.Method != "genesis" {
		t.Fatalf("method = %q, want genesis", got.Method)
	}
}
