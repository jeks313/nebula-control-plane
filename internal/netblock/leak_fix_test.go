package netblock

import (
	"context"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/ipam"
)

// Regression tests for the central-block leak: ordinary clients received overlay IPs inside
// the reserved central /27 (aws-client@10.44.0.3, .4/.5). Two compounding defects, both fixed:
//   (a) the default-fill skip list (Carves) was named-only, so a 'default' range overlapping
//       'central' would bleed into it;
//   (b) a join-source binding that named a reserved block (e.g. "central") allocated from it.
//       The guard lives at ALLOCATION (ipam.Allocate falls a reserved-resolved binding back to
//       'default'); resolution stays TRUTHFUL (central resolves to itself) so allocation
//       PROVENANCE (netblockIDContaining) still records central's real id.

func seedCentralDefault(t *testing.T, r *Registry) {
	t.Helper()
	ctx := context.Background()
	if _, err := r.Seed(ctx, "central", mustP("10.44.0.0/27"), KindReserved, "control-plane", "genesis"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Seed(ctx, NameDefault, mustP("10.44.64.0/18"), KindDefault, "fallback", "genesis"); err != nil {
		t.Fatal(err)
	}
}

// (a) Carves must include the reserved central block (plus named carves), and must NOT
// include the 'default' block being filled.
func TestCarvesIncludesReservedCentral(t *testing.T) {
	ctx := context.Background()
	r := newRegistry(t, "10.44.0.0/16", nil)
	seedCentralDefault(t, r)
	if _, err := r.Add(ctx, "office", mustP("10.44.20.0/24"), "office", "op"); err != nil {
		t.Fatal(err)
	}
	carves, err := r.Carves(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var hasCentral, hasNamed, hasDefault bool
	for _, c := range carves {
		switch c {
		case mustP("10.44.0.0/27"):
			hasCentral = true
		case mustP("10.44.20.0/24"):
			hasNamed = true
		case mustP("10.44.64.0/18"):
			hasDefault = true
		}
	}
	if !hasCentral {
		t.Error("Carves must include the reserved central /27 (else default-fill can bleed into control-plane space)")
	}
	if !hasNamed {
		t.Error("Carves must still include named carves")
	}
	if hasDefault {
		t.Error("Carves must NOT include 'default' itself — that is the block being filled")
	}
}

// (b1) Resolution is TRUTHFUL: a reserved name resolves to ITS OWN block, flagged Reserved — so
// allocation provenance (netblockIDContaining) records central's real id. The leak guard is NOT
// here; it's in ipam.Allocate (see b2).
func TestResolveReservedIsTruthful(t *testing.T) {
	ctx := context.Background()
	r := newRegistry(t, "10.44.0.0/16", nil)
	seedCentralDefault(t, r)

	full, err := r.ResolveFull(ctx, "central")
	if err != nil {
		t.Fatalf("ResolveFull(central): %v", err)
	}
	if full.CIDR != mustP("10.44.0.0/27") || !full.Reserved || full.Named {
		t.Fatalf("ResolveFull(central) = %+v; want central /27, Reserved=true, Named=false (truthful)", full)
	}
	if cidr, err := r.Resolve(ctx, "central"); err != nil || cidr != mustP("10.44.0.0/27") {
		t.Fatalf("Resolve(central) = %s, %v; want the truthful central /27", cidr, err)
	}
	// A named block resolves to itself (Named=true, not Reserved).
	if _, err := r.Add(ctx, "office", mustP("10.44.20.0/24"), "office", "op"); err != nil {
		t.Fatal(err)
	}
	if full, err := r.ResolveFull(ctx, "office"); err != nil || full.CIDR != mustP("10.44.20.0/24") || !full.Named || full.Reserved {
		t.Fatalf("ResolveFull(office) = %+v, %v; want named 10.44.20.0/24 (Named, not Reserved)", full, err)
	}
}

// (b2) The leak guard, end-to-end: a join-source binding that names the reserved 'central' block
// ALLOCATES from 'default', never from central — but the reserved block is still allocatable via
// the control-plane path (AllocateSpecific) for provenance/genesis.
func TestAllocateFromReservedNameFallsBackToDefault(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	r := New(s.DB, mustP("10.44.0.0/16"), nil, &fakeAllocs{}, nil)
	seedCentralDefault(t, r)

	alloc, err := ipam.NewAllocator(s, ipam.Pool{Prefix: mustP("10.44.0.0/16")})
	if err != nil {
		t.Fatal(err)
	}
	alloc = alloc.WithResolver(r)

	ip, err := alloc.Allocate(ctx, "client-x", "central", "token")
	if err != nil {
		t.Fatalf("allocate (central-bound): %v", err)
	}
	if mustP("10.44.0.0/27").Contains(ip) {
		t.Fatalf("client allocated %s INSIDE the reserved central /27 — the leak is not closed", ip)
	}
	if !mustP("10.44.64.0/18").Contains(ip) {
		t.Fatalf("client allocated %s; want it in the 'default' block 10.44.64.0/18", ip)
	}
}
