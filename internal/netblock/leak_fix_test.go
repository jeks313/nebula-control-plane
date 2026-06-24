package netblock

import (
	"context"
	"testing"
)

// Regression tests for the central-block leak: ordinary clients received overlay IPs inside
// the reserved central /27 (aws-client@10.44.0.3, .4/.5). Two compounding defects, both fixed:
//   (a) the default-fill skip list (Carves) was named-only, so a 'default' range overlapping
//       'central' would bleed into it;
//   (b) a join-source name resolving to a reserved block (e.g. "central") returned central's
//       /27 instead of falling back to 'default'.

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

// (b) A join-source name resolving to a RESERVED block falls back to 'default' (bounded,
// Named=false) — reserved control-plane space is never handed out by name-resolution.
func TestResolveReservedNameFallsBackToDefault(t *testing.T) {
	ctx := context.Background()
	r := newRegistry(t, "10.44.0.0/16", nil)
	seedCentralDefault(t, r)

	full, err := r.ResolveFull(ctx, "central")
	if err != nil {
		t.Fatalf("ResolveFull(central): %v", err)
	}
	if full.CIDR != mustP("10.44.64.0/18") {
		t.Fatalf("ResolveFull(central).CIDR = %s, want default 10.44.64.0/18 (reserved must not resolve to its /27)", full.CIDR)
	}
	if full.Named {
		t.Error("the fallback must be Named=false (bounded default, not auto-grow-eligible)")
	}
	if cidr, err := r.Resolve(ctx, "central"); err != nil || cidr != mustP("10.44.64.0/18") {
		t.Fatalf("Resolve(central) = %s, %v; want default 10.44.64.0/18", cidr, err)
	}
	// A real named block still resolves to itself (the guard is reserved-only).
	if _, err := r.Add(ctx, "office", mustP("10.44.20.0/24"), "office", "op"); err != nil {
		t.Fatal(err)
	}
	if full, err := r.ResolveFull(ctx, "office"); err != nil || full.CIDR != mustP("10.44.20.0/24") || !full.Named {
		t.Fatalf("ResolveFull(office) = %+v, %v; want the named 10.44.20.0/24", full, err)
	}
}
