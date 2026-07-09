package coreapi

import (
	"context"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/policy"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

// TestKeepReservedGroups is the renew CHOKEPOINT guard: a reduction must never strip a reserved
// group off a node that holds it (that would drop its baseline-accept firewall and brick the
// fleet). It must, however, leave a normal reduction alone.
func TestKeepReservedGroups(t *testing.T) {
	cp, lh := policy.GroupControlPlane, policy.GroupLighthouse
	cases := []struct {
		name     string
		issued   []string
		desired  []string
		wantKept []string
	}{
		{"strip control-plane refused", []string{cp, "x"}, []string{"prod"}, []string{cp}},
		{"strip lighthouse refused", []string{lh}, []string{}, []string{lh}},
		{"normal reduction allowed", []string{"laptops", "x"}, []string{"laptops"}, nil},
		{"non-reserved addition", []string{"laptops"}, []string{"laptops", "prod"}, nil},
		{"control-plane retained when kept", []string{cp}, []string{cp, "extra"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, kept := keepReservedGroups(c.issued, c.desired)
			// Invariant: any reserved group the live cert held must survive into the signed set.
			for _, g := range c.issued {
				if policy.IsReservedGroup(g) && !containsGroup(got, g) {
					t.Errorf("chokepoint dropped reserved group %q: got=%v", g, got)
				}
			}
			// We only ADD reserved groups, never drop a desired one.
			for _, g := range c.desired {
				if !containsGroup(got, g) {
					t.Errorf("dropped desired group %q: got=%v", g, got)
				}
			}
			if len(kept) != len(c.wantKept) {
				t.Errorf("kept=%v want %v", kept, c.wantKept)
			}
		})
	}
}

// TestGroupsReduced distinguishes a reduction (soft until revoked) from a pure addition.
func TestGroupsReduced(t *testing.T) {
	cases := []struct {
		old, new []string
		want     bool
	}{
		{[]string{"a", "b"}, []string{"a"}, true},       // dropped b
		{[]string{"a"}, []string{"a", "b"}, false},      // pure addition
		{[]string{"a"}, []string{"a"}, false},           // unchanged
		{[]string{"a", "b"}, []string{"b", "a"}, false}, // reorder only
		{[]string{}, []string{"a"}, false},              // first grant
		{[]string{"a"}, []string{}, true},               // dropped to none
	}
	for _, c := range cases {
		if got := groupsReduced(c.old, c.new); got != c.want {
			t.Errorf("groupsReduced(%v,%v)=%v want %v", c.old, c.new, got, c.want)
		}
	}
}

// TestCommandsForRegroupTrigger: a pending reassignment (groups_generation > issued_generation)
// triggers a CmdRenew, an up-to-date device does not, and a host that is BOTH near-expiry and
// pending gets exactly one CmdRenew (deduped).
func TestCommandsForRegroupTrigger(t *testing.T) {
	f := newCoreFixture(t)
	ctx := context.Background()
	count := func(cmds []wire.Command) (n int) {
		for _, c := range cmds {
			if c.Type == wire.CmdRenew {
				n++
			}
		}
		return n
	}

	// Rollout is nil + RenewCommandThreshold 0 in the fixture, so only the regroup trigger fires.
	if n := count(f.srv.commandsFor(ctx, "100.64.0.1", "", "", 0, 0, 0, 0, 0 /*certNotAfter*/, 2 /*groupsGen*/, 1 /*issuedGen*/)); n != 1 {
		t.Fatalf("pending regroup: want 1 CmdRenew, got %d", n)
	}
	if n := count(f.srv.commandsFor(ctx, "100.64.0.1", "", "", 0, 0, 0, 0, 0, 1, 1)); n != 0 {
		t.Fatalf("converged device: want 0 CmdRenew, got %d", n)
	}

	// Near-expiry AND pending → still exactly one CmdRenew (no duplicate).
	f.srv.cfg.RenewCommandThreshold = time.Hour
	nearExpiry := time.Now().Add(time.Minute).UnixNano()
	if n := count(f.srv.commandsFor(ctx, "100.64.0.1", "", "", 0, 0, 0, 0, nearExpiry, 2, 1)); n != 1 {
		t.Fatalf("near-expiry + pending: want exactly 1 CmdRenew (deduped), got %d", n)
	}
}
