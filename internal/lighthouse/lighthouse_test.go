package lighthouse_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/lighthouse"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

func newReg(t *testing.T) *lighthouse.Registry {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(t.TempDir() + "/lh.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	audit := func(ctx context.Context, a, ac, tgt, d string) error {
		_, e := s.AppendAudit(ctx, a, ac, tgt, d)
		return e
	}
	return lighthouse.New(s.DB, audit)
}

func ips(t *testing.T, reg *lighthouse.Registry) []string {
	t.Helper()
	lhs, err := reg.Active(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, len(lhs))
	for i, l := range lhs {
		out[i] = l.OverlayIP
	}
	return out
}

// TestAddActive: added lighthouses are advertised, ordered deterministically.
func TestAddActive(t *testing.T) {
	reg := newReg(t)
	ctx := context.Background()
	if _, err := reg.Add(ctx, "100.64.0.2", "lh-b", []string{"b.example:4242"}, "op"); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Add(ctx, "100.64.0.1", "lh-a", []string{"a.example:4242"}, "op"); err != nil {
		t.Fatal(err)
	}
	got := ips(t, reg)
	if len(got) != 2 || got[0] != "100.64.0.1" || got[1] != "100.64.0.2" {
		t.Fatalf("active = %v, want sorted [100.64.0.1 100.64.0.2]", got)
	}
}

// TestRemovedStopsBeingAdvertised is the 6.8 acceptance: a removed lighthouse
// drops out of the advertised set.
func TestRemovedStopsBeingAdvertised(t *testing.T) {
	reg := newReg(t)
	ctx := context.Background()
	_, _ = reg.Add(ctx, "100.64.0.1", "lh-a", []string{"a:4242"}, "op")
	_, _ = reg.Add(ctx, "100.64.0.2", "lh-b", []string{"b:4242"}, "op")

	if err := reg.Remove(ctx, "100.64.0.1", "op"); err != nil {
		t.Fatal(err)
	}
	got := ips(t, reg)
	if len(got) != 1 || got[0] != "100.64.0.2" {
		t.Fatalf("after remove active = %v, want [100.64.0.2]", got)
	}
}

// TestRemoveLastBlocked is the discovery-never-lost invariant (6.3): the final
// active lighthouse cannot be removed.
func TestRemoveLastBlocked(t *testing.T) {
	reg := newReg(t)
	ctx := context.Background()
	_, _ = reg.Add(ctx, "100.64.0.1", "lh-a", []string{"a:4242"}, "op")
	if err := reg.Remove(ctx, "100.64.0.1", "op"); !errors.Is(err, lighthouse.ErrLastActive) {
		t.Fatalf("remove last err = %v, want ErrLastActive", err)
	}
	if got := ips(t, reg); len(got) != 1 {
		t.Fatalf("last lighthouse must remain advertised, got %v", got)
	}
}

// TestSwapNoOutage: the add-new-then-remove-old swap keeps >=1 lighthouse
// advertised at every step.
func TestSwapNoOutage(t *testing.T) {
	reg := newReg(t)
	ctx := context.Background()
	_, _ = reg.Add(ctx, "100.64.0.1", "old", []string{"old:4242"}, "op")
	// Add the replacement first — now two are active.
	if _, err := reg.Add(ctx, "100.64.0.9", "new", []string{"new:4242"}, "op"); err != nil {
		t.Fatal(err)
	}
	if got := ips(t, reg); len(got) != 2 {
		t.Fatalf("mid-swap active = %v, want 2", got)
	}
	// Now retiring the old one is allowed and leaves the new one advertised.
	if err := reg.Remove(ctx, "100.64.0.1", "op"); err != nil {
		t.Fatal(err)
	}
	got := ips(t, reg)
	if len(got) != 1 || got[0] != "100.64.0.9" {
		t.Fatalf("after swap active = %v, want [100.64.0.9]", got)
	}
}

// TestReplaceReaddresses: Replace updates the underlay addr in place and
// re-activates a removed entry.
func TestReplaceReaddresses(t *testing.T) {
	reg := newReg(t)
	ctx := context.Background()
	_, _ = reg.Add(ctx, "100.64.0.1", "lh", []string{"old:4242"}, "op")
	if _, err := reg.Replace(ctx, "100.64.0.1", []string{"new:4242"}, "op"); err != nil {
		t.Fatal(err)
	}
	lhs, _ := reg.Active(ctx)
	if len(lhs) != 1 || lhs[0].PublicAddrs[0] != "new:4242" {
		t.Fatalf("replace did not re-address: %+v", lhs)
	}
	if _, err := reg.Replace(ctx, "100.64.0.2", []string{"x:4242"}, "op"); !errors.Is(err, lighthouse.ErrNotFound) {
		t.Fatalf("replace unknown err = %v, want ErrNotFound", err)
	}
}

// TestAddDuplicate: adding the same overlay IP twice is rejected.
func TestAddDuplicate(t *testing.T) {
	reg := newReg(t)
	ctx := context.Background()
	_, _ = reg.Add(ctx, "100.64.0.1", "lh", []string{"a:4242"}, "op")
	if _, err := reg.Add(ctx, "100.64.0.1", "lh", []string{"b:4242"}, "op"); !errors.Is(err, lighthouse.ErrAlreadyExists) {
		t.Fatalf("duplicate add err = %v, want ErrAlreadyExists", err)
	}
}
