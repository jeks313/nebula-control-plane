package gatewayreg_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/collect"
	"github.com/jeks313/nebula-control-plane/internal/gatewayreg"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

func newReg(t *testing.T) (*gatewayreg.Registry, *[]string) {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(filepath.Join(t.TempDir(), "g.db"))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	var actions []string
	audit := func(_ context.Context, _, action, _, _ string) error {
		actions = append(actions, action)
		return nil
	}
	return gatewayreg.New(s.DB, audit), &actions
}

func cert(t *testing.T) string {
	t.Helper()
	c, _, err := collect.GenerateSelfSigned("gw", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return string(c)
}

// TestAddListActiveRemove covers the lifecycle: add → active + list show it →
// remove → no longer active (kept in list as removed), each state change audited.
func TestAddListActiveRemove(t *testing.T) {
	r, actions := newReg(t)
	ctx := context.Background()
	gw1 := cert(t)

	if _, err := r.Add(ctx, "gw-1", "https://gw1:9443", gw1, "admin"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if active, _ := r.Active(ctx); len(active) != 1 || active[0].Name != "gw-1" || active[0].URL != "https://gw1:9443" {
		t.Fatalf("active = %+v, want [gw-1]", active)
	}

	if err := r.Remove(ctx, "gw-1", "admin"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if active, _ := r.Active(ctx); len(active) != 0 {
		t.Fatalf("active after remove = %+v, want []", active)
	}
	if rows, _ := r.List(ctx); len(rows) != 1 || rows[0].State != gatewayreg.StateRemoved {
		t.Fatalf("list = %+v, want one removed row", rows)
	}
	if got := *actions; len(got) != 2 || got[0] != "gateway-add" || got[1] != "gateway-remove" {
		t.Fatalf("audit = %v, want [gateway-add gateway-remove]", got)
	}
}

// TestDuplicateAndReactivate: a duplicate active name is rejected; re-adding a
// removed name re-activates + re-addresses it in place (not a new row).
func TestDuplicateAndReactivate(t *testing.T) {
	r, _ := newReg(t)
	ctx := context.Background()
	c := cert(t)

	if _, err := r.Add(ctx, "gw", "https://a:9443", c, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(ctx, "gw", "https://a:9443", c, "admin"); !errors.Is(err, gatewayreg.ErrAlreadyExists) {
		t.Fatalf("re-add active err = %v, want ErrAlreadyExists", err)
	}
	if err := r.Remove(ctx, "gw", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(ctx, "gw", "https://b:9443", cert(t), "admin"); err != nil {
		t.Fatalf("re-activate: %v", err)
	}
	active, _ := r.Active(ctx)
	if len(active) != 1 || active[0].URL != "https://b:9443" {
		t.Fatalf("reactivated = %+v, want one row re-addressed to b", active)
	}
	if rows, _ := r.List(ctx); len(rows) != 1 {
		t.Fatalf("want 1 row after reactivate, got %d", len(rows))
	}
}

func TestRejectsBadCert(t *testing.T) {
	r, _ := newReg(t)
	if _, err := r.Add(context.Background(), "gw", "https://a:9443", "not a cert", "admin"); !errors.Is(err, gatewayreg.ErrBadCert) {
		t.Fatalf("err = %v, want ErrBadCert", err)
	}
}
