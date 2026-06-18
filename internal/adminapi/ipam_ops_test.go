package adminapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/adminapi"
	"github.com/jeks313/nebula-control-plane/internal/ipam"
	"github.com/jeks313/nebula-control-plane/internal/netblock"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

const ipamPool = "10.44.0.0/16"

// ipamSrv builds an admin server with the netblock registry + allocator wired and
// central/default seeded (as genesis would), for the ADR-0010 IPAM endpoints.
func ipamSrv(t *testing.T, role string) *httptest.Server {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(t.TempDir() + "/ipam.db")})
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
	pool := mustPrefix(t, ipamPool)
	alloc, err := ipam.NewAllocator(s, ipam.Pool{Prefix: pool})
	if err != nil {
		t.Fatal(err)
	}
	reg := netblock.New(s.DB, pool, nil, alloc, audit)
	alloc = alloc.WithResolver(reg)
	ctx := context.Background()
	if _, err := reg.Seed(ctx, netblock.NameCentral, mustPrefix(t, "10.44.0.0/27"), netblock.KindReserved, "central", "genesis"); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Seed(ctx, netblock.NameDefault, mustPrefix(t, "10.44.64.0/18"), netblock.KindDefault, "fallback", "genesis"); err != nil {
		t.Fatal(err)
	}
	srv := adminapi.New(adminapi.Config{
		Store:     s,
		Identity:  adminapi.DevHeaderProvider{Roles: []string{role}},
		Netblocks: reg, Allocator: alloc, Pool: pool,
	})
	return httptest.NewServer(srv.Handler())
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("bad prefix %q: %v", s, err)
	}
	return p.Masked()
}

// TestNetblockLifecycleOverHTTP: list (genesis blocks) -> create -> list again ->
// allocations -> delete, with schema conformance at each step.
func TestNetblockLifecycleOverHTTP(t *testing.T) {
	ts := ipamSrv(t, "admin")
	defer ts.Close()
	doc := loadSpec(t)

	// List: the two genesis blocks (central, default).
	code, list := req(t, ts, "GET", "/admin/v1/ipam/netblocks", "alice", nil)
	if code != http.StatusOK {
		t.Fatalf("list status = %d (%v)", code, list)
	}
	conform(t, doc, "GET", "/admin/v1/ipam/netblocks", 200, list)
	if list["count"].(float64) != 2 {
		t.Fatalf("seeded count = %v, want 2 (central+default)", list["count"])
	}
	// The configured pool prefix rides along so the UI overlay can show free space
	// above the highest block (D21, supersedes the D19 block-derived extent workaround).
	if list["pool"] != ipamPool {
		t.Fatalf("list pool = %v, want %q", list["pool"], ipamPool)
	}

	// Create a named carve.
	code, nb := req(t, ts, "POST", "/admin/v1/ipam/netblocks", "alice",
		map[string]any{"name": "office", "cidr": "10.44.20.0/24", "description": "office vpn"})
	if code != http.StatusCreated {
		t.Fatalf("create status = %d (%v)", code, nb)
	}
	conform(t, doc, "POST", "/admin/v1/ipam/netblocks", 201, nb)
	if nb["kind"] != "named" || nb["cidr"] != "10.44.20.0/24" {
		t.Fatalf("created netblock = %v", nb)
	}
	if cap, _ := nb["capacity"].(float64); cap != 255 { // /24 = 256 - network
		t.Fatalf("capacity = %v, want 255", nb["capacity"])
	}

	// It now appears in the list.
	if _, list = req(t, ts, "GET", "/admin/v1/ipam/netblocks", "alice", nil); list["count"].(float64) != 3 {
		t.Fatalf("post-create count = %v, want 3", list["count"])
	}

	// Allocations within it (empty, but well-formed + conformant).
	code, al := req(t, ts, "GET", "/admin/v1/ipam/allocations?netblock=office", "alice", nil)
	if code != http.StatusOK {
		t.Fatalf("allocations status = %d (%v)", code, al)
	}
	conform(t, doc, "GET", "/admin/v1/ipam/allocations", 200, al)
	if al["count"].(float64) != 0 {
		t.Fatalf("allocations count = %v, want 0", al["count"])
	}

	// Edit the description (no cidr) — must not trip the stranding guard.
	code, upd := req(t, ts, "PATCH", "/admin/v1/ipam/netblocks/office", "alice",
		map[string]any{"description": "renamed"})
	if code != http.StatusOK {
		t.Fatalf("update status = %d (%v)", code, upd)
	}
	conform(t, doc, "PATCH", "/admin/v1/ipam/netblocks/{name}", 200, upd)
	if upd["description"] != "renamed" {
		t.Fatalf("update did not persist description: %v", upd)
	}

	// Delete it.
	code, del := req(t, ts, "DELETE", "/admin/v1/ipam/netblocks/office", "alice", nil)
	if code != http.StatusOK || del["removed"] != true {
		t.Fatalf("delete status = %d (%v)", code, del)
	}
	// Gone now.
	if _, list = req(t, ts, "GET", "/admin/v1/ipam/netblocks", "alice", nil); list["count"].(float64) != 2 {
		t.Fatalf("post-delete count = %v, want 2", list["count"])
	}
	// Deleting again is a 404.
	if code, _ := req(t, ts, "DELETE", "/admin/v1/ipam/netblocks/office", "alice", nil); code != http.StatusNotFound {
		t.Fatalf("delete-missing status = %d, want 404", code)
	}
}

// TestNetblockSuggestOverHTTP: the growth-aware placement endpoint returns a
// CIDR of the requested size, and 400 without a prefix.
func TestNetblockSuggestOverHTTP(t *testing.T) {
	ts := ipamSrv(t, "admin")
	defer ts.Close()
	doc := loadSpec(t)

	code, sug := req(t, ts, "GET", "/admin/v1/ipam/netblocks/suggest?prefix=27", "alice", nil)
	if code != http.StatusOK {
		t.Fatalf("suggest status = %d (%v)", code, sug)
	}
	conform(t, doc, "GET", "/admin/v1/ipam/netblocks/suggest", 200, sug)
	if sug["prefix"].(float64) != 27 {
		t.Fatalf("suggest prefix = %v, want 27", sug["prefix"])
	}
	cidr, _ := sug["cidr"].(string)
	p, perr := netip.ParsePrefix(cidr)
	if perr != nil || p.Bits() != 27 {
		t.Fatalf("suggest cidr = %q (want a /27)", cidr)
	}
	// The suggestion must be carve-able (clear of central/default + non-overlapping).
	if code, nb := req(t, ts, "POST", "/admin/v1/ipam/netblocks", "alice",
		map[string]any{"name": "carved", "cidr": cidr}); code != http.StatusCreated {
		t.Fatalf("carve at suggested cidr status = %d (%v)", code, nb)
	}

	// Missing prefix → 400.
	if code, _ := req(t, ts, "GET", "/admin/v1/ipam/netblocks/suggest", "alice", nil); code != http.StatusBadRequest {
		t.Fatalf("suggest (no prefix) status = %d, want 400", code)
	}
}

// TestNetblockErrorMappings: the domain errors map to the right HTTP codes —
// overlap (409), protected (409), out-of-pool / bad cidr (400), not-found (404).
func TestNetblockErrorMappings(t *testing.T) {
	ts := ipamSrv(t, "admin")
	defer ts.Close()

	// Carve a block, then a second one overlapping it → 409.
	if code, _ := req(t, ts, "POST", "/admin/v1/ipam/netblocks", "alice",
		map[string]any{"name": "a", "cidr": "10.44.20.0/24"}); code != http.StatusCreated {
		t.Fatalf("first carve status = %d", code)
	}
	if code, _ := req(t, ts, "POST", "/admin/v1/ipam/netblocks", "alice",
		map[string]any{"name": "b", "cidr": "10.44.20.0/25"}); code != http.StatusConflict {
		t.Fatalf("overlapping carve status = %d, want 409", code)
	}
	// Duplicate name → 409.
	if code, _ := req(t, ts, "POST", "/admin/v1/ipam/netblocks", "alice",
		map[string]any{"name": "a", "cidr": "10.44.30.0/24"}); code != http.StatusConflict {
		t.Fatalf("duplicate-name carve status = %d, want 409", code)
	}
	// Out-of-pool CIDR → 400.
	if code, _ := req(t, ts, "POST", "/admin/v1/ipam/netblocks", "alice",
		map[string]any{"name": "c", "cidr": "192.168.0.0/24"}); code != http.StatusBadRequest {
		t.Fatalf("out-of-pool carve status = %d, want 400", code)
	}
	// Malformed CIDR → 400.
	if code, _ := req(t, ts, "POST", "/admin/v1/ipam/netblocks", "alice",
		map[string]any{"name": "d", "cidr": "not-a-cidr"}); code != http.StatusBadRequest {
		t.Fatalf("malformed carve status = %d, want 400", code)
	}
	// Editing a protected block (default) → 409.
	if code, _ := req(t, ts, "PATCH", "/admin/v1/ipam/netblocks/default", "alice",
		map[string]any{"description": "nope"}); code != http.StatusConflict {
		t.Fatalf("edit-protected status = %d, want 409", code)
	}
	// Deleting a protected block (central) → 409.
	if code, _ := req(t, ts, "DELETE", "/admin/v1/ipam/netblocks/central", "alice", nil); code != http.StatusConflict {
		t.Fatalf("delete-protected status = %d, want 409", code)
	}
	// Allocations for a missing netblock → 404.
	if code, _ := req(t, ts, "GET", "/admin/v1/ipam/allocations?netblock=nope", "alice", nil); code != http.StatusNotFound {
		t.Fatalf("allocations(missing) status = %d, want 404", code)
	}
	// Allocations without a netblock param → 400.
	if code, _ := req(t, ts, "GET", "/admin/v1/ipam/allocations", "alice", nil); code != http.StatusBadRequest {
		t.Fatalf("allocations(no param) status = %d, want 400", code)
	}
}

// TestNetblockStrandingOverHTTP: an edit that would strand a live allocation
// outside the new range is refused (422).
func TestNetblockStrandingOverHTTP(t *testing.T) {
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(t.TempDir() + "/strand.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	audit := func(ctx context.Context, a, ac, tgt, d string) error {
		_, e := s.AppendAudit(ctx, a, ac, tgt, d)
		return e
	}
	pool := mustPrefix(t, ipamPool)
	alloc, err := ipam.NewAllocator(s, ipam.Pool{Prefix: pool})
	if err != nil {
		t.Fatal(err)
	}
	reg := netblock.New(s.DB, pool, nil, alloc, audit)
	alloc = alloc.WithResolver(reg)
	ctx := context.Background()
	if _, err := reg.Seed(ctx, netblock.NameDefault, mustPrefix(t, "10.44.64.0/18"), netblock.KindDefault, "fallback", "genesis"); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Add(ctx, "office", mustPrefix(t, "10.44.20.0/24"), "office", "op"); err != nil {
		t.Fatal(err)
	}
	// Allocate a host high in the block (.200), so shrinking to a /25 would strand it.
	if _, err := alloc.Allocate(ctx, "host-200", "office", "token"); err != nil {
		t.Fatal(err)
	}
	// Force a .200 allocation directly so the address is unambiguously in the upper half.
	if err := alloc.AllocateSpecific(ctx, "host-hi", netip.MustParseAddr("10.44.20.200"), "token"); err != nil {
		t.Fatal(err)
	}

	srv := adminapi.New(adminapi.Config{
		Store:     s,
		Identity:  adminapi.DevHeaderProvider{Roles: []string{"admin"}},
		Netblocks: reg, Allocator: alloc, Pool: pool,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Shrinking office to a /25 (10.44.20.0/25) strands 10.44.20.200 → 422.
	if code, body := req(t, ts, "PATCH", "/admin/v1/ipam/netblocks/office", "alice",
		map[string]any{"cidr": "10.44.20.0/25"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("stranding edit status = %d, want 422 (%v)", code, body)
	}
}

// TestIPAMRequiresPerm: a viewer (no ipam:manage) is 403 on every mutation, but
// the read endpoints still work.
func TestIPAMRequiresPerm(t *testing.T) {
	ts := ipamSrv(t, "viewer")
	defer ts.Close()
	cases := []struct {
		method, path string
		body         any
	}{
		{"POST", "/admin/v1/ipam/netblocks", map[string]any{"name": "x", "cidr": "10.44.30.0/24"}},
		{"PATCH", "/admin/v1/ipam/netblocks/default", map[string]any{"description": "y"}},
		{"DELETE", "/admin/v1/ipam/netblocks/office", nil},
	}
	for _, c := range cases {
		if code, _ := req(t, ts, c.method, c.path, "carol", c.body); code != http.StatusForbidden {
			t.Errorf("%s %s as viewer = %d, want 403", c.method, c.path, code)
		}
	}
	// Reads remain allowed for a viewer.
	if code, _ := req(t, ts, "GET", "/admin/v1/ipam/netblocks", "carol", nil); code != http.StatusOK {
		t.Errorf("viewer list netblocks = %d, want 200", code)
	}
	if code, _ := req(t, ts, "GET", "/admin/v1/ipam/netblocks/suggest?prefix=27", "carol", nil); code != http.StatusOK {
		t.Errorf("viewer suggest = %d, want 200", code)
	}
}

// TestIPAMOperatorCanManage: the operator role carries ipam:manage.
func TestIPAMOperatorCanManage(t *testing.T) {
	ts := ipamSrv(t, "operator")
	defer ts.Close()
	if code, nb := req(t, ts, "POST", "/admin/v1/ipam/netblocks", "op",
		map[string]any{"name": "ops-block", "cidr": "10.44.30.0/24"}); code != http.StatusCreated {
		t.Fatalf("operator create status = %d (%v)", code, nb)
	}
}
