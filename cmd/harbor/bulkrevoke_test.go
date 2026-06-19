package main

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/revocation"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

func brTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(filepath.Join(t.TempDir(), "br.db"))})
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func activeBlocklist(t *testing.T, s *store.Store) []string {
	t.Helper()
	reg := revocation.New(s.DB, nil)
	fps, err := reg.ActiveFingerprints(context.Background())
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	return fps
}

// TestProposeBulkRevokeTwoOperators (test i): a bulk revoke proposed + approved by
// two distinct operators commits and blocklists the fingerprints.
func TestProposeBulkRevokeTwoOperators(t *testing.T) {
	s := brTestStore(t)
	spec := revocation.BulkRevokeSpec{Fingerprints: []string{"aaaa", "bbbb"}, Reason: "mass compromise"}

	ch, err := proposeBulkRevoke(s, spec, "alice", "bob", netip.Prefix{})
	if err != nil {
		t.Fatalf("propose bulk revoke: %v", err)
	}
	if ch.State != "committed" {
		t.Fatalf("change state = %s, want committed", ch.State)
	}
	got := activeBlocklist(t, s)
	if len(got) != 2 || got[0] != "aaaa" || got[1] != "bbbb" {
		t.Fatalf("active blocklist = %v, want [aaaa bbbb]", got)
	}
}

// TestProposeBulkRevokeSelfApprovalRejected (test j): a single operator proposing
// and approving their own change is rejected (no quorum) and nothing is blocklisted.
func TestProposeBulkRevokeSelfApprovalRejected(t *testing.T) {
	s := brTestStore(t)
	spec := revocation.BulkRevokeSpec{Fingerprints: []string{"cccc"}, Reason: "x"}

	if _, err := proposeBulkRevoke(s, spec, "carol", "carol", netip.Prefix{}); err == nil {
		t.Fatal("expected same-operator bulk revoke to be rejected (no self-approve)")
	}
	if got := activeBlocklist(t, s); len(got) != 0 {
		t.Fatalf("active blocklist = %v, want [] (nothing committed)", got)
	}
}

// TestProposeBulkRevokeControlPlaneProtected: a control-plane fingerprint in the set
// fails the commit (the committer re-validates the P10 guard), so nothing commits.
func TestProposeBulkRevokeControlPlaneProtected(t *testing.T) {
	s := brTestStore(t)
	if err := s.DB.Table("enrollments").Create(map[string]any{
		"enrollment_id": "e-cp", "device_name": "core", "pubkey_hash": "ph", "pubkey": []byte("k"),
		"method": "test", "fingerprint": "cpfp", "status": "issued", "groups": `["control-plane"]`,
		"overlay_ip": "10.44.0.1", "created_at": time.Now().UnixNano(),
	}).Error; err != nil {
		t.Fatal(err)
	}
	spec := revocation.BulkRevokeSpec{Fingerprints: []string{"dddd", "cpfp"}}
	if _, err := proposeBulkRevoke(s, spec, "alice", "bob", netip.Prefix{}); err == nil {
		t.Fatal("expected commit to fail on a control-plane fingerprint")
	}
	if got := activeBlocklist(t, s); len(got) != 0 {
		t.Fatalf("active blocklist = %v, want [] (atomic reject)", got)
	}
}
