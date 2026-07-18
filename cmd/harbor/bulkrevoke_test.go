package main

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/revocation"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

// 64-hex fingerprints (the registry now rejects non-64-hex; these stand in for the short
// placeholders the tests used before), distinct + orderable for the sorted-output asserts.
var (
	brFPa  = strings.Repeat("a", 64)
	brFPb  = strings.Repeat("b", 64)
	brFPc  = strings.Repeat("c", 64)
	brFPd  = strings.Repeat("d", 64)
	brFPcp = strings.Repeat("e", 64)
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
	spec := revocation.BulkRevokeSpec{Fingerprints: []string{brFPa, brFPb}, Reason: "mass compromise"}

	ch, err := proposeBulkRevoke(s, spec, "alice", "bob", netip.Prefix{})
	if err != nil {
		t.Fatalf("propose bulk revoke: %v", err)
	}
	if ch.State != "committed" {
		t.Fatalf("change state = %s, want committed", ch.State)
	}
	got := activeBlocklist(t, s)
	if len(got) != 2 || got[0] != brFPa || got[1] != brFPb {
		t.Fatalf("active blocklist = %v, want [a… b…]", got)
	}
}

// TestProposeBulkRevokeSelfApprovalRejected (test j): a single operator proposing
// and approving their own change is rejected (no quorum) and nothing is blocklisted.
func TestProposeBulkRevokeSelfApprovalRejected(t *testing.T) {
	s := brTestStore(t)
	spec := revocation.BulkRevokeSpec{Fingerprints: []string{brFPc}, Reason: "x"}

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
		"method": "test", "fingerprint": brFPcp, "status": "issued", "groups": `["control-plane"]`,
		"overlay_ip": "10.44.0.1", "created_at": time.Now().UnixNano(),
	}).Error; err != nil {
		t.Fatal(err)
	}
	spec := revocation.BulkRevokeSpec{Fingerprints: []string{brFPd, brFPcp}}
	if _, err := proposeBulkRevoke(s, spec, "alice", "bob", netip.Prefix{}); err == nil {
		t.Fatal("expected commit to fail on a control-plane fingerprint")
	}
	if got := activeBlocklist(t, s); len(got) != 0 {
		t.Fatalf("active blocklist = %v, want [] (atomic reject)", got)
	}
}
