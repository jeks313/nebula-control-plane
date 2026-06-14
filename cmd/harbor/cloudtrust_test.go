package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/cloudtrust"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

func ctTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(filepath.Join(t.TempDir(), "ct.db"))})
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestPublishCloudTrust: two distinct operators commit a config that the active
// reader then sees; a same-operator publish is rejected (no single-actor bypass).
func TestPublishCloudTrust(t *testing.T) {
	s := ctTestStore(t)
	cfg := cloudtrust.Config{
		DefaultGroups: []string{"fleet"},
		AWS: []cloudtrust.AWSAccount{
			{Account: "111122223333", ARNPatterns: []string{"arn:aws:sts::111122223333:assumed-role/ncp-node-*/*"}, Groups: []string{"workloads"}, AutoIssue: true},
		},
	}

	ch, err := publishCloudTrust(s, cfg, "alice", "bob", "test config")
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if ch.State != "committed" {
		t.Fatalf("change state = %s, want committed", ch.State)
	}

	got, ok := activeCloudTrust(context.Background(), s)
	if !ok {
		t.Fatal("activeCloudTrust returned not-found after a committed publish")
	}
	if len(got.AWS) != 1 || got.AWS[0].Account != "111122223333" || !got.AWS[0].AutoIssue {
		t.Fatalf("active config = %+v", got)
	}
	if len(got.DefaultGroups) != 1 || got.DefaultGroups[0] != "fleet" {
		t.Fatalf("active default groups = %v", got.DefaultGroups)
	}

	// Same operator proposing and approving must be rejected (two-person control).
	if _, err := publishCloudTrust(s, cfg, "carol", "carol", "x"); err == nil {
		t.Fatal("expected same-operator publish to be rejected (no self-approve)")
	}
}
