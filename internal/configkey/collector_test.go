package configkey

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestKeyDeletionCollector: the pending-deletion gauge (the alarm signal) reflects a scheduled
// config-signing key. Mirrors internal/ca's collector test.
func TestKeyDeletionCollector(t *testing.T) {
	s, r := setup(t)
	ctx := context.Background()
	now := fixedNow(r) // pin r.now so the NoopKeyDeleter and the registry share a clock

	c := NewCollector(s.DB)
	// No pending deletions -> the gauge is 0.
	none := `
# HELP ncp_configkey_key_deletion_pending Number of config-signing keys currently scheduled for deletion (M8.5; each is in its cancellable pending window).
# TYPE ncp_configkey_key_deletion_pending gauge
ncp_configkey_key_deletion_pending 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(none), "ncp_configkey_key_deletion_pending"); err != nil {
		t.Fatalf("empty gauge: %v", err)
	}

	// Seed k1 active + a staged k2, cut over so k1 drains, retire k1 (empty fleet -> vacuously
	// drained), then schedule its key for deletion.
	p1, _ := mkConfigPub(t)
	p2, _ := mkConfigPub(t)
	if _, _, err := r.SeedActive(ctx, "k1", p1, "kms:1", "boot"); err != nil {
		t.Fatal(err)
	}
	k2, err := r.Stage(ctx, "k2", p2, "kms:2", "op")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Activate(ctx, k2.ID, "op"); err != nil {
		t.Fatal(err)
	}
	if err := r.Retire(ctx, 1, 5*time.Minute, "op"); err != nil {
		t.Fatalf("retire k1: %v", err)
	}
	del := NoopKeyDeleter{Now: func() time.Time { return now }}
	if _, err := r.ScheduleKeyDeletion(ctx, 1, 30, del, "op"); err != nil {
		t.Fatalf("schedule key deletion: %v", err)
	}

	one := `
# HELP ncp_configkey_key_deletion_pending Number of config-signing keys currently scheduled for deletion (M8.5; each is in its cancellable pending window).
# TYPE ncp_configkey_key_deletion_pending gauge
ncp_configkey_key_deletion_pending 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(one), "ncp_configkey_key_deletion_pending"); err != nil {
		t.Fatalf("pending gauge: %v", err)
	}
}
