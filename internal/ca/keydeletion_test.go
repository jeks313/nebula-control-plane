package ca

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// recordingDeleter is a fake ca.KeyDeleter that records calls and can be made to fail.
type recordingDeleter struct {
	scheduled   []string
	cancelled   []string
	date        time.Time
	scheduleErr error
	cancelErr   error
}

func (d *recordingDeleter) ScheduleDeletion(_ context.Context, kmsKeyID string, _ int32) (time.Time, error) {
	if d.scheduleErr != nil {
		return time.Time{}, d.scheduleErr
	}
	d.scheduled = append(d.scheduled, kmsKeyID)
	return d.date, nil
}

func (d *recordingDeleter) CancelDeletion(_ context.Context, kmsKeyID string) error {
	if d.cancelErr != nil {
		return d.cancelErr
	}
	d.cancelled = append(d.cancelled, kmsKeyID)
	return nil
}

// retireCA1 seeds CA-1 active, activates a staged CA-2 (so CA-1 drains), then retires CA-1, and
// returns the retired CA-1 row. CA-1 carries kmsKeyID so it is eligible for key deletion.
func retireCA1(t *testing.T, r *Registry, kmsKeyID string) CA {
	t.Helper()
	ctx := context.Background()
	pem1, _, _, _ := mkCAWithBackend(t, "ca-1")
	pem2, _, _, _ := mkCAWithBackend(t, "ca-2")
	ca1, _, _ := r.SeedActive(ctx, "ca-1", pem1, kmsKeyID, "boot")
	ca2, _ := r.Stage(ctx, "ca-2", pem2, "kms:ca2-arn", "op")
	if err := r.Activate(ctx, ca2.ID, "op"); err != nil {
		t.Fatal(err)
	}
	if err := r.Retire(ctx, ca1.ID, "op"); err != nil {
		t.Fatalf("retire ca-1: %v", err)
	}
	got, _ := r.Get(ctx, ca1.ID)
	return got
}

// TestScheduleKeyDeletionGuardrails: only a RETIRED CA's key may be scheduled, the window must be
// 7-30 days, and a nil deleter is refused — none of which touches the backend.
func TestScheduleKeyDeletionGuardrails(t *testing.T) {
	_, r := setup(t)
	ctx := context.Background()
	pem1, _, _, _ := mkCAWithBackend(t, "ca-1")
	pem2, _, _, _ := mkCAWithBackend(t, "ca-2")
	ca1, _, _ := r.SeedActive(ctx, "ca-1", pem1, "kms:ca1-arn", "boot") // active
	ca2, _ := r.Stage(ctx, "ca-2", pem2, "kms:ca2-arn", "op")           // staged
	del := &recordingDeleter{date: time.Now().Add(30 * 24 * time.Hour)}

	// Active CA -> refused.
	if _, err := r.ScheduleKeyDeletion(ctx, ca1.ID, 30, del, "op"); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("schedule active CA err = %v, want ErrIllegalTransition", err)
	}
	// Staged CA -> refused.
	if _, err := r.ScheduleKeyDeletion(ctx, ca2.ID, 30, del, "op"); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("schedule staged CA err = %v, want ErrIllegalTransition", err)
	}
	// Draining CA (activate CA-2 first) -> refused.
	_ = r.Activate(ctx, ca2.ID, "op")
	if _, err := r.ScheduleKeyDeletion(ctx, ca1.ID, 30, del, "op"); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("schedule draining CA err = %v, want ErrIllegalTransition", err)
	}
	// Window out of the KMS 7-30 range -> refused.
	if _, err := r.ScheduleKeyDeletion(ctx, ca1.ID, 6, del, "op"); err == nil {
		t.Fatal("a 6-day window must be refused (<7)")
	}
	if _, err := r.ScheduleKeyDeletion(ctx, ca1.ID, 31, del, "op"); err == nil {
		t.Fatal("a 31-day window must be refused (>30)")
	}
	// nil deleter -> refused.
	if _, err := r.ScheduleKeyDeletion(ctx, ca1.ID, 30, nil, "op"); err == nil {
		t.Fatal("a nil deleter must be refused")
	}
	if len(del.scheduled) != 0 {
		t.Fatalf("the backend must not be touched on a guardrail failure, got %v", del.scheduled)
	}
}

// TestScheduleAndCancelKeyDeletion: the happy path schedules + persists + calls the backend once,
// double-scheduling is refused, and cancel restores the key + clears the record.
func TestScheduleAndCancelKeyDeletion(t *testing.T) {
	_, r := setup(t)
	ctx := context.Background()
	ca1 := retireCA1(t, r, "kms:ca1-arn")
	delDate := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	del := &recordingDeleter{date: delDate}

	got, err := r.ScheduleKeyDeletion(ctx, ca1.ID, 30, del, "op")
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if !got.Equal(delDate) {
		t.Fatalf("returned deletion date %v, want %v", got, delDate)
	}
	if len(del.scheduled) != 1 || del.scheduled[0] != "kms:ca1-arn" {
		t.Fatalf("backend scheduled %v, want [kms:ca1-arn]", del.scheduled)
	}
	row, _ := r.Get(ctx, ca1.ID)
	if row.KeyDeletionScheduledAt == 0 || row.KeyDeletionDate != delDate.UnixNano() {
		t.Fatalf("schedule not persisted: scheduledAt=%d date=%d", row.KeyDeletionScheduledAt, row.KeyDeletionDate)
	}
	if pend, _ := r.PendingKeyDeletions(ctx); len(pend) != 1 || pend[0].ID != ca1.ID {
		t.Fatalf("PendingKeyDeletions = %v, want [ca-1]", pend)
	}
	// Double-schedule -> refused (backend untouched a second time).
	if _, err := r.ScheduleKeyDeletion(ctx, ca1.ID, 30, del, "op"); err == nil {
		t.Fatal("double-schedule must be refused")
	}
	if len(del.scheduled) != 1 {
		t.Fatalf("backend scheduled %d times, want 1 (double-schedule must not re-call)", len(del.scheduled))
	}
	// Cancel restores the key + clears the record.
	if err := r.CancelKeyDeletion(ctx, ca1.ID, del, "op"); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if len(del.cancelled) != 1 || del.cancelled[0] != "kms:ca1-arn" {
		t.Fatalf("backend cancelled %v, want [kms:ca1-arn]", del.cancelled)
	}
	row, _ = r.Get(ctx, ca1.ID)
	if row.KeyDeletionScheduledAt != 0 || row.KeyDeletionDate != 0 {
		t.Fatal("cancel did not clear the schedule")
	}
	if pend, _ := r.PendingKeyDeletions(ctx); len(pend) != 0 {
		t.Fatal("PendingKeyDeletions must be empty after cancel")
	}
	// Cancel with nothing scheduled -> error.
	if err := r.CancelKeyDeletion(ctx, ca1.ID, del, "op"); err == nil {
		t.Fatal("cancel with nothing scheduled must error")
	}
}

// TestScheduleKeyDeletionRejectsNoKeyAndLiveDeps: a trust-only (no key) retired CA and a retired CA
// that still (out-of-band) has a live leaf are both refused, and neither touches the backend. Each
// scenario uses a fresh registry (SeedActive is a one-shot boot-seed).
func TestScheduleKeyDeletionRejectsNoKeyAndLiveDeps(t *testing.T) {
	ctx := context.Background()

	// A trust-only CA (empty kms key) abandoned -> retired with no key backend.
	t.Run("no-key-backend", func(t *testing.T) {
		_, r := setup(t)
		del := &recordingDeleter{date: time.Now().Add(30 * 24 * time.Hour)}
		pemTO, _, _, _ := mkCAWithBackend(t, "ca-trustonly")
		caTO, _ := r.Stage(ctx, "ca-trustonly", pemTO, "", "op")
		if err := r.Abandon(ctx, caTO.ID, "op"); err != nil { // staged -> retired
			t.Fatal(err)
		}
		if _, err := r.ScheduleKeyDeletion(ctx, caTO.ID, 30, del, "op"); err == nil {
			t.Fatal("a retired trust-only CA (no key backend) must be refused")
		}
		if len(del.scheduled) != 0 {
			t.Fatalf("the backend must not be touched, got %v", del.scheduled)
		}
	})

	// A retired CA with an (out-of-band injected) live leaf -> refused fail-closed.
	t.Run("live-dependent", func(t *testing.T) {
		s, r := setup(t)
		del := &recordingDeleter{date: time.Now().Add(30 * 24 * time.Hour)}
		pem1, _, ca1cert, bk1 := mkCAWithBackend(t, "ca-1")
		pem2, _, _, _ := mkCAWithBackend(t, "ca-2")
		ca1, _, _ := r.SeedActive(ctx, "ca-1", pem1, "kms:ca1-arn", "boot")
		ca2, _ := r.Stage(ctx, "ca-2", pem2, "kms:ca2-arn", "op")
		_ = r.Activate(ctx, ca2.ID, "op")
		_ = r.Retire(ctx, ca1.ID, "op")
		seedEnroll(t, s.DB, "e-live-del", "issued", mkLeafPEM(t, ca1cert, bk1, "h", time.Now().Add(24*time.Hour)), ca1.Fingerprint)
		if _, err := r.ScheduleKeyDeletion(ctx, ca1.ID, 30, del, "op"); !errors.Is(err, ErrHasDependents) {
			t.Fatalf("schedule with a live dependent err = %v, want ErrHasDependents", err)
		}
		if len(del.scheduled) != 0 {
			t.Fatalf("the backend must not be touched on a guardrail failure, got %v", del.scheduled)
		}
	})
}

// TestScheduleKeyDeletionBackendErrorNoPersist: if the backend refuses, no schedule is recorded
// (state stays clean, so the operator can retry without a phantom pending deletion).
func TestScheduleKeyDeletionBackendErrorNoPersist(t *testing.T) {
	_, r := setup(t)
	ctx := context.Background()
	ca1 := retireCA1(t, r, "kms:ca1-arn")
	del := &recordingDeleter{scheduleErr: errors.New("kms boom")}
	if _, err := r.ScheduleKeyDeletion(ctx, ca1.ID, 30, del, "op"); err == nil {
		t.Fatal("a backend error must fail the schedule")
	}
	if row, _ := r.Get(ctx, ca1.ID); row.KeyDeletionScheduledAt != 0 {
		t.Fatal("a backend error must not persist a schedule")
	}
}

// TestKeyDeletionCollector: the pending-deletion gauge (the alarm signal) reflects a scheduled CA.
func TestKeyDeletionCollector(t *testing.T) {
	s, r := setup(t)
	ctx := context.Background()

	c := NewCollector(s.DB)
	// No pending deletions -> the gauge is 0.
	none := `
# HELP ncp_ca_key_deletion_pending Number of CA signing keys currently scheduled for deletion (M8.4; each is in its cancellable pending window).
# TYPE ncp_ca_key_deletion_pending gauge
ncp_ca_key_deletion_pending 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(none), "ncp_ca_key_deletion_pending"); err != nil {
		t.Fatalf("empty gauge: %v", err)
	}

	ca1 := retireCA1(t, r, "kms:ca1-arn")
	if _, err := r.ScheduleKeyDeletion(ctx, ca1.ID, 30, &recordingDeleter{date: time.Now().Add(30 * 24 * time.Hour)}, "op"); err != nil {
		t.Fatal(err)
	}
	one := `
# HELP ncp_ca_key_deletion_pending Number of CA signing keys currently scheduled for deletion (M8.4; each is in its cancellable pending window).
# TYPE ncp_ca_key_deletion_pending gauge
ncp_ca_key_deletion_pending 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(one), "ncp_ca_key_deletion_pending"); err != nil {
		t.Fatalf("pending gauge: %v", err)
	}
}
