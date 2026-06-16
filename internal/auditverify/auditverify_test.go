package auditverify

import (
	"context"
	"fmt"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type fakeStore struct {
	rows int64
	err  error
}

func (f fakeStore) VerifyAudit(context.Context) (int64, error) { return f.rows, f.err }

func TestVerifyOnce(t *testing.T) {
	runs0 := testutil.ToFloat64(metricRuns)
	fail0 := testutil.ToFloat64(metricFailures)
	tamp0 := testutil.ToFloat64(metricTampered)

	// 1. Clean verification: rows set, no failure counters move.
	New(fakeStore{rows: 42}, 0, nil).verifyOnce(context.Background())
	if got := testutil.ToFloat64(metricRows); got != 42 {
		t.Errorf("rows = %v, want 42", got)
	}
	if got := testutil.ToFloat64(metricFailures); got != fail0 {
		t.Errorf("failures moved on a clean run: %v -> %v", fail0, got)
	}

	// 2. Tamper: failures AND tampered both increment.
	New(fakeStore{rows: 3, err: fmt.Errorf("%w: hash mismatch at seq 3", store.ErrAuditTampered)}, 0, nil).
		verifyOnce(context.Background())
	if got := testutil.ToFloat64(metricFailures); got != fail0+1 {
		t.Errorf("failures = %v, want %v", got, fail0+1)
	}
	if got := testutil.ToFloat64(metricTampered); got != tamp0+1 {
		t.Errorf("tampered = %v, want %v", got, tamp0+1)
	}

	// 3. Transient read error: failures increments, tampered does NOT.
	New(fakeStore{err: fmt.Errorf("db down")}, 0, nil).verifyOnce(context.Background())
	if got := testutil.ToFloat64(metricFailures); got != fail0+2 {
		t.Errorf("failures = %v, want %v", got, fail0+2)
	}
	if got := testutil.ToFloat64(metricTampered); got != tamp0+1 {
		t.Errorf("tampered moved on a transient error: %v, want %v", got, tamp0+1)
	}

	if got := testutil.ToFloat64(metricRuns); got != runs0+3 {
		t.Errorf("runs = %v, want %v", got, runs0+3)
	}
}
