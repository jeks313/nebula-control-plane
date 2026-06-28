package gatewayhealth_test

import (
	"context"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/gatewayhealth"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

func openDB(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(t.TempDir() + "/g.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestRecordLifecycle: failures accumulate the caller's count + stamp the error; a success
// stamps last_success_at, zeroes the count, and clears the stale error.
func TestRecordLifecycle(t *testing.T) {
	st := gatewayhealth.New(openDB(t).DB)
	ctx := context.Background()
	t0 := time.Unix(1_700_000_000, 0)

	if err := st.Record(ctx, "gw1", false, "claim: timeout", 1, t0); err != nil {
		t.Fatal(err)
	}
	if err := st.Record(ctx, "gw1", false, "claim: timeout", 2, t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	h := mustGet(t, st, "gw1")
	if h.ConsecutiveFailures != 2 || h.LastError != "claim: timeout" || h.LastSuccessAt != 0 {
		t.Fatalf("after 2 failures: %+v", h)
	}

	if err := st.Record(ctx, "gw1", true, "", 0, t0.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	h = mustGet(t, st, "gw1")
	if h.ConsecutiveFailures != 0 || h.LastSuccessAt != t0.Add(2*time.Second).UnixNano() || h.LastError != "" {
		t.Fatalf("after recovery: %+v", h)
	}
}

// TestRecordTruncatesError: a pathological error can't bloat the row.
func TestRecordTruncatesError(t *testing.T) {
	st := gatewayhealth.New(openDB(t).DB)
	big := make([]byte, 2000)
	for i := range big {
		big[i] = 'x'
	}
	if err := st.Record(context.Background(), "gw1", false, string(big), 1, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if got := len(mustGet(t, st, "gw1").LastError); got != 500 {
		t.Fatalf("last_error len=%d, want 500 (truncated)", got)
	}
}

func mustGet(t *testing.T, st *gatewayhealth.Store, name string) gatewayhealth.Health {
	t.Helper()
	m, err := st.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h, ok := m[name]
	if !ok {
		t.Fatalf("no health row for %s", name)
	}
	return h
}
