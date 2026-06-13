package dualcontrol_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/dualcontrol"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

func newController(t *testing.T) (*dualcontrol.Controller, *recorder) {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(t.TempDir() + "/dc.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	audit := func(ctx context.Context, a, ac, tgt, d string) error {
		_, e := s.AppendAudit(ctx, a, ac, tgt, d)
		rec.add(ac)
		return e
	}
	dc := dualcontrol.New(dualcontrol.Config{DB: s.DB, Audit: audit})
	return dc, rec
}

type recorder struct {
	mu      sync.Mutex
	actions []string
}

func (r *recorder) add(a string) { r.mu.Lock(); r.actions = append(r.actions, a); r.mu.Unlock() }
func (r *recorder) has(a string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, x := range r.actions {
		if x == a {
			return true
		}
	}
	return false
}

// TestTwoDistinctApproversCommit is the 6.5 happy path: propose + one distinct
// approver reaches quorum 2 and commits.
func TestTwoDistinctApproversCommit(t *testing.T) {
	dc, rec := newController(t)
	ctx := context.Background()

	committed := false
	dc.Register("policy.publish", func(ctx context.Context, c dualcontrol.Change) error { committed = true; return nil })

	ch, err := dc.Propose(ctx, "policy.publish", "fw", []byte("allow a -> b tcp 443"), "alice")
	if err != nil {
		t.Fatal(err)
	}
	out, err := dc.Approve(ctx, ch.ID, "bob")
	if err != nil {
		t.Fatalf("distinct approver should commit: %v", err)
	}
	if dualcontrol.State(out.State) != dualcontrol.StateCommitted {
		t.Fatalf("state = %s, want committed", out.State)
	}
	if !committed {
		t.Fatal("committer was not run")
	}
	if !rec.has("dualcontrol-propose") || !rec.has("dualcontrol-commit") {
		t.Fatal("propose/commit not audited")
	}
}

// TestSelfApprovalBlocked is the core security property: the proposer cannot
// reach quorum alone, and the attempt is audited.
func TestSelfApprovalBlocked(t *testing.T) {
	dc, rec := newController(t)
	ctx := context.Background()
	dc.Register("policy.publish", func(ctx context.Context, c dualcontrol.Change) error {
		t.Fatal("committer must not run on a single approver")
		return nil
	})

	ch, err := dc.Propose(ctx, "policy.publish", "fw", []byte("allow a -> b tcp 443"), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dc.Approve(ctx, ch.ID, "alice"); !errors.Is(err, dualcontrol.ErrSelfApproval) {
		t.Fatalf("self-approval err = %v, want ErrSelfApproval", err)
	}
	got, _, _ := dc.Get(ctx, ch.ID)
	if dualcontrol.State(got.State) != dualcontrol.StatePending {
		t.Fatalf("state = %s, want still pending", got.State)
	}
	if !rec.has("dualcontrol-approve-blocked") {
		t.Fatal("blocked self-approval not audited")
	}
}

// TestDuplicateApproverDoesNotCount: the same checker signing twice cannot
// stand in for two people.
func TestDuplicateApproverDoesNotCount(t *testing.T) {
	dc, _ := newController(t)
	ctx := context.Background()
	dc = withQuorum(t, dc, 3) // need proposer + 2 distinct checkers

	ch, _ := dc.Propose(ctx, "k", "t", []byte("x"), "alice")
	if _, err := dc.Approve(ctx, ch.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := dc.Approve(ctx, ch.ID, "bob"); !errors.Is(err, dualcontrol.ErrDuplicateActor) {
		t.Fatalf("duplicate err = %v, want ErrDuplicateActor", err)
	}
	got, _, _ := dc.Get(ctx, ch.ID)
	if dualcontrol.State(got.State) != dualcontrol.StatePending {
		t.Fatalf("state = %s, want pending (quorum 3 not met by one checker)", got.State)
	}
	// A second distinct checker reaches quorum 3.
	out, err := dc.Approve(ctx, ch.ID, "carol")
	if err != nil {
		t.Fatal(err)
	}
	if dualcontrol.State(out.State) != dualcontrol.StateCommitted {
		t.Fatalf("state = %s, want committed", out.State)
	}
}

// TestCommitterFailureMarksFailed: a failing committer leaves nothing applied.
func TestCommitterFailureMarksFailed(t *testing.T) {
	dc, rec := newController(t)
	ctx := context.Background()
	dc.Register("k", func(ctx context.Context, c dualcontrol.Change) error { return errors.New("boom") })

	ch, _ := dc.Propose(ctx, "k", "t", []byte("x"), "alice")
	out, err := dc.Approve(ctx, ch.ID, "bob")
	if err == nil {
		t.Fatal("expected commit error")
	}
	if dualcontrol.State(out.State) != dualcontrol.StateFailed {
		t.Fatalf("state = %s, want failed", out.State)
	}
	if _, ok, _ := dc.LatestCommitted(ctx, "k"); ok {
		t.Fatal("a failed change must not be the latest committed")
	}
	if !rec.has("dualcontrol-commit-failed") {
		t.Fatal("commit failure not audited")
	}
}

// TestDenyVetoes: a single deny stops the change; it can no longer be approved.
func TestDenyVetoes(t *testing.T) {
	dc, _ := newController(t)
	ctx := context.Background()
	ch, _ := dc.Propose(ctx, "k", "t", []byte("x"), "alice")
	if _, err := dc.Deny(ctx, ch.ID, "bob", "looks wrong"); err != nil {
		t.Fatal(err)
	}
	if _, err := dc.Approve(ctx, ch.ID, "carol"); !errors.Is(err, dualcontrol.ErrNotPending) {
		t.Fatalf("approve after deny err = %v, want ErrNotPending", err)
	}
}

// TestLatestCommitted returns the most recent committed change of a kind.
func TestLatestCommitted(t *testing.T) {
	dc, _ := newController(t)
	ctx := context.Background()
	c1, _ := dc.Propose(ctx, "policy.publish", "v1", []byte("v1"), "alice")
	if _, err := dc.Approve(ctx, c1.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	c2, _ := dc.Propose(ctx, "policy.publish", "v2", []byte("v2"), "alice")
	if _, err := dc.Approve(ctx, c2.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	got, ok, err := dc.LatestCommitted(ctx, "policy.publish")
	if err != nil || !ok {
		t.Fatalf("LatestCommitted ok=%v err=%v", ok, err)
	}
	if string(got.Payload) != "v2" {
		t.Fatalf("latest payload = %q, want v2", got.Payload)
	}
}

// TestConcurrentApproversCommitOnce is the regression guard for the commit-claim:
// several distinct approvers reaching quorum at once must run the committer
// exactly once (no double-apply). Without the compare-and-set claim this fails.
func TestConcurrentApproversCommitOnce(t *testing.T) {
	dc, _ := newController(t) // quorum 2
	ctx := context.Background()
	var runs int32
	dc.Register("k", func(context.Context, dualcontrol.Change) error { atomic.AddInt32(&runs, 1); return nil })

	ch, err := dc.Propose(ctx, "k", "t", []byte("x"), "alice")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, who := range []string{"bob", "carol", "dave"} {
		wg.Add(1)
		go func(w string) { defer wg.Done(); _, _ = dc.Approve(ctx, ch.ID, w) }(who)
	}
	wg.Wait()

	if n := atomic.LoadInt32(&runs); n != 1 {
		t.Fatalf("committer ran %d times, want exactly 1", n)
	}
	got, _, _ := dc.Get(ctx, ch.ID)
	if dualcontrol.State(got.State) != dualcontrol.StateCommitted {
		t.Fatalf("state = %s, want committed", got.State)
	}
}

// withQuorum rebuilds a controller sharing the same DB but with a higher quorum.
func withQuorum(t *testing.T, base *dualcontrol.Controller, q int) *dualcontrol.Controller {
	t.Helper()
	db := base.DB()
	return dualcontrol.New(dualcontrol.Config{DB: db, Quorum: q})
}
