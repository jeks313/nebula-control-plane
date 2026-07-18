package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
)

// TestEnrollRefusesReservedGroup (H1 fix): ordinary enrollment must NEVER issue a reserved
// group (control-plane/lighthouse), even if a join key somehow carries one. Every auto-issue
// method AND admin Approve funnel through Consumer.issue(), which now refuses with
// ErrReservedGroup. (Before the fix, an auto-issue key with control-plane minted a
// firewall-bypassing, revocation-immune cert — a single-operator privilege escalation.)
//
// The admin API also rejects a reserved-group join key at create/update time; this test
// drives joinkey.Create directly to prove the issue() chokepoint holds even if that
// perimeter is bypassed.
func TestEnrollRefusesReservedGroup(t *testing.T) {
	for _, group := range []string{"control-plane", "lighthouse"} {
		t.Run(group, func(t *testing.T) {
			e := setupEnroll(t)
			ctx := context.Background()

			// Route 1 — auto-issue: refused, no cert issued.
			secret, _, _ := joinkey.Create(ctx, e.store,
				joinkey.Params{Name: "k-" + group, Groups: []string{group}, MaxUses: 0, AutoIssue: true}, time.Now())
			res, err := e.cons.Process(ctx, e.candidate(t, secret, "rogue-"+group))
			if !errors.Is(err, enrollment.ErrReservedGroup) {
				t.Fatalf("auto-issue enroll err = %v, want ErrReservedGroup", err)
			}
			if res.CertPEM != nil {
				t.Fatalf("a cert was issued for reserved group %q", group)
			}
			// The refusal is terminal (don't redeliver forever).
			if !enrollment.Terminal(err) {
				t.Fatalf("ErrReservedGroup should be terminal")
			}

			// Route 2 — pending + admin Approve (a different path into issue()): also refused.
			secret2, _, _ := joinkey.Create(ctx, e.store,
				joinkey.Params{Name: "kp-" + group, Groups: []string{group}, MaxUses: 1, AutoIssue: false}, time.Now())
			pres, perr := e.cons.Process(ctx, e.candidate(t, secret2, "pend-"+group))
			if perr != nil || pres.Status != enrollment.StatusPending {
				t.Fatalf("pending enroll: status=%s err=%v", pres.Status, perr)
			}
			if _, aerr := e.cons.Approve(ctx, "eid-pend-"+group, "admin"); !errors.Is(aerr, enrollment.ErrReservedGroup) {
				t.Fatalf("approve of a reserved-group enrollment err = %v, want ErrReservedGroup", aerr)
			}
		})
	}
}

// TestEnrollAllowsNormalGroupsAfterFix is a guardrail: the H1 chokepoint must not affect
// ordinary (non-reserved) enrollments — they still auto-issue normally.
func TestEnrollAllowsNormalGroupsAfterFix(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	secret, _, _ := joinkey.Create(ctx, e.store,
		joinkey.Params{Name: "web", Groups: []string{"web", "db"}, MaxUses: 0, AutoIssue: true}, time.Now())
	res, err := e.cons.Process(ctx, e.candidate(t, secret, "normal"))
	if err != nil || res.Status != enrollment.StatusIssued || res.CertPEM == nil {
		t.Fatalf("normal enroll should issue: status=%s err=%v", res.Status, err)
	}
}
