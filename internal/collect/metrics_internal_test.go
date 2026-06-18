package collect

import (
	"errors"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/enrollment"
)

// TestOutcomeLabel pins the (result, error) -> outcome mapping that feeds
// ncp_collect_processed_total, including the error branches the black-box collector
// tests don't exercise.
func TestOutcomeLabel(t *testing.T) {
	transient := errors.New("transient network blip") // not in enrollment's terminal set
	cases := []struct {
		name string
		res  enrollment.Result
		err  error
		want string
	}{
		{"issued", enrollment.Result{Status: enrollment.StatusIssued}, nil, "issued"},
		{"pending (manual approval)", enrollment.Result{Status: enrollment.StatusPending}, nil, "pending"},
		{"clean denial", enrollment.Result{Status: enrollment.StatusDenied}, nil, "denied"},
		{"terminal error (quota)", enrollment.Result{Status: enrollment.StatusDenied}, enrollment.ErrQuota, "terminal_error"},
		{"transient error", enrollment.Result{}, transient, "transient_error"},
	}
	for _, tc := range cases {
		if got := outcomeLabel(tc.res, tc.err); got != tc.want {
			t.Errorf("%s: outcomeLabel(%+v, %v) = %q, want %q", tc.name, tc.res, tc.err, got, tc.want)
		}
	}
}
