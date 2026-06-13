package fleet

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var th = Thresholds{ExpiryWindow: 7 * 24 * time.Hour, StaleAfter: 5 * time.Minute, ClockSkewMs: 5000}

// TestRollupHealthyNonNilReasons: a clean fleet is healthy with reasons as a
// non-nil empty slice (it must serialize as [], never null).
func TestRollupHealthyNonNilReasons(t *testing.T) {
	h := Rollup(Report{Total: 3}, AuditOK, "", th)
	if h.Status != StatusHealthy {
		t.Fatalf("status = %s, want healthy", h.Status)
	}
	if h.Reasons == nil {
		t.Fatal("Reasons must be non-nil (serializes as [], not null)")
	}
	b, _ := json.Marshal(h)
	if !strings.Contains(string(b), `"reasons":[]`) {
		t.Fatalf("reasons must marshal to []: %s", b)
	}
}

// TestRollupAuditUnavailableIsDegraded: a verify that COULDN'T run is degraded
// (AUDIT_CHECK_UNAVAILABLE) — never a critical AUDIT_CHAIN_BROKEN false alarm.
func TestRollupAuditUnavailableIsDegraded(t *testing.T) {
	h := Rollup(Report{Total: 1}, AuditUnavailable, "", th)
	if h.Status != StatusDegraded {
		t.Fatalf("status = %s, want degraded", h.Status)
	}
	codes := codeSet(h)
	if !codes["AUDIT_CHECK_UNAVAILABLE"] {
		t.Fatalf("want AUDIT_CHECK_UNAVAILABLE, got %v", codes)
	}
	if codes["AUDIT_CHAIN_BROKEN"] {
		t.Fatal("an unavailable check must NOT report the chain broken")
	}
}

// TestRollupAuditTamperedIsCritical: a genuine integrity failure is critical.
func TestRollupAuditTamperedIsCritical(t *testing.T) {
	h := Rollup(Report{Total: 1}, AuditTampered, "", th)
	if h.Status != StatusCritical {
		t.Fatalf("status = %s, want critical", h.Status)
	}
	if !codeSet(h)["AUDIT_CHAIN_BROKEN"] {
		t.Fatal("want AUDIT_CHAIN_BROKEN")
	}
}

// TestRollupRolloutInProgressIsInfo: a healthy fleet mid-rollout stays healthy
// (the rollout reason is info, not degraded).
func TestRollupRolloutInProgressIsInfo(t *testing.T) {
	h := Rollup(Report{Total: 5}, AuditOK, "canary", th)
	if h.Status != StatusHealthy {
		t.Fatalf("status = %s, want healthy (rollout-in-progress is info)", h.Status)
	}
	if !codeSet(h)["ROLLOUT_IN_PROGRESS"] {
		t.Fatal("want ROLLOUT_IN_PROGRESS")
	}
}

// TestRollupOrdersCriticalFirst: critical reasons sort ahead of degraded/info.
func TestRollupOrdersCriticalFirst(t *testing.T) {
	rep := Report{Total: 2, Expired: 1, ExpiringSoon: 1}
	h := Rollup(rep, AuditOK, "canary", th)
	if h.Status != StatusCritical {
		t.Fatalf("status = %s, want critical", h.Status)
	}
	if h.Reasons[0].Severity != SevCritical {
		t.Fatalf("first reason severity = %s, want critical", h.Reasons[0].Severity)
	}
	if h.Reasons[len(h.Reasons)-1].Severity != SevInfo {
		t.Fatalf("last reason severity = %s, want info", h.Reasons[len(h.Reasons)-1].Severity)
	}
}

func codeSet(h Health) map[string]bool {
	out := map[string]bool{}
	for _, r := range h.Reasons {
		out[r.Code] = true
	}
	return out
}
