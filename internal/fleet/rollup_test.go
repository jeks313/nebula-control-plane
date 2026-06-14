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

// TestRollupDeviceConditionLinks: device-condition reasons carry a Devices
// drill-down link; non-device reasons (audit, rollout) do not.
func TestRollupDeviceConditionLinks(t *testing.T) {
	rep := Report{Total: 5, Expired: 1, ExpiringSoon: 1, Stale: 1, ClockSkewed: 1, Unhealthy: 1}
	h := Rollup(rep, AuditTampered, "canary", th)
	links := map[string]string{}
	for _, r := range h.Reasons {
		links[r.Code] = r.Link
	}
	want := map[string]string{
		"CERTS_EXPIRED":   "/devices?condition=expired",
		"CERTS_EXPIRING":  "/devices?condition=expiring",
		"HOSTS_STALE":     "/devices?condition=stale",
		"CLOCK_SKEWED":    "/devices?condition=clock_skewed",
		"HOSTS_UNHEALTHY": "/devices?condition=unhealthy",
	}
	for code, link := range want {
		if links[code] != link {
			t.Errorf("%s link = %q, want %q", code, links[code], link)
		}
	}
	if links["AUDIT_CHAIN_BROKEN"] != "" {
		t.Errorf("audit reason must not carry a /devices link, got %q", links["AUDIT_CHAIN_BROKEN"])
	}
	if links["ROLLOUT_IN_PROGRESS"] != "" {
		t.Errorf("rollout reason must not carry a /devices link, got %q", links["ROLLOUT_IN_PROGRESS"])
	}
}

// TestConditionSQLTokens: every condition token resolves; garbage does not.
func TestConditionSQLTokens(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	for _, c := range []string{CondExpired, CondExpiring, CondStale, CondClockSkewed, CondUnhealthy} {
		if sql, _, ok := ConditionSQL(c, now, th); !ok || sql == "" {
			t.Errorf("ConditionSQL(%q) ok=%v sql=%q", c, ok, sql)
		}
	}
	if _, _, ok := ConditionSQL("bogus", now, th); ok {
		t.Error("ConditionSQL(bogus) should be !ok")
	}
}

func codeSet(h Health) map[string]bool {
	out := map[string]bool{}
	for _, r := range h.Reasons {
		out[r.Code] = true
	}
	return out
}
