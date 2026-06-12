package fleet

import (
	"testing"
	"time"
)

func TestSummarizeBuckets(t *testing.T) {
	now := time.Now()
	far := now.Add(30 * 24 * time.Hour).UnixNano()
	recent := now.Add(-30 * time.Second).UnixNano()
	th := Thresholds{ExpiryWindow: 7 * 24 * time.Hour, StaleAfter: 5 * time.Minute, ClockSkewMs: 5000}

	rows := []hb{
		{OverlayIP: "100.64.0.2", DeviceName: "ok", CertNotAfter: far, LastSeen: recent, ClockOffsetMs: 10, Health: "ok"},
		{OverlayIP: "100.64.0.3", DeviceName: "expiring", CertNotAfter: now.Add(time.Hour).UnixNano(), LastSeen: recent, Health: "ok"},
		{OverlayIP: "100.64.0.4", DeviceName: "expired", CertNotAfter: now.Add(-time.Hour).UnixNano(), LastSeen: recent, Health: "ok"},
		{OverlayIP: "100.64.0.5", DeviceName: "stale", CertNotAfter: far, LastSeen: now.Add(-time.Hour).UnixNano(), Health: "ok"},
		{OverlayIP: "100.64.0.6", DeviceName: "skewed", CertNotAfter: far, LastSeen: recent, ClockOffsetMs: 9000, Health: "ok"},
		{OverlayIP: "100.64.0.7", DeviceName: "sick", CertNotAfter: far, LastSeen: recent, Health: "degraded"},
	}
	r := Summarize(rows, now, th)

	if r.Total != 6 || r.Expired != 1 || r.ExpiringSoon != 1 || r.Stale != 1 || r.ClockSkewed != 1 || r.Unhealthy != 1 {
		t.Fatalf("buckets wrong: %+v", r)
	}
	if len(r.AtRisk) != 3 { // expired + expiring + stale
		t.Fatalf("at-risk = %d, want 3", len(r.AtRisk))
	}
	// Worst (soonest expiry) first -> the expired one leads.
	if r.AtRisk[0].Name != "expired" {
		t.Fatalf("at-risk[0] = %s, want expired", r.AtRisk[0].Name)
	}
	if !r.HasAlerts() {
		t.Fatal("HasAlerts should be true")
	}
}

// TestRenewalBlockedDrill is the M4.7 acceptance: when renewal is blocked a host
// drifts toward expiry, and the report alerts on it.
func TestRenewalBlockedDrill(t *testing.T) {
	now := time.Now()
	th := Thresholds{ExpiryWindow: 7 * 24 * time.Hour, StaleAfter: 5 * time.Minute, ClockSkewMs: 5000}

	// A host whose renewal is blocked: cert nearing expiry, still heartbeating.
	rows := []hb{{
		OverlayIP: "100.64.0.9", DeviceName: "blocked",
		CertNotAfter: now.Add(36 * time.Hour).UnixNano(), LastSeen: now.Add(-30 * time.Second).UnixNano(), Health: "ok",
	}}
	r := Summarize(rows, now, th)
	if r.ExpiringSoon != 1 || !r.HasAlerts() || len(r.Alerts) == 0 {
		t.Fatalf("expected an expiry alert, got %+v", r)
	}
}

func TestHealthyFleetNoAlerts(t *testing.T) {
	now := time.Now()
	th := Thresholds{ExpiryWindow: 7 * 24 * time.Hour, StaleAfter: 5 * time.Minute, ClockSkewMs: 5000}
	rows := []hb{{
		OverlayIP: "100.64.0.2", DeviceName: "ok",
		CertNotAfter: now.Add(30 * 24 * time.Hour).UnixNano(), LastSeen: now.Add(-10 * time.Second).UnixNano(), Health: "ok",
	}}
	r := Summarize(rows, now, th)
	if r.HasAlerts() || len(r.AtRisk) != 0 {
		t.Fatalf("healthy fleet should have no alerts: %+v", r)
	}
	if Summarize(nil, now, th).HasAlerts() {
		t.Fatal("empty fleet has no alerts")
	}
}
