// Package fleet reports fleet health from persisted heartbeats (implementation-
// plan 4.7): cert-expiry posture, stale/missing heartbeats (the tell-tale of a
// blocked renewal or a down host), clock drift, and health. It is the data
// behind the expiry/health dashboards and the alerts that fire when renewal is
// blocked.
package fleet

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/store"
)

// hb maps the heartbeats table (a local view — fleet is a read-only reporter).
type hb struct {
	OverlayIP     string `gorm:"column:overlay_ip"`
	DeviceName    string `gorm:"column:device_name"`
	PilotVersion  string `gorm:"column:pilot_version"`
	CertNotAfter  int64  `gorm:"column:cert_not_after"`
	ClockOffsetMs int    `gorm:"column:clock_offset_ms"`
	Health        string `gorm:"column:health"`
	LastSeen      int64  `gorm:"column:last_seen"`
}

func (hb) TableName() string { return "heartbeats" }

// Thresholds tune the report's alert conditions.
type Thresholds struct {
	ExpiryWindow time.Duration // flag certs expiring within this
	StaleAfter   time.Duration // flag devices not heard from within this
	ClockSkewMs  int           // flag |clock offset| beyond this
}

// Condition tokens name the per-device health states. They are the vocabulary the
// dashboard "why" drill-down and the /admin/v1/devices?condition= filter share.
const (
	CondExpired     = "expired"
	CondExpiring    = "expiring"
	CondStale       = "stale"
	CondClockSkewed = "clock_skewed"
	CondUnhealthy   = "unhealthy"
)

// conditions is the set of health states a single heartbeat is in.
type conditions struct {
	Expired     bool
	Expiring    bool
	Stale       bool
	ClockSkewed bool
	Unhealthy   bool
}

// classify is THE per-device health definition. Summarize (the /fleet/health
// counts) consumes it directly, and ConditionSQL is its SQL twin (cross-checked by
// a test against this logic), so the dashboard verdict and its /devices drill-down
// can never drift. expired and expiring are mutually exclusive (an already-expired
// cert is counted expired, not expiring).
func classify(certNotAfter, lastSeen int64, clockOffsetMs int, health string, now time.Time, th Thresholds) conditions {
	var c conditions
	switch {
	case certNotAfter != 0 && time.Unix(0, certNotAfter).Before(now):
		c.Expired = true
	case certNotAfter != 0 && time.Unix(0, certNotAfter).Sub(now) < th.ExpiryWindow:
		c.Expiring = true
	}
	if th.StaleAfter > 0 && now.Sub(time.Unix(0, lastSeen)) > th.StaleAfter {
		c.Stale = true
	}
	if th.ClockSkewMs > 0 && abs(clockOffsetMs) > th.ClockSkewMs {
		c.ClockSkewed = true
	}
	if health != "" && health != "ok" {
		c.Unhealthy = true
	}
	return c
}

// ConditionSQL returns a portable SQL predicate (and bind args) selecting the
// heartbeats rows matching a health condition, computed from the SAME thresholds
// and clock as Rollup/classify. ok=false for an unknown token. The predicates are
// the SQL twin of classify()'s Go comparisons — a test asserts /devices?condition=X
// returns exactly the rows /fleet/health counts — so the verdict and its drill-down
// stay consistent. Referenced columns all exist on the heartbeats table; works on
// both sqlite and postgres (plain integer/string comparisons, no DB date funcs).
func ConditionSQL(cond string, now time.Time, th Thresholds) (string, []any, bool) {
	nowNs := now.UnixNano()
	switch cond {
	case CondExpired:
		return "cert_not_after != 0 AND cert_not_after < ?", []any{nowNs}, true
	case CondExpiring:
		// not yet expired (>= now) AND notAfter.Sub(now) < ExpiryWindow.
		return "cert_not_after != 0 AND cert_not_after >= ? AND cert_not_after < ?",
			[]any{nowNs, nowNs + th.ExpiryWindow.Nanoseconds()}, true
	case CondStale:
		if th.StaleAfter <= 0 {
			return "1 = 0", nil, true // disabled threshold matches nothing (mirrors classify's guard)
		}
		// now.Sub(lastSeen) > StaleAfter  <=>  last_seen < now - StaleAfter.
		return "last_seen < ?", []any{nowNs - th.StaleAfter.Nanoseconds()}, true
	case CondClockSkewed:
		if th.ClockSkewMs <= 0 {
			return "1 = 0", nil, true
		}
		// abs(clock_offset_ms) > ClockSkewMs.
		return "(clock_offset_ms > ? OR clock_offset_ms < ?)", []any{th.ClockSkewMs, -th.ClockSkewMs}, true
	case CondUnhealthy:
		return "health <> '' AND health <> 'ok'", nil, true
	}
	return "", nil, false
}

// conditionLink maps a device-condition reason code to its Devices drill-down. Non
// device reasons (audit, rollout) have no /devices target and return "".
func conditionLink(code string) string {
	switch code {
	case "CERTS_EXPIRED":
		return "/devices?condition=" + CondExpired
	case "CERTS_EXPIRING":
		return "/devices?condition=" + CondExpiring
	case "HOSTS_STALE":
		return "/devices?condition=" + CondStale
	case "CLOCK_SKEWED":
		return "/devices?condition=" + CondClockSkewed
	case "HOSTS_UNHEALTHY":
		return "/devices?condition=" + CondUnhealthy
	}
	return ""
}

// Device is a per-host view for the at-risk list.
type Device struct {
	OverlayIP, Name string
	CertNotAfter    time.Time
	LastSeen        time.Time
	ClockOffsetMs   int
	Health          string
	Reasons         []string // why it's at risk: expired | expiring | stale
}

// Report is the fleet summary.
type Report struct {
	Total        int
	Expired      int
	ExpiringSoon int
	Stale        int
	ClockSkewed  int
	Unhealthy    int
	AtRisk       []Device // expired / expiring-soon / stale, worst first
	Alerts       []string
}

// HasAlerts reports whether any renewal-health condition fired (the cron/CI
// exit signal): expired, expiring-soon, or stale devices.
func (r Report) HasAlerts() bool {
	return r.Expired > 0 || r.ExpiringSoon > 0 || r.Stale > 0
}

// Severity orders a health reason. info does not degrade the top-line status;
// degraded and critical do.
type Severity string

const (
	SevInfo     Severity = "info"
	SevDegraded Severity = "degraded"
	SevCritical Severity = "critical"
)

// Status is the fleet's single top-line health verdict.
type Status string

const (
	StatusHealthy  Status = "healthy"
	StatusDegraded Status = "degraded"
	StatusCritical Status = "critical"
)

// Reason is one contributor to fleet health (UI Implementation Plan §3.2). Codes
// are stable so the dashboard, `harbor fleet`, and webhooks all speak the same
// vocabulary.
type Reason struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Count    int      `json:"count"`
	Detail   string   `json:"detail"`
	Link     string   `json:"link,omitempty"`
}

// Health is the server-computed fleet health rollup: a single status plus the
// reasons that produced it, severity-ordered. This is THE definition (computed
// server-side, never in the client) shared across the dashboard verdict, the CLI,
// and any webhook/SIEM, so there is no drift between surfaces.
type Health struct {
	Status  Status   `json:"status"`
	Reasons []Reason `json:"reasons"`
}

// AuditState distinguishes a verified-clean chain from a tampered one from a
// check that couldn't run — so a transient DB failure never masquerades as
// tampering.
type AuditState string

const (
	AuditOK          AuditState = "ok"
	AuditTampered    AuditState = "tampered"
	AuditUnavailable AuditState = "unavailable"
)

// Rollup turns the heartbeat Report plus a few cross-cutting facts into the
// health verdict. It is pure (no DB / no engine imports): callers gather the
// inputs (audit state? current rollout state?) and pass them in.
//
//	rolloutState: "" if no rollout exists; else rollout.State* ("canary" |
//	"widening" | "rolledback" | "completed" | "aborted").
func Rollup(rep Report, audit AuditState, rolloutState string, th Thresholds) Health {
	rs := []Reason{} // never nil — the contract is always a JSON array
	add := func(sev Severity, code string, count int, detail string) {
		// Device-condition reasons carry a deep-link to the Devices list pre-filtered
		// to that condition (UI Implementation Plan §3.4); non-device reasons get "".
		rs = append(rs, Reason{Code: code, Severity: sev, Count: count, Detail: detail, Link: conditionLink(code)})
	}

	// Critical — something is actually broken or down.
	if audit == AuditTampered {
		add(SevCritical, "AUDIT_CHAIN_BROKEN", 1, "audit chain failed integrity verification")
	}
	if rep.Expired > 0 {
		add(SevCritical, "CERTS_EXPIRED", rep.Expired, fmt.Sprintf("%d device(s) have expired certs", rep.Expired))
	}
	if rolloutState == "rolledback" {
		add(SevCritical, "ROLLOUT_ROLLEDBACK", 1, "a rollout auto-rolled-back and is frozen")
	}

	// Degraded — at risk, needs attention soon.
	if rep.ExpiringSoon > 0 {
		add(SevDegraded, "CERTS_EXPIRING", rep.ExpiringSoon, fmt.Sprintf("%d cert(s) expiring within %s", rep.ExpiringSoon, th.ExpiryWindow))
	}
	if rep.Stale > 0 {
		add(SevDegraded, "HOSTS_STALE", rep.Stale, fmt.Sprintf("%d host(s) silent > %s", rep.Stale, th.StaleAfter))
	}
	if rep.ClockSkewed > 0 {
		add(SevDegraded, "CLOCK_SKEWED", rep.ClockSkewed, fmt.Sprintf("%d host(s) clock-skewed > %dms", rep.ClockSkewed, th.ClockSkewMs))
	}
	if rep.Unhealthy > 0 {
		add(SevDegraded, "HOSTS_UNHEALTHY", rep.Unhealthy, fmt.Sprintf("%d host(s) report degraded health", rep.Unhealthy))
	}

	// Degraded — the integrity check couldn't run (NOT proof of tampering, but we
	// can't currently vouch for the chain either).
	if audit == AuditUnavailable {
		add(SevDegraded, "AUDIT_CHECK_UNAVAILABLE", 1, "audit chain could not be verified right now")
	}

	// Info — notable but not degradation (a healthy fleet mid-rollout is healthy).
	if rolloutState == "canary" || rolloutState == "widening" {
		add(SevInfo, "ROLLOUT_IN_PROGRESS", 1, "a staged rollout is in progress")
	}

	// Top-line status = worst of {degraded, critical}; info never degrades it.
	status := StatusHealthy
	for _, r := range rs {
		if r.Severity == SevCritical {
			status = StatusCritical
			break
		}
		if r.Severity == SevDegraded {
			status = StatusDegraded
		}
	}

	// Order: critical, then degraded, then info (stable within a tier).
	sort.SliceStable(rs, func(i, j int) bool { return sevRank(rs[i].Severity) > sevRank(rs[j].Severity) })
	return Health{Status: status, Reasons: rs}
}

func sevRank(s Severity) int {
	switch s {
	case SevCritical:
		return 3
	case SevDegraded:
		return 2
	case SevInfo:
		return 1
	}
	return 0
}

// Generate loads heartbeats and summarizes them.
func Generate(ctx context.Context, s *store.Store, now time.Time, th Thresholds) (Report, error) {
	var rows []hb
	if err := s.DB.WithContext(ctx).Find(&rows).Error; err != nil {
		return Report{}, fmt.Errorf("fleet: load heartbeats: %w", err)
	}
	return Summarize(rows, now, th), nil
}

// Summarize is the pure reporting logic (testable without a DB).
func Summarize(rows []hb, now time.Time, th Thresholds) Report {
	rep := Report{Total: len(rows)}
	for _, r := range rows {
		d := Device{
			OverlayIP: r.OverlayIP, Name: r.DeviceName, CertNotAfter: time.Unix(0, r.CertNotAfter),
			LastSeen: time.Unix(0, r.LastSeen), ClockOffsetMs: r.ClockOffsetMs, Health: r.Health,
		}

		c := classify(r.CertNotAfter, r.LastSeen, r.ClockOffsetMs, r.Health, now, th)
		if c.Expired {
			rep.Expired++
			d.Reasons = append(d.Reasons, CondExpired)
		}
		if c.Expiring {
			rep.ExpiringSoon++
			d.Reasons = append(d.Reasons, CondExpiring)
		}
		if c.Stale {
			rep.Stale++
			d.Reasons = append(d.Reasons, CondStale)
		}
		if c.ClockSkewed {
			rep.ClockSkewed++
		}
		if c.Unhealthy {
			rep.Unhealthy++
		}
		if len(d.Reasons) > 0 {
			rep.AtRisk = append(rep.AtRisk, d)
		}
	}

	// Worst (soonest expiry) first.
	sort.Slice(rep.AtRisk, func(i, j int) bool {
		return rep.AtRisk[i].CertNotAfter.Before(rep.AtRisk[j].CertNotAfter)
	})

	if rep.Expired > 0 {
		rep.Alerts = append(rep.Alerts, fmt.Sprintf("%d device(s) have EXPIRED certs", rep.Expired))
	}
	if rep.ExpiringSoon > 0 {
		rep.Alerts = append(rep.Alerts, fmt.Sprintf("%d device(s) expire within %s (renewal may be blocked)", rep.ExpiringSoon, th.ExpiryWindow))
	}
	if rep.Stale > 0 {
		rep.Alerts = append(rep.Alerts, fmt.Sprintf("%d device(s) silent > %s (down or unable to reach Core)", rep.Stale, th.StaleAfter))
	}
	if rep.ClockSkewed > 0 {
		rep.Alerts = append(rep.Alerts, fmt.Sprintf("%d device(s) clock-skewed > %dms", rep.ClockSkewed, th.ClockSkewMs))
	}
	if rep.Unhealthy > 0 {
		rep.Alerts = append(rep.Alerts, fmt.Sprintf("%d device(s) report degraded health", rep.Unhealthy))
	}
	return rep
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
