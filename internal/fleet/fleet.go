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
		notAfter := time.Unix(0, r.CertNotAfter)
		lastSeen := time.Unix(0, r.LastSeen)
		d := Device{
			OverlayIP: r.OverlayIP, Name: r.DeviceName, CertNotAfter: notAfter,
			LastSeen: lastSeen, ClockOffsetMs: r.ClockOffsetMs, Health: r.Health,
		}

		switch {
		case r.CertNotAfter != 0 && notAfter.Before(now):
			rep.Expired++
			d.Reasons = append(d.Reasons, "expired")
		case r.CertNotAfter != 0 && notAfter.Sub(now) < th.ExpiryWindow:
			rep.ExpiringSoon++
			d.Reasons = append(d.Reasons, "expiring")
		}
		if th.StaleAfter > 0 && now.Sub(lastSeen) > th.StaleAfter {
			rep.Stale++
			d.Reasons = append(d.Reasons, "stale")
		}
		if th.ClockSkewMs > 0 && abs(r.ClockOffsetMs) > th.ClockSkewMs {
			rep.ClockSkewed++
		}
		if r.Health != "" && r.Health != "ok" {
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
