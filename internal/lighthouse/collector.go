package lighthouse

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/slackhq/nebula/cert"
	"gorm.io/gorm"
)

// Lighthouse rotation observability (the "everything observable" tenet for the scheduled
// Fargate-lighthouse cert rotation). Computed at SCRAPE TIME by Collector — a
// prometheus.Collector that reads the issued lighthouse certs + the rotation run-record on each
// /metrics request — so the values are always live. Two concerns:
//
//   - BACKSTOP (the outcome): ncp_lighthouse_cert_expiry_seconds{name} — seconds until each
//     issued lighthouse cert expires, read straight from the enrollment cert. If this drops, the
//     cert is not being kept fresh — for ANY reason (timer off, script bug, ECS stuck, KMS perm,
//     secret-inject failed). Critically, lighthouses are NOT `harbor fleet` members, so the
//     fleet/renewal-health metrics never see them — this is the only signal that does.
//   - LIVENESS (the job): ncp_lighthouse_rotation_last_run_seconds / _last_rotated_seconds (unix
//     time; time()-value = age) + _runs_total{result} — written by the rotation timer via
//     `harbor lighthouse rotation-record`. Detects a dead timer / a failing run before the cert
//     is at risk, and tells you which part broke.
var (
	descCertExpiry = prometheus.NewDesc(
		"ncp_lighthouse_cert_expiry_seconds",
		"Seconds until the lighthouse's issued certificate expires, by lighthouse name (the rotation BACKSTOP — lighthouses are not fleet members, so nothing else observes these certs). Negative once expired.",
		[]string{"name"}, nil,
	)
	descRotationLastRun = prometheus.NewDesc(
		"ncp_lighthouse_rotation_last_run_seconds",
		"Unix time of the last rotation-check run for a lighthouse (any result); time()-this is the age. Detects a dead rotation timer.",
		[]string{"name"}, nil,
	)
	descRotationLastRotated = prometheus.NewDesc(
		"ncp_lighthouse_rotation_last_rotated_seconds",
		"Unix time of the last ACTUAL cert rotation for a lighthouse (0 = never rotated).",
		[]string{"name"}, nil,
	)
	descRotationRuns = prometheus.NewDesc(
		"ncp_lighthouse_rotation_runs_total",
		"Count of rotation-check runs for a lighthouse, by result (ok|skip|fail).",
		[]string{"name", "result"}, nil,
	)
)

// Collector emits the lighthouse cert-expiry + rotation-liveness metrics at scrape time. Robust
// to a nil/empty DB (emits nothing) and never panics on a transient query/parse error (skips that
// series). It reads tables directly via minimal local read-models (no import of internal/enrollment,
// avoiding a cycle) — mirroring internal/ipam's NetblockCollector.
type Collector struct {
	db  *gorm.DB
	now func() time.Time
}

// NewCollector builds the collector over a store DB.
func NewCollector(db *gorm.DB) *Collector { return &Collector{db: db, now: time.Now} }

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descCertExpiry
	ch <- descRotationLastRun
	ch <- descRotationLastRotated
	ch <- descRotationRuns
}

// lhEnroll is the minimal read-model of an issued lighthouse enrollment.
type lhEnroll struct {
	ID         int64  `gorm:"column:id"`
	DeviceName string `gorm:"column:device_name"`
	CertPEM    []byte `gorm:"column:cert_pem"`
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	if c == nil || c.db == nil {
		return
	}
	ctx := context.Background()
	now := c.now()

	// BACKSTOP: per-lighthouse cert expiry from the issued lighthouse enrollments. Dedupe by name
	// (rotate-cert updates the row in place, so normally one issued row per name; if duplicates
	// exist, keep the latest-expiring so Prometheus never sees a duplicate label set).
	var rows []lhEnroll
	if err := c.db.WithContext(ctx).Table("enrollments").
		Select("id, device_name, cert_pem").
		Where("status = ? AND groups LIKE ?", "issued", "%lighthouse%").
		Find(&rows).Error; err == nil {
		latest := map[string]time.Time{}
		for _, r := range rows {
			crt, _, perr := cert.UnmarshalCertificateFromPEM(r.CertPEM)
			if perr != nil {
				continue
			}
			na := crt.NotAfter()
			if cur, ok := latest[r.DeviceName]; !ok || na.After(cur) {
				latest[r.DeviceName] = na
			}
		}
		for name, na := range latest {
			ch <- prometheus.MustNewConstMetric(descCertExpiry, prometheus.GaugeValue, na.Sub(now).Seconds(), name)
		}
	}

	// LIVENESS: the rotation run-record.
	var rs []RotationStatus
	if err := c.db.WithContext(ctx).Find(&rs).Error; err == nil {
		for _, s := range rs {
			ch <- prometheus.MustNewConstMetric(descRotationLastRun, prometheus.GaugeValue, float64(s.LastRunAt), s.Name)
			ch <- prometheus.MustNewConstMetric(descRotationLastRotated, prometheus.GaugeValue, float64(s.LastRotatedAt), s.Name)
			ch <- prometheus.MustNewConstMetric(descRotationRuns, prometheus.CounterValue, float64(s.RunsOK), s.Name, "ok")
			ch <- prometheus.MustNewConstMetric(descRotationRuns, prometheus.CounterValue, float64(s.RunsSkip), s.Name, "skip")
			ch <- prometheus.MustNewConstMetric(descRotationRuns, prometheus.CounterValue, float64(s.RunsFail), s.Name, "fail")
		}
	}
}

// RegisterCollector registers the lighthouse collector on the default Prometheus registry
// (exposed by every component's /metrics). Idempotent + race-safe across core-api/collect in one
// process — a second register (or AlreadyRegistered) is a no-op, never a double-register panic.
func RegisterCollector(c *Collector) error { return registerOn(prometheus.DefaultRegisterer, c) }

var (
	regMu   sync.Mutex
	regDone bool
)

func registerOn(reg prometheus.Registerer, c *Collector) error {
	if reg == nil || c == nil {
		return nil
	}
	regMu.Lock()
	defer regMu.Unlock()
	if regDone {
		return nil
	}
	if err := reg.Register(c); err != nil {
		if _, ok := err.(prometheus.AlreadyRegisteredError); ok {
			regDone = true
			return nil
		}
		return err
	}
	regDone = true
	return nil
}
