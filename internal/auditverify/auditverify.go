// Package auditverify periodically re-verifies Harbor's hash-chained audit log and exports
// the result as Prometheus metrics, so tampering (or a chain that won't read) raises an
// operator alarm instead of being caught only by an ad-hoc `harbor audit verify` (ADR 0007
// Phase 7). It deliberately distinguishes an INTEGRITY failure (ErrAuditTampered — a
// security event) from a transient read error.
//
// Each run re-walks the entire chain (store.VerifyAudit is O(rows) — the hash linkage must
// be checked end to end). At the default hourly cadence and current audit sizes that is
// cheap; for very large histories a future optimization is incremental verification from a
// persisted last-verified checkpoint.
package auditverify

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	metricRuns = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ncp_audit_verify_runs_total",
		Help: "Total audit-chain verification runs.",
	})
	metricFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ncp_audit_verify_failures_total",
		Help: "Audit-chain verification failures (tamper OR a read error — any non-clean result).",
	})
	metricTampered = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ncp_audit_verify_tampered_total",
		Help: "Audit-chain INTEGRITY failures (ErrAuditTampered) — a security event, distinct from a transient read error.",
	})
	metricRows = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ncp_audit_verify_rows",
		Help: "Rows verified by the last clean audit-chain check.",
	})
	metricLastSuccess = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ncp_audit_verify_last_success_seconds",
		Help: "Unix timestamp of the last successful (clean) audit-chain verification.",
	})
)

// verifier is the minimal store surface needed (*store.Store satisfies it).
type verifier interface {
	VerifyAudit(ctx context.Context) (int64, error)
}

// Verifier periodically re-verifies the audit chain.
type Verifier struct {
	store    verifier
	interval time.Duration
	log      *slog.Logger
	now      func() time.Time
}

// New builds a Verifier. interval <= 0 defaults to 1h.
func New(s verifier, interval time.Duration, log *slog.Logger) *Verifier {
	if interval <= 0 {
		interval = time.Hour
	}
	return &Verifier{store: s, interval: interval, log: log, now: time.Now}
}

// Run verifies once immediately, then every interval, until ctx is cancelled.
func (v *Verifier) Run(ctx context.Context) {
	v.verifyOnce(ctx)
	t := time.NewTicker(v.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			v.verifyOnce(ctx)
		}
	}
}

// verifyOnce runs a single verification and updates the metrics. Split out for testing.
func (v *Verifier) verifyOnce(ctx context.Context) {
	metricRuns.Inc()
	n, err := v.store.VerifyAudit(ctx)
	if err == nil {
		metricRows.Set(float64(n))
		metricLastSuccess.Set(float64(v.now().Unix()))
		return
	}
	metricFailures.Inc()
	if errors.Is(err, store.ErrAuditTampered) {
		metricTampered.Inc()
		if v.log != nil {
			v.log.Error("audit-chain integrity FAILURE (tamper)", "rows_ok", n, "err", err)
		}
		return
	}
	if v.log != nil {
		v.log.Warn("audit-chain verification could not complete (transient?)", "rows_ok", n, "err", err)
	}
}
