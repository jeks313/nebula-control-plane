package collect

import (
	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Prometheus metrics for the Harbor-side pull collector (ADR 0005). They register on
// the default registry at init, so they surface on `harbor collect`'s internal
// /metrics listener (internal/obs) alongside the Go runtime + process collectors —
// which is what turns harbor-collect from runtime-only telemetry into something that
// reports what the collector is actually doing. Every series is labelled by gateway
// (low cardinality — the few registered gateways Harbor pulls from). The values are
// meaningful only in the collect process; in other harbor processes that link this
// package they simply sit at zero.
var (
	metricCollectCycles = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ncp_collect_cycles_total",
		Help: "Collector claim->process->ship->ack cycles (one CollectOnce), by gateway and result (ok|error).",
	}, []string{"gateway", "result"})

	metricCollectProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ncp_collect_processed_total",
		Help: "Candidates processed by the collector, by gateway and outcome (issued|denied|pending|terminal_error|transient_error).",
	}, []string{"gateway", "outcome"})

	metricCollectErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ncp_collect_errors_total",
		Help: "Collector transport/protocol failures by gateway and phase (claim|ship|ack); each failed cycle bumps exactly one phase here and ncp_collect_cycles_total{result=error}.",
	}, []string{"gateway", "phase"})

	metricCollectCycleSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "ncp_collect_cycle_seconds",
		Help: "Wall-clock duration of one collector cycle (CollectOnce), by gateway.",
		// A cycle is up to three sequential HTTP posts (claim/ship/ack), each with a 30s
		// client timeout, so buckets extend past DefBuckets' 10s top to keep tail latency
		// visible rather than collapsing it into +Inf.
		Buckets: []float64{0.005, 0.025, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60},
	}, []string{"gateway"})

	metricCollectLastSuccess = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ncp_collect_last_success_seconds",
		Help: "Unix timestamp of the last error-free collector cycle, by gateway (for staleness alerting).",
	}, []string{"gateway"})
)

// outcomeLabel maps a processed candidate's (result, error) to a metric outcome,
// mirroring the collector's own ack/nack decision: issued, denied, pending, and
// terminal_error are all acked (a final disposition for this poll), while
// transient_error is nacked for redelivery. The clean (err == nil) outcomes are
// distinguished by status — a manual-approval join key (or a replayed recorded
// pending) returns StatusPending with no cert yet, which must NOT be counted as
// issued; an explicit deny returns StatusDenied; everything else clean is issued.
func outcomeLabel(res enrollment.Result, err error) string {
	switch {
	case err == nil && res.Status == enrollment.StatusDenied:
		return "denied"
	case err == nil && res.Status == enrollment.StatusPending:
		return "pending"
	case err == nil:
		return "issued" // StatusIssued — the remaining clean outcome
	case enrollment.Terminal(err):
		return "terminal_error"
	default:
		return "transient_error"
	}
}
