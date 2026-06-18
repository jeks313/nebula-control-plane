package collect_test

import (
	"context"
	"crypto/sha256"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/collect"
	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/queue"
	"github.com/prometheus/client_golang/prometheus"
)

// metricValue reads one series off the default Prometheus registry (the same registry
// /metrics exposes), matching by name + the given labels. Counters/gauges return their
// value; a histogram returns its observation count. A missing series reads as 0 — which
// is exactly how an un-incremented counter should behave.
func metricValue(t *testing.T, name string, want map[string]string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			match := true
			for k, v := range want {
				if labels[k] != v {
					match = false
					break
				}
			}
			if !match {
				continue
			}
			switch {
			case m.Counter != nil:
				return m.GetCounter().GetValue()
			case m.Gauge != nil:
				return m.GetGauge().GetValue()
			case m.Histogram != nil:
				return float64(m.GetHistogram().GetSampleCount())
			}
		}
	}
	return 0
}

// TestCollectMetricsIssued: one successful CollectOnce of an issued candidate bumps
// processed{issued}, cycles{ok}, the cycle-duration histogram, and last-success.
func TestCollectMetricsIssued(t *testing.T) {
	ctx := context.Background()
	q := openQueue(t)
	secret := "retrieval-secret-metrics"
	h := sha256.Sum256([]byte(secret))
	if err := q.Publish(ctx, queue.Candidate{
		EnrollmentID: "eid-m1", PubkeyHash: "pk", RequestJWS: []byte("jws"),
		RetrievalSecretHash: h[:], ReceivedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	gwCert, gwPin := mustCert(t, "gateway")
	harborCert, harborPin := mustCert(t, "harbor")
	srv := httptest.NewUnstartedServer(collect.NewServer(q, nil).Handler())
	srv.TLS = collect.ServerTLS(gwCert, harborPin)
	srv.StartTLS()
	defer srv.Close()

	const gwName = "metrics-issued-gw" // unique label so we read only this test's series
	sink := collect.NewCaptureSink()
	coll := collect.New(collect.Config{Processor: &fakeProc{sink: sink}, Sink: sink, ClientCert: harborCert, Batch: 10})
	if _, err := coll.CollectOnce(ctx, collect.Gateway{Name: gwName, URL: srv.URL, ServerCertPin: gwPin}); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}

	if got := metricValue(t, "ncp_collect_processed_total", map[string]string{"gateway": gwName, "outcome": "issued"}); got != 1 {
		t.Errorf("processed{issued} = %v, want 1", got)
	}
	if got := metricValue(t, "ncp_collect_cycles_total", map[string]string{"gateway": gwName, "result": "ok"}); got != 1 {
		t.Errorf("cycles{ok} = %v, want 1", got)
	}
	if got := metricValue(t, "ncp_collect_cycle_seconds", map[string]string{"gateway": gwName}); got != 1 {
		t.Errorf("cycle_seconds sample count = %v, want 1", got)
	}
	if got := metricValue(t, "ncp_collect_last_success_seconds", map[string]string{"gateway": gwName}); got <= 0 {
		t.Errorf("last_success_seconds = %v, want > 0", got)
	}
}

// pendingProc mirrors a manual-approval join key: it records a pending result (no
// bundle) and returns StatusPending with no error — which must land in the "pending"
// outcome, not "issued".
type pendingProc struct{ sink *collect.CaptureSink }

func (p *pendingProc) Process(ctx context.Context, cand queue.Candidate) (enrollment.Result, error) {
	_ = p.sink.PutResult(ctx, cand.EnrollmentID, "pending", cand.RetrievalSecretHash, nil, "", time.Time{})
	return enrollment.Result{EnrollmentID: cand.EnrollmentID, Status: enrollment.StatusPending}, nil
}

// TestCollectMetricsPending: a pending (manual-approval) candidate increments
// processed{pending}, not processed{issued}.
func TestCollectMetricsPending(t *testing.T) {
	ctx := context.Background()
	q := openQueue(t)
	secret := "retrieval-secret-pending"
	h := sha256.Sum256([]byte(secret))
	if err := q.Publish(ctx, queue.Candidate{
		EnrollmentID: "eid-p1", PubkeyHash: "pk", RequestJWS: []byte("jws"),
		RetrievalSecretHash: h[:], ReceivedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	gwCert, gwPin := mustCert(t, "gateway")
	harborCert, harborPin := mustCert(t, "harbor")
	srv := httptest.NewUnstartedServer(collect.NewServer(q, nil).Handler())
	srv.TLS = collect.ServerTLS(gwCert, harborPin)
	srv.StartTLS()
	defer srv.Close()

	const gwName = "metrics-pending-gw"
	sink := collect.NewCaptureSink()
	coll := collect.New(collect.Config{Processor: &pendingProc{sink: sink}, Sink: sink, ClientCert: harborCert, Batch: 10})
	if _, err := coll.CollectOnce(ctx, collect.Gateway{Name: gwName, URL: srv.URL, ServerCertPin: gwPin}); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}

	if got := metricValue(t, "ncp_collect_processed_total", map[string]string{"gateway": gwName, "outcome": "pending"}); got != 1 {
		t.Errorf("processed{pending} = %v, want 1", got)
	}
	if got := metricValue(t, "ncp_collect_processed_total", map[string]string{"gateway": gwName, "outcome": "issued"}); got != 0 {
		t.Errorf("processed{issued} = %v, want 0 (pending must not count as issued)", got)
	}
}

// TestCollectMetricsClaimError: a wrong-pinned gateway fails the claim, bumping
// errors{phase=claim} and cycles{error} and leaving last-success unset.
func TestCollectMetricsClaimError(t *testing.T) {
	ctx := context.Background()
	q := openQueue(t)
	gwCert, _ := mustCert(t, "gateway")
	harborCert, harborPin := mustCert(t, "harbor")
	_, wrongPin := mustCert(t, "imposter") // not the gateway's pin

	srv := httptest.NewUnstartedServer(collect.NewServer(q, nil).Handler())
	srv.TLS = collect.ServerTLS(gwCert, harborPin)
	srv.StartTLS()
	defer srv.Close()

	const gwName = "metrics-claimerr-gw"
	sink := collect.NewCaptureSink()
	coll := collect.New(collect.Config{Processor: &fakeProc{sink: sink}, Sink: sink, ClientCert: harborCert, Batch: 10})
	if _, err := coll.CollectOnce(ctx, collect.Gateway{Name: gwName, URL: srv.URL, ServerCertPin: wrongPin}); err == nil {
		t.Fatal("expected a claim failure against a wrong-pinned gateway")
	}

	if got := metricValue(t, "ncp_collect_errors_total", map[string]string{"gateway": gwName, "phase": "claim"}); got != 1 {
		t.Errorf("errors{claim} = %v, want 1", got)
	}
	if got := metricValue(t, "ncp_collect_cycles_total", map[string]string{"gateway": gwName, "result": "error"}); got != 1 {
		t.Errorf("cycles{error} = %v, want 1", got)
	}
	if got := metricValue(t, "ncp_collect_last_success_seconds", map[string]string{"gateway": gwName}); got != 0 {
		t.Errorf("last_success_seconds = %v, want 0 (never succeeded)", got)
	}
}
