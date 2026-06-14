package collect_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/collect"
	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/queue"
)

// fakeProc mirrors what a real enrollment.Consumer does: it writes the issued
// result to the sink (which the collector drains + ships back) and returns issued.
type fakeProc struct{ sink *collect.CaptureSink }

func (f *fakeProc) Process(ctx context.Context, cand queue.Candidate) (enrollment.Result, error) {
	_ = f.sink.PutResult(ctx, cand.EnrollmentID, "issued", cand.RetrievalSecretHash,
		[]byte(`{"bundle":"`+cand.EnrollmentID+`"}`), "", time.Now().Add(time.Hour))
	return enrollment.Result{EnrollmentID: cand.EnrollmentID, Status: "issued"}, nil
}

func mustCert(t *testing.T, cn string) (tls.Certificate, [32]byte) {
	t.Helper()
	certPEM, keyPEM, err := collect.GenerateSelfSigned(cn, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := collect.PinFromCertPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return kp, pin
}

func openQueue(t *testing.T) *queue.Durable {
	t.Helper()
	q, err := queue.OpenDurable(queue.DurableConfig{
		DSN: filepath.Join(t.TempDir(), "q.db") + "?_pragma=busy_timeout(5000)", Key: make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { q.Close() })
	return q
}

// TestPullTransportEndToEnd is the ADR-0005 Phase-1 acceptance: Harbor PULLS a
// queued candidate from a gateway over leaf-pinned mTLS, processes it, ships the
// result back (so the host can poll the gateway), and acks it — the gateway
// initiating nothing.
func TestPullTransportEndToEnd(t *testing.T) {
	ctx := context.Background()
	q := openQueue(t) // the gateway's LOCAL queue

	// A vetted candidate the gateway would have queued (secret hash known to us).
	secret := "retrieval-secret-xyz"
	h := sha256.Sum256([]byte(secret))
	if err := q.Publish(ctx, queue.Candidate{
		EnrollmentID: "eid-1", PubkeyHash: "pk", RequestJWS: []byte("jws"),
		RetrievalSecretHash: h[:], ReceivedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	// mTLS identities: gateway server cert + Harbor client cert, each leaf-pinned.
	gwCert, gwPin := mustCert(t, "gateway")
	harborCert, harborPin := mustCert(t, "harbor")

	srv := httptest.NewUnstartedServer(collect.NewServer(q, nil).Handler())
	srv.TLS = collect.ServerTLS(gwCert, harborPin) // require + pin Harbor's client cert
	srv.StartTLS()
	defer srv.Close()

	sink := collect.NewCaptureSink()
	coll := collect.New(collect.Config{Processor: &fakeProc{sink: sink}, Sink: sink, ClientCert: harborCert, Batch: 10})

	n, err := coll.CollectOnce(ctx, collect.Gateway{Name: "gw1", URL: srv.URL, ServerCertPin: gwPin})
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("claimed %d, want 1", n)
	}

	// The issued result was shipped back to the gateway's queue — the host polls it.
	res, err := q.GetResult(ctx, "eid-1", secret)
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if res.Status != "issued" || len(res.Bundle) == 0 {
		t.Fatalf("result = %+v, want issued with a bundle", res)
	}
	// The candidate was acked (consumed), so the queue is drained.
	if depth, _ := q.Depth(ctx); depth != 0 {
		t.Fatalf("queue depth = %d after ack, want 0", depth)
	}
	// A second collect finds nothing.
	if n, err := coll.CollectOnce(ctx, collect.Gateway{Name: "gw1", URL: srv.URL, ServerCertPin: gwPin}); err != nil || n != 0 {
		t.Fatalf("second collect = (%d, %v), want (0, nil)", n, err)
	}
}

// TestWrongServerPinRefused: the collector must refuse a gateway whose server cert
// doesn't match the pinned leaf (a MITM / wrong endpoint) — no candidate leaks.
func TestWrongServerPinRefused(t *testing.T) {
	ctx := context.Background()
	q := openQueue(t)
	gwCert, _ := mustCert(t, "gateway")
	harborCert, harborPin := mustCert(t, "harbor")
	_, wrongPin := mustCert(t, "imposter") // a pin that is NOT the gateway's

	srv := httptest.NewUnstartedServer(collect.NewServer(q, nil).Handler())
	srv.TLS = collect.ServerTLS(gwCert, harborPin)
	srv.StartTLS()
	defer srv.Close()

	sink := collect.NewCaptureSink()
	coll := collect.New(collect.Config{Processor: &fakeProc{sink: sink}, Sink: sink, ClientCert: harborCert, Batch: 10})
	if _, err := coll.CollectOnce(ctx, collect.Gateway{Name: "gw1", URL: srv.URL, ServerCertPin: wrongPin}); err == nil {
		t.Fatal("collect against a wrong-pinned gateway must fail the TLS handshake")
	}
}

// TestGatewayRejectsUnpinnedClient: the gateway must reject a client whose cert is
// not Harbor's pinned client cert (only Harbor may drain it).
func TestGatewayRejectsUnpinnedClient(t *testing.T) {
	ctx := context.Background()
	q := openQueue(t)
	gwCert, gwPin := mustCert(t, "gateway")
	_, harborPin := mustCert(t, "harbor")
	imposterCert, _ := mustCert(t, "imposter") // not the pinned Harbor client

	srv := httptest.NewUnstartedServer(collect.NewServer(q, nil).Handler())
	srv.TLS = collect.ServerTLS(gwCert, harborPin)
	srv.StartTLS()
	defer srv.Close()

	sink := collect.NewCaptureSink()
	coll := collect.New(collect.Config{Processor: &fakeProc{sink: sink}, Sink: sink, ClientCert: imposterCert, Batch: 10})
	if _, err := coll.CollectOnce(ctx, collect.Gateway{Name: "gw1", URL: srv.URL, ServerCertPin: gwPin}); err == nil {
		t.Fatal("gateway must reject a client cert that isn't Harbor's pinned cert")
	}
}
