package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/gateway"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/queue"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

func newDurableQueue(t *testing.T) *queue.Durable {
	t.Helper()
	d, err := queue.OpenDurable(queue.DurableConfig{
		DSN: filepath.Join(t.TempDir(), "q.db") + "?_pragma=busy_timeout(5000)",
		Key: make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// TestGatewayToQueueToCore is the M3.3a end-to-end: the gateway publishes a
// vetted candidate to the durable queue, Core drains it, and the enrollment is
// processed — gateway and Core communicating only through the queue.
func TestGatewayToQueueToCore(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()
	d := newDurableQueue(t)

	gw := gateway.New(gateway.Config{Nonces: e.ring, Queue: d}).Handler()
	secret, _, _ := joinkey.Create(ctx, e.store, joinkey.Params{Name: "q", Groups: []string{"web"}, MaxUses: 0, AutoIssue: true}, time.Now())

	// A host submits a signed enroll request to the gateway.
	priv, _, n := e.fresh(t)
	body := signBody(t, priv, n, secret, "host-q")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/enroll", strings.NewReader(string(body))))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("enroll status = %d; body=%s", rec.Code, rec.Body)
	}
	var acc wire.EnrollAccepted
	if err := json.Unmarshal(rec.Body.Bytes(), &acc); err != nil {
		t.Fatal(err)
	}

	if depth, _ := d.Depth(ctx); depth != 1 {
		t.Fatalf("queue depth = %d, want 1", depth)
	}

	// Core drains the queue and processes.
	if processed, err := e.cons.Drain(ctx, d, 10, time.Minute); err != nil || processed != 1 {
		t.Fatalf("drain = %d, %v", processed, err)
	}
	if depth, _ := d.Depth(ctx); depth != 0 {
		t.Fatalf("queue depth after drain = %d, want 0 (acked)", depth)
	}

	// The enrollment was recorded + issued (auto_issue key).
	var en enrollment.Enrollment
	if err := e.store.DB.Where("enrollment_id = ?", acc.EnrollmentID).First(&en).Error; err != nil {
		t.Fatal(err)
	}
	if en.Status != enrollment.StatusIssued || len(en.CertPEM) == 0 {
		t.Fatalf("enrollment not issued: %+v", en.Status)
	}
	e.verifyCert(t, en.CertPEM)
}
