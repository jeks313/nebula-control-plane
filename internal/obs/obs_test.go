package obs

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func do(h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestMountHealthy(t *testing.T) {
	mux := http.NewServeMux()
	Mount(mux, Check{Name: "ok-dep", Probe: func(context.Context) error { return nil }})

	if rec := do(mux, "/healthz"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ok") {
		t.Errorf("/healthz = %d %q", rec.Code, rec.Body.String())
	}
	if rec := do(mux, "/readyz"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Errorf("/readyz (healthy) = %d %q", rec.Code, rec.Body.String())
	}
	// /metrics serves the default registry — Go runtime collectors give a non-empty exposition.
	if rec := do(mux, "/metrics"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "# HELP") {
		t.Errorf("/metrics = %d (len %d)", rec.Code, rec.Body.Len())
	}
}

func TestReadyzUnhealthy(t *testing.T) {
	mux := http.NewServeMux()
	Mount(mux, Check{Name: "db", Probe: func(context.Context) error { return errors.New("down") }})

	rec := do(mux, "/readyz")
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz code = %d, want 503", rec.Code)
	}
	// Body names the failed check but NOT the raw error ("down") — unauthenticated endpoint.
	if b := rec.Body.String(); !strings.Contains(b, "unavailable") || !strings.Contains(b, "db") {
		t.Errorf("/readyz body = %q", b)
	}
	if b := rec.Body.String(); strings.Contains(b, "down") {
		t.Errorf("/readyz body leaked the raw probe error: %q", b)
	}
}

func TestCacheReusesResult(t *testing.T) {
	calls := 0
	c := Cache(time.Minute, Check{Name: "x", Probe: func(context.Context) error {
		calls++
		return nil
	}})
	for i := 0; i < 5; i++ {
		if err := c.Probe(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Errorf("probe ran %d times, want 1 (cached for the ttl)", calls)
	}
}
