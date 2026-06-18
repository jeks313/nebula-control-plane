// Package obs provides the Phase 7 observability endpoints — Prometheus /metrics,
// /healthz (liveness), and /readyz (readiness) — and a one-call Mount to add them to a
// component's HTTP mux. /metrics exposes the default Prometheus registry, so the Go
// runtime + process collectors come for free alongside the app metrics that other
// packages register via promauto.
//
// All three endpoints are UNAUTHENTICATED — they are scraped by monitoring infra, expose
// no secrets, and on the public-facing gateway are served on a SEPARATE internal listener
// (never the public enroll port).
package obs

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Check is a named readiness probe; Probe returns nil when the dependency is healthy.
type Check struct {
	Name  string
	Probe func(ctx context.Context) error
}

// Cache wraps a Check so its probe result is reused for ttl. Repeated /readyz hits then
// don't each run the probe — important when the probe contends for a scarce resource (e.g.
// the single SQLite connection), which would otherwise let an unauthenticated /readyz flood
// starve real traffic. The probe is serialized (one in flight at a time) and thread-safe.
func Cache(ttl time.Duration, c Check) Check {
	var (
		mu      sync.Mutex
		fetched time.Time
		err     error
		done    bool
	)
	return Check{Name: c.Name, Probe: func(ctx context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		if done && time.Since(fetched) < ttl {
			return err
		}
		err = c.Probe(ctx)
		fetched = time.Now()
		done = true
		return err
	}}
}

// readyTimeout bounds how long all readiness probes together may take.
const readyTimeout = 3 * time.Second

// Mount adds GET /metrics, /healthz, and /readyz to mux. /healthz is a pure liveness
// signal (the process is up and serving); /readyz runs the supplied checks on each request
// and returns 503 with a JSON body if any fails.
func Mount(mux *http.ServeMux, ready ...Check) {
	mux.Handle("GET /metrics", promhttp.Handler())
	mux.HandleFunc("GET /healthz", liveness)
	mux.HandleFunc("GET /readyz", readiness(ready))
}

// Serve runs /metrics + /healthz + /readyz on addr in background goroutines, shutting down
// gracefully when ctx is cancelled. Plaintext + unauthenticated — an INTERNAL listener only
// (never a public port). The one-call form for a component that doesn't already run an HTTP
// server on the scrape interface (e.g. harbor collect).
func Serve(ctx context.Context, addr string, log *slog.Logger, ready ...Check) {
	mux := http.NewServeMux()
	Mount(mux, ready...)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sc)
	}()
	go func() {
		log.Info("observability listening", "addr", addr, "endpoints", "/metrics /healthz /readyz", "access", "internal")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("obs server failed", "err", err)
		}
	}()
}

func liveness(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func readiness(checks []Check) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), readyTimeout)
		defer cancel()
		var failed []string
		for _, c := range checks {
			if err := c.Probe(ctx); err != nil {
				failed = append(failed, c.Name)
			}
		}
		sort.Strings(failed)
		w.Header().Set("Content-Type", "application/json")
		if len(failed) > 0 {
			// Report WHICH dependency failed, not the raw probe error — this endpoint is
			// unauthenticated, and the error detail belongs in the component's own logs.
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "unavailable", "failed": failed})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	}
}
