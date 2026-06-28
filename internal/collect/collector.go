package collect

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/queue"
)

// Processor verifies + issues a claimed candidate. *enrollment.Consumer satisfies
// it; it writes the poll result to its configured ResultSink (a CaptureSink here).
type Processor interface {
	Process(ctx context.Context, cand queue.Candidate) (enrollment.Result, error)
}

// Resolver re-derives the signed result to deliver for a DECIDED enrollment (or
// ok=false if it's still pending). *enrollment.Consumer satisfies it via
// BuildDeliverable. The delivery-reconcile lane uses it to carry an admin approval to
// the gateway on Harbor's OUTBOUND poll — the gateway never calls Harbor.
type Resolver interface {
	BuildDeliverable(ctx context.Context, enrollmentID string) (status string, bundleJWS []byte, reason string, ok bool, err error)
}

// CaptureSink is an enrollment.ResultSink that buffers issued/denied results in
// memory so the collector can ship them back to the originating gateway after a
// claim batch (instead of writing them to a local queue). Drain returns + clears.
type CaptureSink struct {
	mu      sync.Mutex
	results []Result
}

// NewCaptureSink builds an empty capture sink.
func NewCaptureSink() *CaptureSink { return &CaptureSink{} }

// PutResult satisfies enrollment.ResultSink.
func (c *CaptureSink) PutResult(_ context.Context, enrollmentID, status string, secretHash, bundle []byte, reason string, expiresAt time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.results = append(c.results, Result{
		EnrollmentID: enrollmentID, Status: status, SecretHash: secretHash,
		Bundle: bundle, Reason: reason, ExpiresAt: expiresAt,
	})
	return nil
}

// Drain returns the buffered results and clears the buffer.
func (c *CaptureSink) Drain() []Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.results
	c.results = nil
	return out
}

// Gateway is a registered gateway the collector pulls from.
type Gateway struct {
	Name          string
	URL           string   // e.g. https://gw.example:9443
	ServerCertPin [32]byte // SHA-256 of the gateway's server-cert leaf DER
}

// HealthSink persists the outcome of each collect cycle per gateway so the console can
// show gateway health (a wedged gateway = stale last success + climbing failures).
// Optional — nil disables recording. consecutiveFailures is the absolute count.
type HealthSink interface {
	Record(ctx context.Context, gateway string, ok bool, lastErr string, consecutiveFailures int, at time.Time) error
}

// healthHeartbeat throttles steady-state health writes: on an unchanged ok/fail state we
// persist at most this often (a transition always writes immediately), so a healthy
// gateway polled every 1s doesn't write every cycle while staleness stays detectable.
const healthHeartbeat = 15 * time.Second

// Collector is the Harbor-side pull loop (ADR 0005). It claims candidates from a
// gateway over leaf-pinned mTLS, runs the Processor (which captures results into
// sink), ships the results back, then acks. Collection is SEQUENTIAL per gateway —
// the shared CaptureSink maps cleanly to one in-flight batch.
type Collector struct {
	proc        Processor
	sink        *CaptureSink
	clientCert  tls.Certificate
	batch       int
	leaseTTL    time.Duration
	resolver    Resolver
	deliveryTTL time.Duration
	now         func() time.Time
	httpClient  func(gw Gateway) *http.Client
	log         *slog.Logger

	health      HealthSink           // optional: persists per-gateway cycle health
	healthFails map[string]int       // consecutive failed cycles per gateway (single-writer: Run)
	healthOK    map[string]bool      // last recorded ok state per gateway (transition detection)
	healthWrote map[string]time.Time // last health write per gateway (heartbeat throttle)

	mu      sync.Mutex
	clients map[string]*http.Client // cached per gateway (name|pin) so connections pool across cycles
}

// Config parameterizes a Collector.
type Config struct {
	Processor   Processor
	Sink        *CaptureSink
	ClientCert  tls.Certificate // Harbor's pinned client identity
	Batch       int             // candidates per claim (0 -> 64)
	LeaseTTL    time.Duration   // claim lease (0 -> 60s)
	Resolver    Resolver        // delivery-reconcile: re-derive results for decided enrollments (nil disables the lane)
	DeliveryTTL time.Duration   // how long a delivered issued/denied result stays fetchable (0 -> 24h)
	Logger      *slog.Logger
	Health      HealthSink      // optional: persist per-gateway cycle health for the console
}

// New builds a Collector.
func New(cfg Config) *Collector {
	if cfg.Batch <= 0 {
		cfg.Batch = defaultClaim
	}
	if cfg.LeaseTTL <= 0 {
		cfg.LeaseTTL = defaultLeaseTTL
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.DeliveryTTL <= 0 {
		cfg.DeliveryTTL = 24 * time.Hour
	}
	c := &Collector{
		proc: cfg.Processor, sink: cfg.Sink, clientCert: cfg.ClientCert,
		batch: cfg.Batch, leaseTTL: cfg.LeaseTTL,
		resolver: cfg.Resolver, deliveryTTL: cfg.DeliveryTTL, now: time.Now,
		log:         cfg.Logger,
		health:      cfg.Health,
		healthFails: map[string]int{},
		healthOK:    map[string]bool{},
		healthWrote: map[string]time.Time{},
		clients:     map[string]*http.Client{},
	}
	c.httpClient = func(gw Gateway) *http.Client {
		return &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: ClientTLS(c.clientCert, gw.ServerCertPin)},
		}
	}
	return c
}

// clientFor returns a cached http.Client per gateway (keyed by name + cert pin) so
// connections pool across collect cycles, instead of a fresh Transport + TLS
// handshake on every CollectOnce. A changed pin yields a fresh client.
func (c *Collector) clientFor(gw Gateway) *http.Client {
	key := gw.Name + "|" + string(gw.ServerCertPin[:])
	c.mu.Lock()
	defer c.mu.Unlock()
	if cl := c.clients[key]; cl != nil {
		return cl
	}
	cl := c.httpClient(gw)
	c.clients[key] = cl
	return cl
}

// CollectOnce pulls + processes one batch from gw: claim → process → ship results
// back → ack/nack. Results are shipped BEFORE acking (at-least-once: a failed ship
// leaves the candidates leased for redelivery, and PutResult is an idempotent
// upsert). Returns the number of candidates claimed.
func (c *Collector) CollectOnce(ctx context.Context, gw Gateway) (claimed int, err error) {
	// One cycle = one CollectOnce. The defer records its duration and tallies it as
	// ok/error from the returned err, stamping last-success on a clean cycle (so a
	// stalled collector shows up as a stale ncp_collect_last_success_seconds). An
	// empty claim is still a healthy heartbeat, so it counts as ok.
	start := time.Now()
	defer func() {
		metricCollectCycleSeconds.WithLabelValues(gw.Name).Observe(time.Since(start).Seconds())
		if err != nil {
			metricCollectCycles.WithLabelValues(gw.Name, "error").Inc()
			return
		}
		metricCollectCycles.WithLabelValues(gw.Name, "ok").Inc()
		metricCollectLastSuccess.WithLabelValues(gw.Name).Set(float64(time.Now().Unix()))
	}()

	client := c.clientFor(gw)

	var cr ClaimResponse
	if err := c.post(ctx, client, gw, "/collect/v1/claim", ClaimRequest{Limit: c.batch, LeaseMs: c.leaseTTL.Milliseconds()}, &cr); err != nil {
		metricCollectErrors.WithLabelValues(gw.Name, "claim").Inc()
		return 0, fmt.Errorf("claim: %w", err)
	}
	if len(cr.Candidates) == 0 {
		return 0, nil
	}

	c.sink.Drain() // discard anything stale before this batch
	var ackIDs, nackIDs []int64
	for _, cand := range cr.Candidates {
		res, perr := c.proc.Process(ctx, queue.Candidate{
			EnrollmentID: cand.EnrollmentID, PubkeyHash: cand.PubkeyHash,
			RequestJWS: cand.RequestJWS, RetrievalSecretHash: cand.RetrievalSecretHash, ReceivedAt: cand.ReceivedAt,
		})
		metricCollectProcessed.WithLabelValues(gw.Name, outcomeLabel(res, perr)).Inc()
		if perr == nil || enrollment.Terminal(perr) {
			ackIDs = append(ackIDs, cand.LeaseID)
		} else {
			nackIDs = append(nackIDs, cand.LeaseID)
			c.log.Warn("collect: transient processing failure; will redeliver", "gateway", gw.Name, "enrollment", cand.EnrollmentID, "err", perr)
		}
	}

	// Ship results FIRST — if this fails we return without acking, so the gateway
	// redelivers and we re-ship (PutResult upserts). Never ack a result we failed
	// to deliver, or the host would never get its bundle.
	if results := c.sink.Drain(); len(results) > 0 {
		if err := c.post(ctx, client, gw, "/collect/v1/results", PutResultsRequest{Results: results}, nil); err != nil {
			metricCollectErrors.WithLabelValues(gw.Name, "ship").Inc()
			return len(cr.Candidates), fmt.Errorf("ship results: %w", err)
		}
	}
	if err := c.post(ctx, client, gw, "/collect/v1/ack", AckRequest{Ack: ackIDs, Nack: nackIDs}, nil); err != nil {
		metricCollectErrors.WithLabelValues(gw.Name, "ack").Inc()
		return len(cr.Candidates), fmt.Errorf("ack: %w", err)
	}
	return len(cr.Candidates), nil
}

// Run polls every gateway from gateways() each interval, draining each to empty
// before moving on, until ctx is cancelled. A per-gateway error is logged and the
// loop continues (one bad gateway never stalls the rest).
func (c *Collector) Run(ctx context.Context, gateways func() []Gateway, interval time.Duration) error {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	for {
		for _, gw := range gateways() {
			var cycleErr error
			for {
				n, err := c.CollectOnce(ctx, gw)
				if err != nil {
					c.log.Warn("collect: cycle failed", "gateway", gw.Name, "err", err)
					cycleErr = err
					break
				}
				if n == 0 {
					break // gateway drained
				}
			}
			// Delivery-reconcile lane (separate from the claim/ack drain above): on this
			// same OUTBOUND cycle, push any admin decisions the gateway is still waiting on.
			if _, err := c.ReconcileOnce(ctx, gw); err != nil {
				c.log.Warn("collect: reconcile failed", "gateway", gw.Name, "err", err)
				if cycleErr == nil {
					cycleErr = err
				}
			}
			c.recordHealth(ctx, gw.Name, cycleErr)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}

// recordHealth persists this cycle's outcome for a gateway via the HealthSink (no-op if
// none). It maintains the absolute consecutive-failure count and writes on every ok/fail
// transition, else at most once per healthHeartbeat — so a wedged gateway is visible in
// the console within a heartbeat while a healthy one barely writes.
func (c *Collector) recordHealth(ctx context.Context, name string, cycleErr error) {
	if c.health == nil {
		return
	}
	ok := cycleErr == nil
	if ok {
		c.healthFails[name] = 0
	} else {
		c.healthFails[name]++
	}
	prev, seen := c.healthOK[name]
	now := c.now()
	if !seen || prev != ok || now.Sub(c.healthWrote[name]) >= healthHeartbeat {
		msg := ""
		if cycleErr != nil {
			msg = cycleErr.Error()
		}
		if err := c.health.Record(ctx, name, ok, msg, c.healthFails[name], now); err != nil {
			c.log.Warn("collect: record gateway health failed", "gateway", name, "err", err)
		}
		c.healthWrote[name] = now
	}
	c.healthOK[name] = ok
}

func (c *Collector) post(ctx context.Context, client *http.Client, gw Gateway, path string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gw.URL+path, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, collectMaxBody))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s -> %d: %s", path, resp.StatusCode, rb)
	}
	if out != nil {
		return json.Unmarshal(rb, out)
	}
	return nil
}

func (c *Collector) get(ctx context.Context, client *http.Client, gw Gateway, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gw.URL+path, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, collectMaxBody))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s -> %d: %s", path, resp.StatusCode, rb)
	}
	return json.Unmarshal(rb, out)
}

// ReconcileOnce delivers admin decisions the gateway is still waiting on — the
// delivery-reconcile lane, structurally separate from CollectOnce's claim/ack. On
// Harbor's OUTBOUND poll it pulls the gateway's still-pending enrollment ids, asks the
// Resolver whether each is now decided, and pushes the signed results back via
// /collect/v1/results with a fresh delivery TTL. The gateway then serves them to the
// host's own poll — it never calls Harbor. Idempotent: PutResult upserts, and a row
// that flips to issued/denied drops off the pending list, so each decision ships once.
func (c *Collector) ReconcileOnce(ctx context.Context, gw Gateway) (delivered int, err error) {
	if c.resolver == nil {
		return 0, nil
	}
	client := c.clientFor(gw)
	var pending PendingResponse
	if err := c.get(ctx, client, gw, "/collect/v1/pending", &pending); err != nil {
		return 0, fmt.Errorf("pending: %w", err)
	}
	var results []Result
	for _, id := range pending.EnrollmentIDs {
		status, bundleJWS, reason, ok, rerr := c.resolver.BuildDeliverable(ctx, id)
		if rerr != nil {
			c.log.Warn("collect: reconcile resolve failed", "gateway", gw.Name, "enrollment", id, "err", rerr)
			continue
		}
		if !ok {
			continue // still pending on Harbor's side too — nothing to deliver yet
		}
		results = append(results, Result{
			EnrollmentID: id, Status: status, Bundle: bundleJWS, Reason: reason,
			SecretHash: nil, // the gateway preserves the pending row's secret_hash on upsert
			ExpiresAt:  c.now().Add(c.deliveryTTL),
		})
	}
	if len(results) == 0 {
		return 0, nil
	}
	if err := c.post(ctx, client, gw, "/collect/v1/results", PutResultsRequest{Results: results}, nil); err != nil {
		return 0, fmt.Errorf("deliver results: %w", err)
	}
	c.log.Info("collect: delivered decided enrollments", "gateway", gw.Name, "count", len(results))
	return len(results), nil
}
