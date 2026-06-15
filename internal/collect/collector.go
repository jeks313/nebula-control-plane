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

// Collector is the Harbor-side pull loop (ADR 0005). It claims candidates from a
// gateway over leaf-pinned mTLS, runs the Processor (which captures results into
// sink), ships the results back, then acks. Collection is SEQUENTIAL per gateway —
// the shared CaptureSink maps cleanly to one in-flight batch.
type Collector struct {
	proc       Processor
	sink       *CaptureSink
	clientCert tls.Certificate
	batch      int
	leaseTTL   time.Duration
	httpClient func(gw Gateway) *http.Client
	log        *slog.Logger

	mu      sync.Mutex
	clients map[string]*http.Client // cached per gateway (name|pin) so connections pool across cycles
}

// Config parameterizes a Collector.
type Config struct {
	Processor  Processor
	Sink       *CaptureSink
	ClientCert tls.Certificate // Harbor's pinned client identity
	Batch      int             // candidates per claim (0 -> 64)
	LeaseTTL   time.Duration   // claim lease (0 -> 60s)
	Logger     *slog.Logger
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
	c := &Collector{
		proc: cfg.Processor, sink: cfg.Sink, clientCert: cfg.ClientCert,
		batch: cfg.Batch, leaseTTL: cfg.LeaseTTL, log: cfg.Logger,
		clients: map[string]*http.Client{},
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
func (c *Collector) CollectOnce(ctx context.Context, gw Gateway) (int, error) {
	client := c.clientFor(gw)

	var cr ClaimResponse
	if err := c.post(ctx, client, gw, "/collect/v1/claim", ClaimRequest{Limit: c.batch, LeaseMs: c.leaseTTL.Milliseconds()}, &cr); err != nil {
		return 0, fmt.Errorf("claim: %w", err)
	}
	if len(cr.Candidates) == 0 {
		return 0, nil
	}

	c.sink.Drain() // discard anything stale before this batch
	var ackIDs, nackIDs []int64
	for _, cand := range cr.Candidates {
		_, perr := c.proc.Process(ctx, queue.Candidate{
			EnrollmentID: cand.EnrollmentID, PubkeyHash: cand.PubkeyHash,
			RequestJWS: cand.RequestJWS, RetrievalSecretHash: cand.RetrievalSecretHash, ReceivedAt: cand.ReceivedAt,
		})
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
			return len(cr.Candidates), fmt.Errorf("ship results: %w", err)
		}
	}
	if err := c.post(ctx, client, gw, "/collect/v1/ack", AckRequest{Ack: ackIDs, Nack: nackIDs}, nil); err != nil {
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
			for {
				n, err := c.CollectOnce(ctx, gw)
				if err != nil {
					c.log.Warn("collect: cycle failed", "gateway", gw.Name, "err", err)
					break
				}
				if n == 0 {
					break // gateway drained
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
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
