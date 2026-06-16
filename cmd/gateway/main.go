// Command gateway is the public, credential-less Enrollment Gateway. It holds
// only the nonce HMAC key (k_gw) — no DB, no KMS (design §P3). M3.2 serves
// GET /v1/nonce; later steps add POST /v1/enroll + queue publish.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/autotls"
	"github.com/jeks313/nebula-control-plane/internal/clilog"
	"github.com/jeks313/nebula-control-plane/internal/collect"
	"github.com/jeks313/nebula-control-plane/internal/gateway"
	"github.com/jeks313/nebula-control-plane/internal/httpserve"
	"github.com/jeks313/nebula-control-plane/internal/nonce"
	"github.com/jeks313/nebula-control-plane/internal/obs"
	"github.com/jeks313/nebula-control-plane/internal/queue"
	"github.com/jeks313/nebula-control-plane/internal/ratelimit"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

// Secret-material env vars (ADR 0006): a shell-less distroless container reads its keys
// and certs straight from these Secrets-Manager-injected vars, so no entrypoint shell is
// needed to materialize files. Each takes precedence over its matching -flag <file>, which
// remains for systemd / dev. PEM vars hold the literal PEM; key vars hold base64url.
const (
	envHMACKey      = "NCP_GW_HMAC_KEY_B64"
	envHMACKeyPrev  = "NCP_GW_HMAC_KEY_PREV_B64"
	envQueueKey     = "NCP_GW_QUEUE_KEY_B64"
	envCollectCert  = "NCP_GW_COLLECT_CERT_PEM"
	envCollectKey   = "NCP_GW_COLLECT_KEY_PEM"
	envHarborClient = "NCP_GW_HARBOR_CLIENT_PEM"
)

func main() {
	if len(os.Args) >= 2 && (os.Args[1] == "version" || os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Printf("gateway %s\n", version)
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "collect-keygen" {
		collectKeygen(os.Args[2:])
		return
	}

	fs := flag.NewFlagSet("gateway", flag.ExitOnError)
	addr := fs.String("addr", ":8443", "listen address")
	keyPath := fs.String("hmac-key", "", "path to the primary nonce HMAC key (base64url, >=16 bytes); or set $"+envHMACKey)
	prevPath := fs.String("hmac-key-prev", "", "optional previous nonce key for rotation overlap; or set $"+envHMACKeyPrev)
	rps := fs.Float64("rate", 5, "edge rate limit (requests/sec per IP and per key)")
	burst := fs.Int("burst", 20, "edge rate-limit burst")
	queueDSN := fs.String("queue-dsn", "", "durable queue SQLite DSN (default: in-memory dev queue)")
	queueKeyPath := fs.String("queue-key", "", "gateway<->Core queue HMAC key (base64url, >=16 bytes); or set $"+envQueueKey)
	tlsCert := fs.String("tls-cert", "", "TLS certificate PEM (serve HTTPS — required on this public endpoint unless -acme-domain or -insecure)")
	tlsKey := fs.String("tls-key", "", "TLS private key PEM (with -tls-cert)")
	insecure := fs.Bool("insecure", false, "serve plain HTTP on this PUBLIC endpoint (only when TLS is terminated by a trusted proxy)")
	// Auto-TLS via Let's Encrypt (ACME DNS-01 over Cloudflare): the gateway obtains + renews
	// its own public cert, so TLS terminates here (end-to-end, even behind an L4 proxy/NLB).
	acme := autotls.RegisterFlags(fs, "/var/lib/gateway/acme")
	logFormat := fs.String("log-format", "auto", "log format: auto (text on a TTY, JSON as a service) | text | json")
	logLevel := fs.String("log-level", "info", "log level: debug | info | warn | error")
	// ADR 0005 pull transport: when -collect-addr is set, expose a Harbor-facing
	// mTLS API so Harbor PULLS from this gateway's local queue (the gateway is then
	// off-mesh and initiates nothing). Empty = co-located mode (Core drains directly).
	collectAddr := fs.String("collect-addr", "", "Harbor-facing collect API address (mTLS; e.g. :9443). Empty = co-located mode")
	collectCert := fs.String("collect-cert", "", "gateway's collect server cert PEM (self-signed; its leaf is pinned in Harbor's gateway registry); or set $"+envCollectCert)
	collectKey := fs.String("collect-key", "", "gateway's collect server key PEM; or set $"+envCollectKey)
	harborClientCert := fs.String("harbor-client-cert", "", "Harbor's pinned client cert PEM — the only client allowed to drain this gateway; or set $"+envHarborClient)
	obsAddr := fs.String("obs-addr", "", "internal listener for /metrics + /healthz + /readyz (e.g. :9091); served plaintext, NEVER the public enroll port. Empty disables.")
	_ = fs.Parse(os.Args[1:])
	log := clilog.Setup(clilog.Options{Format: *logFormat, Level: *logLevel})
	// The enroll endpoint is public, so demand an explicit transport posture (P8: fail
	// closed on a config error). A partial cert/key pair is always a misconfiguration;
	// plaintext is allowed only behind an operator's -insecure opt-out (upstream TLS).
	switch {
	case (*tlsCert == "") != (*tlsKey == ""):
		fatalf("-tls-cert and -tls-key must be set together")
	case acme.Enabled():
		// Auto-TLS terminates here; cert obtained below once the ctx exists.
	case *tlsCert != "":
		// Static cert/key pair.
	case *insecure:
		log.Warn("gateway: serving plain HTTP by operator opt-out (-insecure) — ensure TLS is terminated by a trusted proxy")
	default:
		fatalf("refusing to serve the public enroll endpoint over plaintext; provide -acme-domain (Let's Encrypt), -tls-cert/-tls-key, or -insecure if TLS is terminated by a trusted proxy")
	}

	// Resolve secret material env-first (a shell-less distroless container gets it as
	// Secrets-Manager-injected env vars; systemd / dev still use the -flag <file> paths).
	hmacB64, err := materialString(envHMACKey, *keyPath)
	if err != nil {
		fatalf("%v", err)
	}
	prevB64, err := materialString(envHMACKeyPrev, *prevPath)
	if err != nil {
		fatalf("%v", err)
	}
	keys, err := loadKeys(hmacB64, prevB64)
	if err != nil {
		fatalf("%v", err)
	}
	ring, err := nonce.NewKeyring(keys, 0, 0)
	if err != nil {
		fatalf("%v", err)
	}

	queueKeyB64, err := materialString(envQueueKey, *queueKeyPath)
	if err != nil {
		fatalf("%v", err)
	}
	q, err := openQueue(*queueDSN, queueKeyB64)
	if err != nil {
		fatalf("%v", err)
	}
	defer closeQueue(q) // flush + close the durable (SQLite) queue on exit; no-op for the in-memory queue

	gwCfg := gateway.Config{
		Nonces:  ring,
		Queue:   q,
		Limiter: ratelimit.New(*rps, *burst),
	}
	// The durable queue also serves poll results (read-own-result); the in-memory
	// dev queue has none, so poll is unavailable there.
	if rr, ok := q.(gateway.ResultReader); ok {
		gwCfg.Results = rr
	}
	gw := gateway.New(gwCfg)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           gw.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Auto-TLS: obtain (blocking) + auto-renew a Let's Encrypt cert via DNS-01, and serve
	// HTTPS with it. Done after the ctx exists so a shutdown signal cancels issuance.
	if err := acme.Apply(ctx, srv); err != nil {
		fatalf("gateway: auto-TLS: %v", err)
	}
	if acme.Enabled() {
		log.Info("gateway: auto-TLS via Let's Encrypt (ACME DNS-01)", "domain", *acme.Domain, "staging", *acme.Staging)
	}

	go func() {
		<-ctx.Done()
		log.Info("gateway shutting down", "reason", "signal")
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	var wg sync.WaitGroup // background servers, joined on shutdown so we never exit mid-drain
	if *collectAddr != "" {
		collectCertPEM, err := materialString(envCollectCert, *collectCert)
		if err != nil {
			fatalf("%v", err)
		}
		collectKeyPEM, err := materialString(envCollectKey, *collectKey)
		if err != nil {
			fatalf("%v", err)
		}
		harborPEM, err := materialString(envHarborClient, *harborClientCert)
		if err != nil {
			fatalf("%v", err)
		}
		startCollect(ctx, &wg, log, q, *collectAddr, []byte(collectCertPEM), []byte(collectKeyPEM), []byte(harborPEM))
	}
	// Observability on a SEPARATE internal listener — never the public enroll port (which
	// would leak runtime/throughput metrics to the internet).
	if *obsAddr != "" {
		startObs(ctx, &wg, log, *obsAddr)
	}

	log.Info("gateway listening", "addr", *addr, "scheme", httpserve.SchemeFor(srv, *tlsCert, *tlsKey), "version", version, "access", "public/credential-less")
	if err := httpserve.Serve(srv, *tlsCert, *tlsKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatalf("%v", err)
	}
	wg.Wait() // let the collect server finish its in-flight drain before we exit
	log.Info("gateway stopped")
}

// startObs serves the observability endpoints (/metrics + /healthz + /readyz) on a SEPARATE
// internal listener — never the public enroll port, so runtime/throughput metrics aren't
// exposed to the internet. Plaintext; the scraper reaches it inside the VPC.
func startObs(ctx context.Context, wg *sync.WaitGroup, log *slog.Logger, addr string) {
	mux := http.NewServeMux()
	obs.Mount(mux) // no readiness checks: the gateway's only dependency (its local queue) is fatal at boot
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
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info("gateway observability listening", "addr", addr, "endpoints", "/metrics /healthz /readyz", "access", "internal")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("gateway obs server failed", "err", err)
		}
	}()
}

// startCollect launches the Harbor-facing mTLS collect API (ADR 0005): Harbor
// pulls candidates from this gateway's LOCAL durable queue and pushes results
// back. It requires the durable queue (claim/ack/put-result) and a leaf-pinned
// mTLS pair (the gateway's own server cert + Harbor's pinned client cert).
func startCollect(ctx context.Context, wg *sync.WaitGroup, log *slog.Logger, q queue.Queue, addr string, gwCertPEM, gwKeyPEM, harborPEM []byte) {
	dq, ok := q.(*queue.Durable)
	if !ok {
		fatalf("-collect-addr requires the durable queue (-queue-dsn); the in-memory dev queue cannot be collected")
	}
	if len(gwCertPEM) == 0 || len(gwKeyPEM) == 0 || len(harborPEM) == 0 {
		fatalf("-collect-addr requires the collect cert, key and Harbor client cert (-collect-cert/-collect-key/-harbor-client-cert or $%s/$%s/$%s)", envCollectCert, envCollectKey, envHarborClient)
	}
	gwCert, err := tls.X509KeyPair(gwCertPEM, gwKeyPEM)
	if err != nil {
		fatalf("collect server cert: %v", err)
	}
	harborPin, err := collect.PinFromCertPEM(harborPEM)
	if err != nil {
		fatalf("-harbor-client-cert: %v", err)
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           collect.NewServer(dq, log).Handler(),
		TLSConfig:         collect.ServerTLS(gwCert, harborPin),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sc)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info("gateway collect API listening", "addr", addr, "access", "Harbor-only (mTLS, leaf-pinned)")
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("gateway collect API failed", "err", err)
		}
	}()
}

// closeQueue closes the durable (SQLite) queue on shutdown; the in-memory dev
// queue has nothing to close (the io.Closer assertion simply fails).
func closeQueue(q queue.Queue) {
	if c, ok := q.(io.Closer); ok {
		_ = c.Close()
	}
}

// loadKeys decodes the primary (and optional previous) nonce key from already-resolved
// base64url material (env var or file contents). For dev convenience, an empty primary
// yields an ephemeral key (warned) — restarting then invalidates outstanding nonces.
func loadKeys(primaryB64, prevB64 string) ([][]byte, error) {
	if primaryB64 == "" {
		eph := make([]byte, 32)
		if _, err := rand.Read(eph); err != nil {
			return nil, err
		}
		slog.Warn("gateway: no nonce key; using an ephemeral key (dev only) — restart invalidates outstanding nonces")
		return [][]byte{eph}, nil
	}
	k, err := decodeKey(primaryB64)
	if err != nil {
		return nil, err
	}
	keys := [][]byte{k}
	if prevB64 != "" {
		p, err := decodeKey(prevB64)
		if err != nil {
			return nil, err
		}
		keys = append(keys, p)
	}
	return keys, nil
}

// openQueue returns the durable queue when -queue-dsn is set, else the in-memory
// dev queue. The durable queue is the gateway's only persistent dependency — and
// it is queue-only (no CA/devices/audit), preserving least privilege (P3).
// queueKeyB64 is the already-resolved base64url queue key (env or file).
func openQueue(dsn, queueKeyB64 string) (queue.Queue, error) {
	if dsn == "" {
		slog.Warn("gateway: no -queue-dsn; using an in-memory queue (dev only) — enrollments are not durable")
		return queue.NewMemory(), nil
	}
	if queueKeyB64 == "" {
		return nil, fmt.Errorf("-queue-dsn requires a queue key (-queue-key or $%s)", envQueueKey)
	}
	key, err := decodeKey(queueKeyB64)
	if err != nil {
		return nil, err
	}
	return queue.OpenDurable(queue.DurableConfig{DSN: dsn, Key: key})
}

// materialString resolves secret material env-first: the env var if set (a shell-less
// distroless container gets Secrets-Manager values injected directly), else the contents
// of path. Returns "" when neither is set.
func materialString(env, path string) (string, error) {
	if v := os.Getenv(env); v != "" {
		return v, nil
	}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", path, err)
		}
		return string(b), nil
	}
	return "", nil
}

// decodeKey decodes a base64url (raw, unpadded) key, tolerating surrounding whitespace.
func decodeKey(b64 string) ([]byte, error) {
	k, err := base64.RawURLEncoding.DecodeString(trimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("key is not base64url: %w", err)
	}
	return k, nil
}

func trimSpace(s string) string {
	for s != "" && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// collectKeygen mints a self-signed leaf for the ADR-0005 collect mTLS (usable as
// either the gateway's server identity or Harbor's client identity — both EKUs
// are set) and prints its SHA-256 leaf pin, which the peer pins (gateway registry
// / -harbor-client-cert). No CA: trust is by pinning the leaf.
func collectKeygen(args []string) {
	fs := flag.NewFlagSet("collect-keygen", flag.ExitOnError)
	cn := fs.String("cn", "", "common name (e.g. gateway-1 or harbor-collector)")
	certOut := fs.String("cert-out", "", "write the cert PEM here")
	keyOut := fs.String("key-out", "", "write the key PEM here (0600)")
	days := fs.Int("days", 825, "validity in days")
	_ = fs.Parse(args)
	if *cn == "" || *certOut == "" || *keyOut == "" {
		fatalf("collect-keygen: -cn, -cert-out and -key-out are required")
	}
	certPEM, keyPEM, err := collect.GenerateSelfSigned(*cn, time.Duration(*days)*24*time.Hour)
	if err != nil {
		fatalf("collect-keygen: %v", err)
	}
	if err := os.WriteFile(*keyOut, keyPEM, 0o600); err != nil {
		fatalf("collect-keygen: write key: %v", err)
	}
	if err := os.WriteFile(*certOut, certPEM, 0o644); err != nil { //nolint:gosec // a public cert is world-readable by design
		fatalf("collect-keygen: write cert: %v", err)
	}
	pin, _ := collect.PinFromCertPEM(certPEM)
	fmt.Printf("wrote %s (cert) + %s (key)\nleaf pin (sha256): %x\n", *certOut, *keyOut, pin)
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "gateway: "+format+"\n", a...)
	os.Exit(1)
}
