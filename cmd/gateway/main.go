// Command gateway is the public, credential-less Enrollment Gateway. It holds
// only the nonce HMAC key (k_gw) — no DB, no KMS (design §P3). M3.2 serves
// GET /v1/nonce; later steps add POST /v1/enroll + queue publish.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/clilog"
	"github.com/jeks313/nebula-control-plane/internal/collect"
	"github.com/jeks313/nebula-control-plane/internal/gateway"
	"github.com/jeks313/nebula-control-plane/internal/httpserve"
	"github.com/jeks313/nebula-control-plane/internal/nonce"
	"github.com/jeks313/nebula-control-plane/internal/queue"
	"github.com/jeks313/nebula-control-plane/internal/ratelimit"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

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
	keyPath := fs.String("hmac-key", "", "path to the primary nonce HMAC key (base64url, >=16 bytes)")
	prevPath := fs.String("hmac-key-prev", "", "optional previous nonce key for rotation overlap")
	rps := fs.Float64("rate", 5, "edge rate limit (requests/sec per IP and per key)")
	burst := fs.Int("burst", 20, "edge rate-limit burst")
	queueDSN := fs.String("queue-dsn", "", "durable queue SQLite DSN (default: in-memory dev queue)")
	queueKeyPath := fs.String("queue-key", "", "gateway<->Core queue HMAC key (base64url, >=16 bytes)")
	tlsCert := fs.String("tls-cert", "", "TLS certificate PEM (serve HTTPS — required on this public endpoint unless -insecure)")
	tlsKey := fs.String("tls-key", "", "TLS private key PEM (with -tls-cert)")
	insecure := fs.Bool("insecure", false, "serve plain HTTP on this PUBLIC endpoint (only when TLS is terminated by a trusted proxy)")
	logFormat := fs.String("log-format", "auto", "log format: auto (text on a TTY, JSON as a service) | text | json")
	logLevel := fs.String("log-level", "info", "log level: debug | info | warn | error")
	// ADR 0005 pull transport: when -collect-addr is set, expose a Harbor-facing
	// mTLS API so Harbor PULLS from this gateway's local queue (the gateway is then
	// off-mesh and initiates nothing). Empty = co-located mode (Core drains directly).
	collectAddr := fs.String("collect-addr", "", "Harbor-facing collect API address (mTLS; e.g. :9443). Empty = co-located mode")
	collectCert := fs.String("collect-cert", "", "gateway's collect server cert PEM (self-signed; its leaf is pinned in Harbor's gateway registry)")
	collectKey := fs.String("collect-key", "", "gateway's collect server key PEM")
	harborClientCert := fs.String("harbor-client-cert", "", "Harbor's pinned client cert PEM — the only client allowed to drain this gateway")
	_ = fs.Parse(os.Args[1:])
	log := clilog.Setup(clilog.Options{Format: *logFormat, Level: *logLevel})
	// The enroll endpoint is public, so demand an explicit transport posture (P8: fail
	// closed on a config error). A partial cert/key pair is always a misconfiguration;
	// plaintext is allowed only behind an operator's -insecure opt-out (upstream TLS).
	switch {
	case (*tlsCert == "") != (*tlsKey == ""):
		fatalf("-tls-cert and -tls-key must be set together")
	case *tlsCert == "" && !*insecure:
		fatalf("refusing to serve the public enroll endpoint over plaintext; provide -tls-cert/-tls-key, or pass -insecure if TLS is terminated by a trusted proxy")
	case *tlsCert == "" && *insecure:
		log.Warn("gateway: serving plain HTTP by operator opt-out (-insecure) — ensure TLS is terminated by a trusted proxy")
	}

	keys, err := loadKeys(*keyPath, *prevPath)
	if err != nil {
		fatalf("%v", err)
	}
	ring, err := nonce.NewKeyring(keys, 0, 0)
	if err != nil {
		fatalf("%v", err)
	}

	q, err := openQueue(*queueDSN, *queueKeyPath)
	if err != nil {
		fatalf("%v", err)
	}

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
	go func() {
		<-ctx.Done()
		log.Info("gateway shutting down", "reason", "signal")
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	if *collectAddr != "" {
		startCollect(ctx, log, q, *collectAddr, *collectCert, *collectKey, *harborClientCert)
	}

	log.Info("gateway listening", "addr", *addr, "scheme", httpserve.Scheme(*tlsCert, *tlsKey), "version", version, "access", "public/credential-less")
	if err := httpserve.Serve(srv, *tlsCert, *tlsKey); err != nil && err != http.ErrServerClosed {
		fatalf("%v", err)
	}
	log.Info("gateway stopped")
}

// startCollect launches the Harbor-facing mTLS collect API (ADR 0005): Harbor
// pulls candidates from this gateway's LOCAL durable queue and pushes results
// back. It requires the durable queue (claim/ack/put-result) and a leaf-pinned
// mTLS pair (the gateway's own server cert + Harbor's pinned client cert).
func startCollect(ctx context.Context, log *slog.Logger, q queue.Queue, addr, certPath, keyPath, harborCertPath string) {
	dq, ok := q.(*queue.Durable)
	if !ok {
		fatalf("-collect-addr requires the durable queue (-queue-dsn); the in-memory dev queue cannot be collected")
	}
	if certPath == "" || keyPath == "" || harborCertPath == "" {
		fatalf("-collect-addr requires -collect-cert, -collect-key and -harbor-client-cert")
	}
	gwCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		fatalf("collect server cert: %v", err)
	}
	harborPEM, err := os.ReadFile(harborCertPath)
	if err != nil {
		fatalf("read -harbor-client-cert: %v", err)
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
	go func() {
		log.Info("gateway collect API listening", "addr", addr, "access", "Harbor-only (mTLS, leaf-pinned)")
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Error("gateway collect API failed", "err", err)
		}
	}()
}

// loadKeys reads the primary (and optional previous) nonce key. For dev
// convenience, if no -hmac-key is given an ephemeral key is generated (warned);
// note that restarting then invalidates outstanding nonces. Production wires the
// key from secrets management (2.10).
func loadKeys(keyPath, prevPath string) ([][]byte, error) {
	var keys [][]byte
	if keyPath == "" {
		eph := make([]byte, 32)
		if _, err := rand.Read(eph); err != nil {
			return nil, err
		}
		slog.Warn("gateway: no -hmac-key; using an ephemeral key (dev only) — restart invalidates outstanding nonces")
		return [][]byte{eph}, nil
	}
	k, err := readKey(keyPath)
	if err != nil {
		return nil, err
	}
	keys = append(keys, k)
	if prevPath != "" {
		p, err := readKey(prevPath)
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
func openQueue(dsn, keyPath string) (queue.Queue, error) {
	if dsn == "" {
		slog.Warn("gateway: no -queue-dsn; using an in-memory queue (dev only) — enrollments are not durable")
		return queue.NewMemory(), nil
	}
	if keyPath == "" {
		return nil, fmt.Errorf("-queue-dsn requires -queue-key")
	}
	key, err := readKey(keyPath)
	if err != nil {
		return nil, err
	}
	return queue.OpenDurable(queue.DurableConfig{DSN: dsn, Key: key})
}

func readKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", path, err)
	}
	k, err := base64.RawURLEncoding.DecodeString(trimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("key %s is not base64url: %w", path, err)
	}
	return k, nil
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
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
