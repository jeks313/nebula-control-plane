// Command gateway is the public, credential-less Enrollment Gateway. It holds
// only the nonce HMAC key (k_gw) — no DB, no KMS (design §P3). M3.2 serves
// GET /v1/nonce; later steps add POST /v1/enroll + queue publish.
package main

import (
	"context"
	"crypto/rand"
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
	"github.com/jeks313/nebula-control-plane/internal/gateway"
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

	fs := flag.NewFlagSet("gateway", flag.ExitOnError)
	addr := fs.String("addr", ":8443", "listen address")
	keyPath := fs.String("hmac-key", "", "path to the primary nonce HMAC key (base64url, >=16 bytes)")
	prevPath := fs.String("hmac-key-prev", "", "optional previous nonce key for rotation overlap")
	rps := fs.Float64("rate", 5, "edge rate limit (requests/sec per IP and per key)")
	burst := fs.Int("burst", 20, "edge rate-limit burst")
	queueDSN := fs.String("queue-dsn", "", "durable queue SQLite DSN (default: in-memory dev queue)")
	queueKeyPath := fs.String("queue-key", "", "gateway<->Core queue HMAC key (base64url, >=16 bytes)")
	logFormat := fs.String("log-format", "auto", "log format: auto (text on a TTY, JSON as a service) | text | json")
	logLevel := fs.String("log-level", "info", "log level: debug | info | warn | error")
	_ = fs.Parse(os.Args[1:])
	log := clilog.Setup(clilog.Options{Format: *logFormat, Level: *logLevel})

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

	log.Info("gateway listening", "addr", *addr, "version", version, "access", "public/credential-less")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatalf("%v", err)
	}
	log.Info("gateway stopped")
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

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "gateway: "+format+"\n", a...)
	os.Exit(1)
}
