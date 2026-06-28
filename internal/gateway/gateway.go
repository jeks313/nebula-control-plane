// Package gateway is the public, credential-less Enrollment Gateway
// (design §P3, protocol spec §5). It deliberately depends on no DB/KMS: it mints
// nonces (3.2), structurally validates enroll requests, edge-rate-limits, and
// publishes vetted candidates to a queue, returning a retrieval ticket (3.3).
// All authoritative decisions (token/attestation, group resolution, issuance)
// live in Core, which re-verifies everything.
package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/nonce"
	"github.com/jeks313/nebula-control-plane/internal/queue"
	"github.com/jeks313/nebula-control-plane/internal/ratelimit"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

// ResultReader is the gateway's read-own-result capability (poll, 3.6a).
// *queue.Durable satisfies it.
type ResultReader interface {
	GetResult(ctx context.Context, enrollmentID, secret string) (queue.PollResult, error)
}

const (
	maxBindingLen      = 128
	defaultMaxBody     = 16 << 10 // 16 KiB
	defaultTicketTTL   = 5 * time.Minute
	defaultPollAfterMs = 500
)

// Config builds a gateway Server.
type Config struct {
	Nonces       *nonce.Keyring
	Queue        queue.Queue
	Results      ResultReader       // nil = poll unavailable
	Limiter      *ratelimit.Limiter // nil = no edge limit
	MaxBodyBytes int64              // <=0 -> default
	TicketTTL    time.Duration      // <=0 -> default
	// SSO is the OPTIONAL SSO enrollment portal (ADR 0004). When nil or not fully
	// configured (no SAML SP / no signing key), the portal routes return 404 "SSO not
	// enabled" and the rest of the gateway is unaffected — the gateway never holds a CA.
	SSO *SSOConfig
	Now func() time.Time
}

// Server is the gateway HTTP surface.
type Server struct {
	nonces       *nonce.Keyring
	queue        queue.Queue
	results      ResultReader
	limiter      *ratelimit.Limiter
	maxBody      int64
	ticketTTL    time.Duration
	now          func() time.Time
	sso          *SSOConfig
	ssoSessions  *ssoSessions
	assertionTTL time.Duration
}

// New builds a gateway from cfg.
func New(cfg Config) *Server {
	s := &Server{
		nonces:    cfg.Nonces,
		queue:     cfg.Queue,
		results:   cfg.Results,
		limiter:   cfg.Limiter,
		maxBody:   cfg.MaxBodyBytes,
		ticketTTL: cfg.TicketTTL,
		now:       cfg.Now,
		sso:       cfg.SSO,
	}
	if s.maxBody <= 0 {
		s.maxBody = defaultMaxBody
	}
	if s.ticketTTL <= 0 {
		s.ticketTTL = defaultTicketTTL
	}
	if s.now == nil {
		s.now = time.Now
	}
	// Stand up the SSO portal's session store + TTLs only when it is fully configured.
	if s.sso.enabled() {
		s.assertionTTL = s.sso.AssertionTTL
		if s.assertionTTL <= 0 {
			s.assertionTTL = defaultAssertionTTL
		}
		s.ssoSessions = newSSOSessions(s.sso.SessionTTL, s.now)
	}
	return s
}

// Handler returns the gateway's HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// /healthz on the PUBLIC enroll listener (:8443) — unauthenticated, no rate limit, no deps.
	// The NLB target group HTTPS-probes this so a wedged TLS listener (the 2026-06-28 outage:
	// handshake returned 0 bytes) fails the check and ECS replaces the task. A trivial 200 is
	// enough: the check only passes if the TLS handshake completes AND the server responds, which
	// is exactly what was broken. (Distinct from the internal :9091 obs /healthz, which only
	// proves the process is alive and so stayed green through the wedge.)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /v1/nonce", s.handleNonce)
	mux.HandleFunc("POST /v1/enroll", s.handleEnroll)
	mux.HandleFunc("GET /v1/enroll/{id}", s.handlePoll)
	// SSO enrollment portal (ADR 0004). The routes are always mounted; when SSO is not
	// configured they answer 404 "SSO not enabled" (so the surface is uniform and a
	// probe can't distinguish "off" from "missing route"). The gateway holds no CA.
	mux.HandleFunc("GET /v1/sso/start", s.handleSSOStart)
	mux.HandleFunc("POST /v1/sso/acs", s.handleSSOACS)
	return mux
}

// handleHealth implements GET /healthz on the public enroll listener — a cheap liveness probe
// for the NLB target group (reaching it proves the :8443 TLS listener is actually serving).
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// handleNonce implements GET /v1/nonce?binding=<pubkey_hash> (spec §4.3).
func (s *Server) handleNonce(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	binding := r.URL.Query().Get("binding")
	if binding == "" || len(binding) > maxBindingLen {
		wire.WriteError(w, wire.CodeInvalidRequest, "missing or oversized 'binding' query parameter")
		return
	}
	n, expires := s.nonces.Mint([]byte(binding))
	wire.WriteJSON(w, http.StatusOK, wire.NonceResponse{
		ProtocolVersion: wire.ProtocolVersion,
		Nonce:           n,
		ExpiresAt:       expires.UTC().Format(time.RFC3339),
	})
}

// handleEnroll implements POST /v1/enroll (spec §5.1): structural validation,
// request-JWS proof of possession, nonce check, edge rate-limit, queue publish,
// and a retrieval ticket. No authz decision is made here.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	// Cheap shed first: rate-limit by source IP before any parsing/crypto.
	ip := clientIP(r)
	if !s.allow("ip:" + ip) {
		wire.WriteError(w, wire.CodeRateLimited, "rate limited")
		return
	}

	// 1. Hard body cap, pre-parse.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.maxBody))
	if err != nil {
		wire.WriteError(w, wire.CodeInvalidRequest, "request too large or unreadable")
		return
	}

	// 2. Parse the JWS envelope and its payload (self-describing: the key to
	// verify against is inside the payload).
	var env jws.Flattened
	if err := json.Unmarshal(body, &env); err != nil || env.Protected == "" || env.Payload == "" {
		wire.WriteError(w, wire.CodeInvalidRequest, "not a JWS envelope")
		return
	}
	plBytes, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		wire.WriteError(w, wire.CodeInvalidRequest, "bad payload encoding")
		return
	}
	var req wire.EnrollRequest
	if err := json.Unmarshal(plBytes, &req); err != nil {
		wire.WriteError(w, wire.CodeInvalidRequest, "bad enroll request")
		return
	}

	// 3. Schema/version checks.
	if req.ProtocolVersion != wire.ProtocolVersion {
		wire.WriteError(w, wire.CodeUnsupportedVersion, "unsupported protocol_version")
		return
	}
	if req.Type != "enroll" || req.Nonce == "" || req.CSR.Curve != "P256" || !knownMethod(req.Method) {
		wire.WriteError(w, wire.CodeInvalidRequest, "missing or invalid fields")
		return
	}
	pubBytes, err := base64.RawURLEncoding.DecodeString(req.CSR.PublicKey)
	if err != nil || len(pubBytes) != 65 {
		wire.WriteError(w, wire.CodeInvalidRequest, "invalid csr.public_key")
		return
	}
	pub, err := jws.ParseP256PublicPoint(pubBytes)
	if err != nil {
		wire.WriteError(w, wire.CodeInvalidRequest, "invalid csr.public_key point")
		return
	}
	pubkeyHash := wire.PubkeyHash(pubBytes)

	// Rate-limit by identity now that we know it.
	if !s.allow("pk:" + pubkeyHash) {
		wire.WriteError(w, wire.CodeRateLimited, "rate limited")
		return
	}

	// 4. Verify the request JWS (proof of possession of the cert key).
	hdr, _, err := jws.Verify(env, pub)
	if err != nil || hdr.Typ != wire.TypEnrollRequest || hdr.Kid != pubkeyHash {
		wire.WriteError(w, wire.CodeInvalidSignature, "request signature verification failed")
		return
	}

	// 5. Verify the nonce (freshness + binding to this key).
	switch err := s.nonces.Verify(req.Nonce, []byte(pubkeyHash)); {
	case err == nil:
	case errors.Is(err, nonce.ErrExpired):
		wire.WriteError(w, wire.CodeNonceExpired, "nonce expired; fetch a fresh one")
		return
	default:
		wire.WriteError(w, wire.CodeInvalidNonce, "invalid nonce")
		return
	}

	// 6. Mint the ticket and publish the vetted candidate.
	enrollmentID := randToken(16)
	retrievalSecret := randToken(32)
	secretHash := sha256.Sum256([]byte(retrievalSecret))

	cand := queue.Candidate{
		EnrollmentID:        enrollmentID,
		PubkeyHash:          pubkeyHash,
		RequestJWS:          body,
		RetrievalSecretHash: secretHash[:],
		ReceivedAt:          s.now().UTC(),
	}
	if err := s.queue.Publish(r.Context(), cand); err != nil {
		wire.WriteError(w, wire.CodeInternal, "enrollment queue unavailable")
		return
	}

	wire.WriteJSON(w, http.StatusAccepted, wire.EnrollAccepted{
		ProtocolVersion: wire.ProtocolVersion,
		EnrollmentID:    enrollmentID,
		RetrievalSecret: retrievalSecret,
		PollAfterMs:     defaultPollAfterMs,
		ExpiresAt:       s.now().Add(s.ticketTTL).UTC().Format(time.RFC3339),
	})
}

// handlePoll implements GET /v1/enroll/{id} (spec §5.3): release the result only
// to the holder of the retrieval secret; one-time read of an issued bundle.
func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.results == nil {
		wire.WriteError(w, wire.CodeNotFound, "no result store")
		return
	}
	secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if secret == "" || secret == r.Header.Get("Authorization") {
		wire.WriteError(w, wire.CodeInvalidRequest, "missing Bearer retrieval secret")
		return
	}

	res, err := s.results.GetResult(r.Context(), r.PathValue("id"), secret)
	switch {
	case errors.Is(err, queue.ErrResultNotFound):
		wire.WriteError(w, wire.CodeNotFound, "not found")
		return
	case errors.Is(err, queue.ErrResultGone):
		wire.WriteError(w, wire.CodeGone, "expired or already consumed")
		return
	case err != nil:
		wire.WriteError(w, wire.CodeInternal, "result lookup failed")
		return
	}

	switch res.Status {
	case "issued":
		wire.WriteJSON(w, http.StatusOK, wire.PollResponse{Status: "issued", Bundle: json.RawMessage(res.Bundle)})
	case "denied":
		wire.WriteJSON(w, http.StatusOK, wire.PollResponse{Status: "denied", Reason: res.Reason})
	default: // pending
		wire.WriteJSON(w, http.StatusAccepted, wire.PollResponse{Status: "pending", PollAfterMs: defaultPollAfterMs})
	}
}

func (s *Server) allow(key string) bool {
	if s.limiter == nil {
		return true
	}
	return s.limiter.Allow(key)
}

func knownMethod(m string) bool {
	switch m {
	case wire.MethodToken, wire.MethodAWSSigV4, wire.MethodAzureIMDS, wire.MethodOIDC:
		return true
	default:
		return false
	}
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
