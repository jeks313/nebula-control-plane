package collect

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/queue"
)

// Wire DTOs for the collect protocol (Harbor <- gateway over mTLS). []byte fields
// JSON-encode as base64. The gateway's local durable queue is the source of truth;
// these just carry its rows to Harbor and the issued results back.

// Candidate is a leased pending candidate handed to Harbor (lease id + the vetted
// request the gateway queued). Mirrors queue.Leased + queue.Candidate.
type Candidate struct {
	LeaseID             int64     `json:"lease_id"`
	EnrollmentID        string    `json:"enrollment_id"`
	PubkeyHash          string    `json:"pubkey_hash"`
	RequestJWS          []byte    `json:"request_jws"`
	RetrievalSecretHash []byte    `json:"retrieval_secret_hash"`
	ReceivedAt          time.Time `json:"received_at"`
}

// ClaimRequest asks for up to Limit candidates, leased for LeaseMs.
type ClaimRequest struct {
	Limit   int   `json:"limit"`
	LeaseMs int64 `json:"lease_ms"`
}

// ClaimResponse returns the leased candidates.
type ClaimResponse struct {
	Candidates []Candidate `json:"candidates"`
}

// Result is an issued/denied poll result Harbor pushes back for the host to poll.
type Result struct {
	EnrollmentID string    `json:"enrollment_id"`
	Status       string    `json:"status"`
	SecretHash   []byte    `json:"secret_hash"`
	Bundle       []byte    `json:"bundle"`
	Reason       string    `json:"reason"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// PutResultsRequest delivers results back to the gateway.
type PutResultsRequest struct {
	Results []Result `json:"results"`
}

// PendingResponse lists the enrollment ids the gateway still holds a PENDING result
// for. Harbor pulls this on its outbound poll (the delivery-reconcile lane), resolves
// each against its own decisions, and pushes the now-signed results back via
// /collect/v1/results — so an admin approval reaches the host without the gateway
// ever calling in to Harbor.
type PendingResponse struct {
	EnrollmentIDs []string `json:"enrollment_ids"`
}

// AckRequest acks consumed lease ids (done) and nacks transient ones (redeliver).
type AckRequest struct {
	Ack  []int64 `json:"ack"`
	Nack []int64 `json:"nack"`
}

const (
	collectMaxBody  = 1 << 20 // 1 MiB: a claim batch of bundles
	defaultClaim    = 64
	maxClaim        = 512
	defaultLeaseTTL = 60 * time.Second
)

// Server is the gateway-side collect API over its LOCAL durable queue. It is
// served on a separate listener behind leaf-pinned mTLS (ServerTLS) reachable only
// from Harbor's source — never the public internet.
type Server struct {
	q   *queue.Durable
	log *slog.Logger
}

// NewServer builds the gateway-side collect API over q.
func NewServer(q *queue.Durable, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{q: q, log: logger}
}

// Handler returns the collect routes (claim / results / ack).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /collect/v1/claim", s.handleClaim)
	mux.HandleFunc("POST /collect/v1/results", s.handleResults)
	mux.HandleFunc("POST /collect/v1/ack", s.handleAck)
	// Delivery-reconcile lane — structurally separate from the claim/ack candidate flow.
	// Harbor pulls the ids of results still pending here, then pushes the resolved ones
	// back via /results. Read-only; the gateway never originates a call to Harbor.
	mux.HandleFunc("GET /collect/v1/pending", s.handlePending)
	return mux
}

func (s *Server) handleClaim(w http.ResponseWriter, r *http.Request) {
	var req ClaimRequest
	if !readJSON(w, r, &req) {
		return
	}
	limit := req.Limit
	if limit <= 0 || limit > maxClaim {
		limit = defaultClaim
	}
	lease := time.Duration(req.LeaseMs) * time.Millisecond
	if lease <= 0 {
		lease = defaultLeaseTTL
	}
	leased, err := s.q.Claim(r.Context(), limit, lease)
	if err != nil {
		http.Error(w, "claim failed", http.StatusInternalServerError)
		return
	}
	resp := ClaimResponse{Candidates: make([]Candidate, len(leased))}
	for i, l := range leased {
		resp.Candidates[i] = Candidate{
			LeaseID: l.ID, EnrollmentID: l.Candidate.EnrollmentID, PubkeyHash: l.Candidate.PubkeyHash,
			RequestJWS: l.Candidate.RequestJWS, RetrievalSecretHash: l.Candidate.RetrievalSecretHash,
			ReceivedAt: l.Candidate.ReceivedAt,
		}
	}
	writeJSON(w, resp)
}

func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	var req PutResultsRequest
	if !readJSON(w, r, &req) {
		return
	}
	for _, res := range req.Results {
		if err := s.q.PutResult(r.Context(), res.EnrollmentID, res.Status, res.SecretHash, res.Bundle, res.Reason, res.ExpiresAt); err != nil {
			http.Error(w, "put result failed", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// handlePending reports the enrollment ids the gateway is still holding a pending
// result for — the delivery-reconcile work-list. Read-only over the local queue.
func (s *Server) handlePending(w http.ResponseWriter, r *http.Request) {
	ids, err := s.q.PendingResultIDs(r.Context())
	if err != nil {
		http.Error(w, "pending lookup failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, PendingResponse{EnrollmentIDs: ids})
}

func (s *Server) handleAck(w http.ResponseWriter, r *http.Request) {
	var req AckRequest
	if !readJSON(w, r, &req) {
		return
	}
	for _, id := range req.Ack {
		if err := s.q.Ack(r.Context(), id); err != nil {
			http.Error(w, "ack failed", http.StatusInternalServerError)
			return
		}
	}
	for _, id := range req.Nack {
		if err := s.q.Nack(r.Context(), id); err != nil {
			http.Error(w, "nack failed", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, collectMaxBody))
	if err := dec.Decode(v); err != nil {
		http.Error(w, "bad request body", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
