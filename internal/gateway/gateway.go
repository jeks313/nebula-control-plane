// Package gateway is the public, credential-less Enrollment Gateway
// (design §P3, implementation-plan M3.x). It deliberately depends on no DB/KMS:
// it mints nonces (3.2) and — from 3.3 — does structural validation and queue
// publish, nothing more. Authoritative decisions live in Core.
package gateway

import (
	"net/http"

	"github.com/jeks313/nebula-control-plane/internal/nonce"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

// maxBindingLen caps the nonce `binding` query value (a base64url pubkey hash is
// ~43 chars; allow generous slack, reject anything absurd pre-work).
const maxBindingLen = 128

// Server is the gateway HTTP surface.
type Server struct {
	nonces *nonce.Keyring
}

// New builds a gateway over a nonce keyring.
func New(keyring *nonce.Keyring) *Server {
	return &Server{nonces: keyring}
}

// Handler returns the gateway's HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/nonce", s.handleNonce)
	return mux
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
		ExpiresAt:       expires.Format("2006-01-02T15:04:05Z07:00"),
	})
}
