// Package wire holds the shared on-the-wire types and error model from the
// protocol spec (§2, §7) — used by both the Enrollment Gateway and Core so the
// contract is defined once.
package wire

import (
	"encoding/json"
	"net/http"
)

// ProtocolVersion is the current wire protocol major (spec §2.2).
const ProtocolVersion = 1

// Error codes (spec §7). Clients branch on Code, never Message.
const (
	CodeInvalidRequest     = "invalid_request"
	CodeUnsupportedVersion = "unsupported_version"
	CodeInvalidSignature   = "invalid_signature"
	CodeInvalidNonce       = "invalid_nonce"
	CodeNonceExpired       = "nonce_expired"
	CodeInvalidToken       = "invalid_token"
	CodeTokenUsed          = "token_used"
	CodeAttestationFailed  = "attestation_failed"
	CodeAccountNotAllowed  = "account_not_allowed"
	CodeQuotaExceeded      = "quota_exceeded"
	CodeRateLimited        = "rate_limited"
	CodeSigningUnavailable = "signing_unavailable"
	CodeConflict           = "conflict"
	CodeNotFound           = "not_found"
	CodeGone               = "gone"
	CodeInternal           = "internal"
)

// codeInfo maps each error code to its HTTP status and default retryability.
var codeInfo = map[string]struct {
	status    int
	retryable bool
}{
	CodeInvalidRequest:     {http.StatusBadRequest, false},
	CodeUnsupportedVersion: {http.StatusBadRequest, false},
	CodeInvalidSignature:   {http.StatusUnauthorized, false},
	CodeInvalidNonce:       {http.StatusUnauthorized, false},
	CodeNonceExpired:       {http.StatusUnauthorized, true},
	CodeInvalidToken:       {http.StatusUnauthorized, false},
	CodeTokenUsed:          {http.StatusConflict, false},
	CodeAttestationFailed:  {http.StatusUnauthorized, false},
	CodeAccountNotAllowed:  {http.StatusForbidden, false},
	CodeQuotaExceeded:      {http.StatusTooManyRequests, true},
	CodeRateLimited:        {http.StatusTooManyRequests, true},
	CodeSigningUnavailable: {http.StatusServiceUnavailable, true},
	CodeConflict:           {http.StatusConflict, false},
	CodeNotFound:           {http.StatusNotFound, false},
	CodeGone:               {http.StatusGone, false},
	CodeInternal:           {http.StatusInternalServerError, true},
}

// Error is the body's error object.
type Error struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type errorBody struct {
	Error Error `json:"error"`
}

// NonceResponse is the GET /v1/nonce body (spec §4.3).
type NonceResponse struct {
	ProtocolVersion int    `json:"protocol_version"`
	Nonce           string `json:"nonce"`
	ExpiresAt       string `json:"expires_at"`
}

// WriteJSON writes v as JSON with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes the uniform error body with the status/retryability for code.
func WriteError(w http.ResponseWriter, code, message string) {
	info, ok := codeInfo[code]
	if !ok {
		code, info = CodeInternal, codeInfo[CodeInternal]
	}
	if message == "" {
		message = code
	}
	WriteJSON(w, info.status, errorBody{Error: Error{Code: code, Message: message, Retryable: info.retryable}})
}
