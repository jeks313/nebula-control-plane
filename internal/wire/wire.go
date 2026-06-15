// Package wire holds the shared on-the-wire types and error model from the
// protocol spec (§2, §7) — used by both the Enrollment Gateway and Core so the
// contract is defined once.
package wire

import (
	"crypto/sha256"
	"encoding/base64"
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

// JWS `typ` values (spec §3).
const (
	TypEnrollRequest = "ncp-request+jws"
	TypRenewRequest  = "ncp-renew+jws"
	TypBundle        = "ncp-bundle+jws"
)

// RenewRequest is the JWS payload of POST /v1/certs/renew (spec §8.1), signed by
// the host's NEW key (proof of possession). The identity is established by the
// calling tunnel (source overlay IP), not by this request.
type RenewRequest struct {
	ProtocolVersion int    `json:"protocol_version"`
	Type            string `json:"type"` // "renew"
	IssuedAt        string `json:"issued_at"`
	CSR             CSR    `json:"csr"`
}

// RenewResponse carries the freshly signed bundle.
type RenewResponse struct {
	ProtocolVersion int             `json:"protocol_version"`
	Bundle          json.RawMessage `json:"bundle"`
}

// ConfigResponse carries the host's CURRENT signed config bundle (GET /v1/config,
// spec §9) — same shape as a renew, but built from the host's EXISTING cert with
// no key rotation or re-issue: a config-only refresh used to fast-propagate a
// blocklist/policy/lighthouse change (7.1b).
type ConfigResponse struct {
	ProtocolVersion int             `json:"protocol_version"`
	Bundle          json.RawMessage `json:"bundle"`
}

// HeartbeatRequest is the POST /v1/heartbeat body (spec §8.2). Mesh-only,
// attributed to the calling tunnel's overlay IP — no JWS needed.
type HeartbeatRequest struct {
	ProtocolVersion         int    `json:"protocol_version"`
	Type                    string `json:"type"` // "heartbeat"
	AppliedBundleVersion    int    `json:"applied_bundle_version"`
	AppliedBlocklistVersion int    `json:"applied_blocklist_version"`
	CertNotAfter            string `json:"cert_not_after"` // RFC3339
	PilotVersion            string `json:"pilot_version"`
	PilotSHA256             string `json:"pilot_sha256"` // sha of the RUNNING pilot binary; maps to a release generation (3c)
	NebulaVersion           string `json:"nebula_version"`
	NebulaSHA256            string `json:"nebula_sha256"` // sha of the RUNNING nebula binary; maps to a release generation (1c)
	ClockOffsetMs           int    `json:"clock_offset_ms"`
	Health                  string `json:"health"`
}

// Command types — a CLOSED set (spec §8.2). Pilot executes only these and
// rejects anything else; the command channel is never arbitrary execution.
const (
	CmdRenew       = "renew"
	CmdApplyBundle = "apply_bundle"
	CmdRestart     = "restart"
)

// Command is one typed instruction from Core to Pilot.
type Command struct {
	Type          string `json:"type"`
	BundleVersion int    `json:"bundle_version,omitempty"`
}

// HeartbeatResponse carries the typed command channel back to Pilot.
type HeartbeatResponse struct {
	ProtocolVersion int       `json:"protocol_version"`
	Commands        []Command `json:"commands"`
}

// PollResponse is the GET /v1/enroll/{id} body (spec §5.3).
type PollResponse struct {
	Status      string          `json:"status"` // pending | issued | denied
	PollAfterMs int             `json:"poll_after_ms,omitempty"`
	Bundle      json.RawMessage `json:"bundle,omitempty"` // a bundle JWS, when issued
	Reason      string          `json:"reason,omitempty"`
}

// Enrollment methods (spec §5.4).
const (
	MethodToken     = "token"
	MethodAWSSigV4  = "aws-sigv4"
	MethodAzureIMDS = "azure-imds"
	MethodOIDC      = "oidc"
)

// CSR is the to-be-certified key + requested attributes (spec §5.1). Requested
// fields are advisory; Harbor is authoritative.
type CSR struct {
	Curve           string   `json:"curve"`
	PublicKey       string   `json:"public_key"` // base64url 65-byte P256 point
	RequestedName   string   `json:"requested_name"`
	RequestedGroups []string `json:"requested_groups"`
}

// EnrollRequest is the JWS payload of POST /v1/enroll (spec §5.1).
type EnrollRequest struct {
	ProtocolVersion int             `json:"protocol_version"`
	Type            string          `json:"type"`
	IssuedAt        string          `json:"issued_at"`
	Nonce           string          `json:"nonce"`
	CSR             CSR             `json:"csr"`
	Method          string          `json:"method"`
	Credential      json.RawMessage `json:"credential"`
	Client          struct {
		PilotVersion              string `json:"pilot_version"`
		SupportedProtocolVersions []int  `json:"supported_protocol_versions"`
	} `json:"client"`
}

// EnrollAccepted is the 202 ticket (spec §5.1).
type EnrollAccepted struct {
	ProtocolVersion int    `json:"protocol_version"`
	EnrollmentID    string `json:"enrollment_id"`
	RetrievalSecret string `json:"retrieval_secret"`
	PollAfterMs     int    `json:"poll_after_ms"`
	ExpiresAt       string `json:"expires_at"`
}

// PubkeyHash is base64url(SHA-256(pubkey)) — the stable key identifier used for
// nonce binding and JWS kid (spec §4.2).
func PubkeyHash(pub []byte) string {
	h := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(h[:])
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
