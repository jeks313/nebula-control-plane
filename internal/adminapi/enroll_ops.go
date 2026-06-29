package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jeks313/nebula-control-plane/internal/enrollment"
)

// A0.5 enrollment approval queue. List + deny work on any (Store-only) consumer;
// approve issues a cert and is gated on CanIssue (the admin-api was started with
// the signing config). Actions bind to the authenticated principal.

// EnrollmentView is the API view of a pending/decided enrollment. The host
// pubkey + issued cert bytes are intentionally omitted (large; fingerprint only).
type EnrollmentView struct {
	EnrollmentID string   `json:"enrollment_id"`
	DeviceName   string   `json:"device_name"`
	PubkeyHash   string   `json:"pubkey_hash"`
	Method       string   `json:"method"`
	JoinKeyID    int64    `json:"join_key_id,omitempty"`
	JoinKeyName  string   `json:"join_key_name,omitempty"` // resolved from join_key_id; user-friendly provenance
	Groups       []string `json:"groups"`
	Status       string   `json:"status"`
	// Ephemeral marks an enrollment via an ephemeral join key (shorter cert TTL; foundation
	// for the auto-reaping lifecycle, impl 2.12). Always false for cloud-sigv4 / SSO.
	Ephemeral bool   `json:"ephemeral,omitempty"`
	OverlayIP string `json:"overlay_ip,omitempty"`
	CreatedAt string `json:"created_at"`
	DecidedAt string `json:"decided_at,omitempty"`
	Approver  string `json:"approver,omitempty"`
	// Cloud-attestation evidence (M5; provider-agnostic). Present only for attested hosts.
	AttestProvider  string `json:"attest_provider,omitempty"`
	AttestAccount   string `json:"attest_account,omitempty"`
	AttestPrincipal string `json:"attest_principal,omitempty"`
	AttestRegion    string `json:"attest_region,omitempty"`
	VerifiedAt      string `json:"verified_at,omitempty"`
}

func enrollmentView(e enrollment.Enrollment) EnrollmentView {
	var groups []string
	_ = json.Unmarshal([]byte(e.Groups), &groups)
	if groups == nil {
		groups = []string{}
	}
	return EnrollmentView{
		EnrollmentID: e.EnrollmentID, DeviceName: e.DeviceName, PubkeyHash: e.PubkeyHash,
		Method: e.Method, JoinKeyID: e.JoinKeyID, Groups: groups, Status: e.Status,
		Ephemeral: e.Ephemeral,
		OverlayIP: e.OverlayIP, CreatedAt: rfc3339(e.CreatedAt), DecidedAt: rfc3339(e.DecidedAt),
		Approver:        e.Approver,
		AttestProvider:  e.AttestProvider,
		AttestAccount:   e.AttestAccount,
		AttestPrincipal: e.AttestPrincipal,
		AttestRegion:    e.AttestRegion,
		VerifiedAt:      rfc3339(e.VerifiedAt),
	}
}

func (s *Server) mapEnrollErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, enrollment.ErrNotPending):
		writeProblem(w, http.StatusConflict, "not pending", "the enrollment is not awaiting approval")
	default:
		s.fail(w, r, "enrollment operation failed", err)
	}
}

// GET /admin/v1/enrollments?status=pending&limit=N&before=ID — the approval queue
// (default pending; pass status=issued|denied to view decided ones). Keyset-paginated
// NEWEST-FIRST on id (same shape as /audit's `before` cursor): the queue is join-key-holder
// influenced and pending rows are never auto-reaped, so it must not be unbounded. `count` is
// the page size; `next_before` (when present) pages to older rows.
func (s *Server) handleEnrollments(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status == "" {
		status = enrollment.StatusPending
	}
	limit := queryInt(r, "limit", 200, 1, 2000)
	before := queryInt(r, "before", 0, 0, 1<<62)
	q := s.cfg.Store.DB.WithContext(r.Context()).Model(&enrollment.Enrollment{}).
		Where("status = ?", status).Order("id DESC").Limit(limit)
	if before > 0 {
		q = q.Where("id < ?", before)
	}
	var es []enrollment.Enrollment
	if err := q.Find(&es).Error; err != nil {
		s.fail(w, r, "list enrollments failed", err)
		return
	}
	// Resolve join-key names for token enrollments on this page (one lookup), so the
	// UI can show "token · laptops-2026" instead of a bare numeric id.
	var names map[int64]string
	for _, e := range es {
		if e.JoinKeyID != 0 {
			var nerr error
			if names, nerr = s.joinKeyNameMap(r.Context()); nerr != nil {
				s.fail(w, r, "join key lookup failed", nerr)
				return
			}
			break
		}
	}
	out := make([]EnrollmentView, len(es))
	for i, e := range es {
		v := enrollmentView(e)
		if e.JoinKeyID != 0 {
			v.JoinKeyName = names[e.JoinKeyID]
		}
		out[i] = v
	}
	resp := map[string]any{"enrollments": out, "count": len(out)}
	if len(es) == limit {
		resp["next_before"] = es[len(es)-1].ID // cursor: rows with a lower id (older)
	}
	writeJSON(w, http.StatusOK, resp)
}

// EnrollDecision is the result of an approve/deny.
type EnrollDecision struct {
	EnrollmentID string `json:"enrollment_id"`
	Status       string `json:"status"`
	OverlayIP    string `json:"overlay_ip,omitempty"`
}

// POST /admin/v1/enrollments/{id}/approve — issue the cert for a pending host.
// 501 when the admin-api was not started with the signing config (CanIssue).
func (s *Server) handleEnrollApprove(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !s.requirePerm(w, id, PermEnrollDecide) {
		return
	}
	if !s.cfg.CanIssue {
		writeProblem(w, http.StatusNotImplemented, "issuance not configured",
			"this admin-api was started read-only; run it with the CA/signing config to approve enrollments")
		return
	}
	eid := r.PathValue("id")
	res, err := s.cfg.Enrollment.Approve(r.Context(), eid, id.Principal)
	if err != nil {
		s.mapEnrollErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, EnrollDecision{EnrollmentID: res.EnrollmentID, Status: res.Status, OverlayIP: res.OverlayIP})
}

// POST /admin/v1/enrollments/{id}/deny — reject a pending host (no signing).
func (s *Server) handleEnrollDeny(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !s.requirePerm(w, id, PermEnrollDecide) {
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	res, err := s.cfg.Enrollment.Deny(r.Context(), r.PathValue("id"), id.Principal, body.Reason)
	if err != nil {
		s.mapEnrollErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, EnrollDecision{EnrollmentID: res.EnrollmentID, Status: res.Status})
}
