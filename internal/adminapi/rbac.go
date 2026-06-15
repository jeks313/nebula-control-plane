package adminapi

import (
	"encoding/json"
	"net/http"
	"time"
)

// mfaClockSkew absorbs benign IdP-vs-Harbor clock drift in the step-up freshness
// check without admitting an arbitrarily future-dated MFA instant.
const mfaClockSkew = 2 * time.Minute

// Permission is one server-side RBAC capability (implementation-plan 2.11). The
// admin API authorizes by PERMISSION, not by a single hard-coded role, so the role
// set can grow without touching handlers. Roles arrive on the authenticated Identity
// (mapped from IdP groups by internal/adminauth); the client gets no say — every
// check is here, server-side (P-UI-1). admin is a superuser; operator does day-2
// fleet ops but never policy / CA / dual-control; viewer is read-only (the default);
// break-glass is a dual-control capability (a valid second sign-off when the IdP/mesh
// is down), handled in the approval flow, and grants no standalone permission.
type Permission string

// Permission constants — the capabilities the admin API authorizes against.
const (
	PermLighthouseManage  Permission = "lighthouse:manage"  // add/replace/remove lighthouses
	PermRolloutControl    Permission = "rollout:control"    // start/step/abort rollouts
	PermJoinKeyManage     Permission = "joinkey:manage"     // create/revoke join keys
	PermEnrollDecide      Permission = "enroll:decide"      // approve/deny enrollments
	PermPolicyPropose     Permission = "policy:propose"     // open a policy-publish change
	PermApprovalDecide    Permission = "approval:decide"    // approve/deny a dual-control change
	PermCloudTrustPropose Permission = "cloudtrust:propose" // open a cloud-trust-publish change
)

// RoleAdmin, RoleOperator, RoleViewer, RoleBreakGlass are the named roles. They
// are also the vocabulary internal/adminauth maps IdP groups onto.
const (
	RoleAdmin      = "admin"
	RoleOperator   = "operator"
	RoleViewer     = "viewer"
	RoleBreakGlass = "break-glass"
)

// rolePerms is the permission matrix for non-admin roles. admin is handled as a
// superuser in roleHasPerm (so a newly-added permission can never accidentally be
// withheld from admin). viewer and break-glass appear nowhere here: read-only and
// capability-only respectively.
var rolePerms = map[string]map[Permission]bool{
	RoleOperator: {
		PermLighthouseManage: true,
		PermRolloutControl:   true,
		PermJoinKeyManage:    true,
		PermEnrollDecide:     true,
	},
}

// roleHasPerm reports whether a single role carries a permission. admin is a
// superuser by construction.
func roleHasPerm(role string, perm Permission) bool {
	if role == RoleAdmin {
		return true
	}
	return rolePerms[role][perm]
}

// authorize reports whether any of the identity's roles carries the permission.
func authorize(id Identity, perm Permission) bool {
	for _, role := range id.Roles {
		if roleHasPerm(role, perm) {
			return true
		}
	}
	return false
}

// requirePerm enforces a permission, writing a 403 problem+json if absent. The
// detail names the missing permission (not the roles) so it doesn't leak the
// caller's role set.
func (s *Server) requirePerm(w http.ResponseWriter, id Identity, perm Permission) bool {
	if authorize(id, perm) {
		return true
	}
	writeProblem(w, http.StatusForbidden, "forbidden", "requires permission: "+string(perm))
	return false
}

// requireStepUp enforces recent multi-factor authentication for the most
// privileged, authority-GRANTING actions (dual-control approve, policy publish).
// It is opt-in: a zero MFAFreshness disables it (dev / no-IdP). When enabled, the
// session's mfa_satisfied_at must be within the freshness window; otherwise it
// returns a distinguishable 403 (code "step_up_required") so the console can force
// a re-auth (/admin/v1/auth/login?step_up=1) and retry. The safe direction (deny /
// veto) is intentionally NOT gated, so a bad change can always be stopped.
func (s *Server) requireStepUp(w http.ResponseWriter, id Identity) bool {
	if s.cfg.MFAFreshness <= 0 {
		return true // enforcement disabled
	}
	if id.MFAAt != nil {
		age := s.now().Sub(*id.MFAAt)
		// Fresh AND not future-dated. A future MFA instant (IdP clock ahead, or a
		// bad upstream timestamp) must not pass — a one-sided `age <= window` check
		// would accept it AND it would never expire (age stays negative). Mirrors
		// the symmetric bound in internal/nonce.
		if age >= -mfaClockSkew && age <= s.cfg.MFAFreshness {
			return true
		}
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"title":  "step-up required",
		"status": http.StatusForbidden,
		"detail": "this action requires recent multi-factor authentication; re-authenticate and retry",
		"code":   "step_up_required",
	})
	return false
}
