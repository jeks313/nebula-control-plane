package adminapi

import "net/http"

// RBAC (implementation-plan 2.11). The admin API authorizes by PERMISSION, not by
// a single hard-coded role, so the role set can grow without touching handlers.
// Roles arrive on the authenticated Identity (mapped from IdP groups by
// internal/adminauth); the client gets no say — every check is here, server-side
// (P-UI-1). admin is a superuser; operator does day-2 fleet ops but never policy /
// CA / dual-control; viewer is read-only (the default); break-glass is a
// dual-control capability (a valid second sign-off when the IdP/mesh is down),
// handled in the approval flow, and intentionally grants no standalone permission.
type Permission string

const (
	PermLighthouseManage Permission = "lighthouse:manage" // add/replace/remove lighthouses
	PermRolloutControl   Permission = "rollout:control"   // start/step/abort rollouts
	PermJoinKeyManage    Permission = "joinkey:manage"    // create/revoke join keys
	PermEnrollDecide     Permission = "enroll:decide"     // approve/deny enrollments
	PermPolicyPropose    Permission = "policy:propose"    // open a policy-publish change
	PermApprovalDecide   Permission = "approval:decide"   // approve/deny a dual-control change
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
