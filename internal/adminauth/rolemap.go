package adminauth

import "sort"

// RoleMapper turns a Subject's provider-specific groups into Harbor roles. It is
// the one place IdP group membership becomes authority, so it is explicit and
// fail-closed: an unmapped group grants nothing. DefaultRoles (typically
// ["viewer"]) are granted to any successfully authenticated user — the docs'
// "read-only default" — so a new employee can see the fleet without being granted
// any privileged group.
//
// The Harbor role names are the RBAC vocabulary the admin API authorizes against
// (see internal/adminapi: admin, operator, viewer; break-glass is a capability).
type RoleMapper struct {
	GroupRoles   map[string][]string // group identifier -> Harbor roles
	DefaultRoles []string            // roles every authenticated user gets
}

// Roles returns the deduped, sorted Harbor roles for a set of provider groups.
func (m *RoleMapper) Roles(groups []string) []string {
	set := map[string]bool{}
	for _, r := range m.DefaultRoles {
		set[r] = true
	}
	for _, g := range groups {
		for _, r := range m.GroupRoles[g] {
			set[r] = true
		}
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}
