import { useMe } from './hooks'

// Client mirror of the server RBAC matrix (internal/adminapi/rbac.go) — DEFENSE IN
// DEPTH ONLY (P-UI-1). The server enforces every permission on every endpoint; this
// only hides controls a role cannot use, so a viewer doesn't see dead buttons. A stale
// mirror can never grant authority (the server still 403s) — but keep it in sync.
export const PERMISSIONS = [
  'lighthouse:manage',
  'rollout:control',
  'joinkey:manage',
  'enroll:decide',
  'approval:decide',
  'ipam:manage',
  'device:manage', // reassign a device's groups post-enrollment (ADR 0002/0013)
  // ADR 0011 Phase 1: the declarative config-manage perms gating PUT /config/{kind}.
  // They REPLACE the old policy/cloudtrust/usertrust :propose perms (the in-app
  // propose/approve flow is gone). The operator now holds these (single-operator CRUD);
  // a PRIVILEGED change still routes to a distinct second approver (approval:decide).
  'policy:manage',
  'cloudtrust:manage',
  'usertrust:manage',
] as const

export type Permission = (typeof PERMISSIONS)[number]

// admin is a superuser; operator carries the ops perms AND (ADR 0011 Phase 1) writes
// declarative config directly via the PUT; viewer is read-only; break-glass carries no
// standalone permission (it's only a second sign-off).
const ROLE_PERMS: Record<string, readonly Permission[] | '*'> = {
  admin: '*',
  operator: [
    'lighthouse:manage',
    'rollout:control',
    'joinkey:manage',
    'enroll:decide',
    'ipam:manage',
    'device:manage',
    'policy:manage',
    'cloudtrust:manage',
    'usertrust:manage',
  ],
  viewer: [],
  'break-glass': [],
}

export function rolesHavePerm(roles: readonly string[], perm: Permission): boolean {
  return roles.some((r) => {
    const p = ROLE_PERMS[r]
    if (!p) return false
    return p === '*' || p.includes(perm)
  })
}

// usePermissions reads roles from /me and exposes a can() check for hiding controls.
export function usePermissions() {
  const me = useMe()
  const roles = me.data?.roles ?? []
  return { roles, can: (perm: Permission) => rolesHavePerm(roles, perm) }
}
