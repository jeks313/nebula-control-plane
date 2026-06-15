import { useQuery, useInfiniteQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { components } from './schema'
import { api, unwrap } from './client'

export type FleetHealth = components['schemas']['FleetHealth']
export type Identity = components['schemas']['Identity']
export type Device = components['schemas']['Device']
export type AuditRow = components['schemas']['AuditRow']
export type Enrollment = components['schemas']['EnrollmentView']
export type JoinKey = components['schemas']['JoinKey']
export type JoinKeyCreate = components['schemas']['JoinKeyCreate']
export type JoinKeyCreated = components['schemas']['JoinKeyCreated']
export type JoinKeyUpdate = components['schemas']['JoinKeyUpdate']
export type CloudTrustProposeRequest = components['schemas']['CloudTrustProposeRequest']
export type Lighthouse = components['schemas']['Lighthouse']
export type RolloutStatus = components['schemas']['RolloutStatus']
export type RolloutHost = components['schemas']['RolloutHost']
export type AuditVerify = components['schemas']['AuditVerify']
export type ActivePolicy = components['schemas']['ActivePolicy']
export type Change = components['schemas']['Change']
export type Signoff = components['schemas']['Signoff']
export type ApprovalDetail = components['schemas']['ApprovalDetail']
export type PolicyRule = components['schemas']['PolicyRule']
export type CompileResult = components['schemas']['CompileResult']

export type EnrollmentStatus = 'pending' | 'issued' | 'denied'

// unwrap (client.ts) parses problem+json into a typed ApiError; a 401 is left to the
// AuthGate (which shows the login screen) rather than redirecting from inside a query.
export function useMe() {
  return useQuery({
    queryKey: ['me'],
    queryFn: () => unwrap(api.GET('/admin/v1/me')),
  })
}

export function useFleetHealth() {
  return useQuery({
    queryKey: ['fleet-health'],
    queryFn: () => unwrap(api.GET('/admin/v1/fleet/health')),
    refetchInterval: 15_000, // the rollup is one cheap server call; keep it fresh
  })
}

export type DeviceCondition = 'expired' | 'expiring' | 'stale' | 'clock_skewed' | 'unhealthy'

export type DeviceFilters = {
  provider?: string
  attest_account?: string
  join_key?: string
  condition?: DeviceCondition
}

// useDevices supports the server-side scope filters (provider/attest_account/join_key)
// and the health-condition drill-down. Keyset-paginated on the `next_after` overlay_ip
// cursor (useInfiniteQuery, like useEnrollments) so a drill-down never silently caps —
// the dashboard "why" count and this list stay consistent at any fleet size.
export function useDevices(filters: DeviceFilters = {}) {
  const scope = {
    ...(filters.provider ? { provider: filters.provider } : {}),
    ...(filters.attest_account ? { attest_account: filters.attest_account } : {}),
    ...(filters.join_key ? { join_key: filters.join_key } : {}),
    ...(filters.condition ? { condition: filters.condition } : {}),
  }
  return useInfiniteQuery({
    queryKey: ['devices', filters],
    queryFn: ({ pageParam }) =>
      unwrap(api.GET('/admin/v1/devices', { params: { query: { limit: 200, ...scope, ...(pageParam ? { after: pageParam } : {}) } } })),
    initialPageParam: '',
    getNextPageParam: (last) => last.next_after ?? undefined,
  })
}

export function useAudit() {
  return useQuery({
    queryKey: ['audit'],
    queryFn: () => unwrap(api.GET('/admin/v1/audit', { params: { query: { limit: 50 } } })),
  })
}

// Enrollment approval queue — keyset-paginated on the integer `next_after` cursor
// (real paging, no silent cap). One query key per status tab.
export function useEnrollments(status: EnrollmentStatus) {
  return useInfiniteQuery({
    queryKey: ['enrollments', status],
    queryFn: ({ pageParam }) =>
      unwrap(api.GET('/admin/v1/enrollments', { params: { query: { status, limit: 200, after: pageParam } } })),
    initialPageParam: 0,
    getNextPageParam: (last) => last.next_after ?? undefined,
  })
}

export function useJoinKeys() {
  return useQuery({
    queryKey: ['joinkeys'],
    queryFn: () => unwrap(api.GET('/admin/v1/joinkeys')),
  })
}

// --- UI-2 fleet dashboard reads ---

export function useLighthouses() {
  return useQuery({
    queryKey: ['lighthouses'],
    queryFn: () => unwrap(api.GET('/admin/v1/lighthouses')),
  })
}

// The audit-chain verification walks the chain server-side; fetch once (no poll). A 503
// means the check couldn't run (not a tamper claim) — surfaces as isError to the card.
export function useAuditVerify() {
  return useQuery({
    queryKey: ['audit-verify'],
    queryFn: () => unwrap(api.GET('/admin/v1/audit/verify')),
  })
}

// Poll the current rollout so the active-operations strip stays live until A2/SSE lands.
export function useCurrentRollout() {
  return useQuery({
    queryKey: ['rollout-current'],
    queryFn: () => unwrap(api.GET('/admin/v1/rollouts/current')),
    refetchInterval: 10_000,
  })
}

export function useApprovals(state: string) {
  return useQuery({
    queryKey: ['approvals', state],
    queryFn: () => unwrap(api.GET('/admin/v1/approvals', { params: { query: { state } } })),
    refetchInterval: 15_000,
  })
}

export function useActivePolicy() {
  return useQuery({
    queryKey: ['policy-active'],
    queryFn: () => unwrap(api.GET('/admin/v1/policy/active')),
  })
}

// --- UI-3 cloud-attestation trust config ---

export type CloudTrust = components['schemas']['CloudTrustActive']
export type CloudTrustAccount = components['schemas']['CloudTrustAccount']

export function useCloudTrust() {
  return useQuery({
    queryKey: ['cloudtrust'],
    queryFn: () => unwrap(api.GET('/admin/v1/cloudtrust/active')),
  })
}

// --- #39 binary releases (nebula + pilot registries + per-lane fleet upgrades) ---

export type ReleasesResponse = components['schemas']['ReleasesResponse']
export type ReleaseLane = components['schemas']['ReleaseLane']
export type ReleaseView = components['schemas']['ReleaseView']
export type ReleaseRolloutStart = components['schemas']['ReleaseRolloutStart']
export type ReleaseKind = 'nebula' | 'pilot'

// The console lists both registries + each lane's live rollout in one call. Poll so a
// staged upgrade's wave progress / auto-rollback shows without a manual refresh (same
// cadence as useCurrentRollout, until SSE lands).
export function useReleases() {
  return useQuery({
    queryKey: ['releases'],
    queryFn: () => unwrap(api.GET('/admin/v1/releases')),
    refetchInterval: 10_000,
  })
}

// Stage a fleet upgrade to a registered generation on the kind's canary lane. Binaries
// are added out-of-band via the CLI (harbor nebula/pilot add) — this only triggers the
// rollout. onSettled refetches the registry+lane (a 409 "lane busy" still means re-read).
export function useStartReleaseRollout() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ kind, body }: { kind: ReleaseKind; body: ReleaseRolloutStart }) =>
      unwrap(api.POST('/admin/v1/releases/{kind}/rollouts', { params: { path: { kind } }, body })),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['releases'] })
      void qc.invalidateQueries({ queryKey: ['rollout-current'] })
    },
  })
}

export function useAbortReleaseRollout() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (kind: ReleaseKind) =>
      unwrap(api.POST('/admin/v1/releases/{kind}/rollouts/current/abort', { params: { path: { kind } } })),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['releases'] })
      void qc.invalidateQueries({ queryKey: ['rollout-current'] })
    },
  })
}

// --- UI-4 dual-control publish pipeline ---

export function useApproval(id: number) {
  return useQuery({
    queryKey: ['approval', id],
    queryFn: () => unwrap(api.GET('/admin/v1/approvals/{id}', { params: { path: { id } } })),
  })
}

// approve/deny/propose: the MutationCache (main.tsx) centrally handles 401 (→ login) and
// 403 step_up_required (→ re-auth + retry); callers handle the action-specific outcomes.
// onSettled refetches the inbox + this change + the active policy (a commit publishes).

export function useApproveChange() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => unwrap(api.POST('/admin/v1/approvals/{id}/approve', { params: { path: { id } } })),
    onSettled: (_d, _e, id) => {
      void qc.invalidateQueries({ queryKey: ['approvals'] })
      void qc.invalidateQueries({ queryKey: ['approval', id] })
      void qc.invalidateQueries({ queryKey: ['policy-active'] })
      void qc.invalidateQueries({ queryKey: ['cloudtrust'] })
    },
  })
}

export function useDenyChange() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, reason }: { id: number; reason?: string }) =>
      unwrap(api.POST('/admin/v1/approvals/{id}/deny', { params: { path: { id } }, body: { reason: reason ?? '' } })),
    onSettled: (_d, _e, vars) => {
      void qc.invalidateQueries({ queryKey: ['approvals'] })
      void qc.invalidateQueries({ queryKey: ['approval', vars.id] })
    },
  })
}

export function useProposePolicy() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { policy: string; description?: string }) =>
      unwrap(api.POST('/admin/v1/policy/propose', { body })),
    onSettled: () => qc.invalidateQueries({ queryKey: ['approvals'] }),
  })
}

// Cloud-trust is republished as a whole new version (no per-account patch): the form
// proposes a full {default_groups, aws} config through dual-control, reviewed in
// /approvals. The active config changes only on COMMIT (useApproveChange invalidates it).
export function useProposeCloudTrust() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: CloudTrustProposeRequest) => unwrap(api.POST('/admin/v1/cloudtrust/propose', { body })),
    onSettled: () => qc.invalidateQueries({ queryKey: ['approvals'] }),
  })
}

// compile is a read-only dry-run (no perm/step-up); a mutation since it POSTs a draft.
// It returns 200 even on a parse error (valid:false) — branch on result.valid.
export function useCompilePolicy() {
  return useMutation({
    mutationFn: (body: { policy: string; groups?: string[] }) =>
      unwrap(api.POST('/admin/v1/policy/compile', { body })),
  })
}

// --- A1 policy analysis (read-only dry-runs over a draft) ---

export type Decision = components['schemas']['ReachabilityDecision']
export type ReachabilityMatrix = components['schemas']['ReachabilityMatrix']
export type PolicyTestResults = components['schemas']['PolicyTestResults']
export type PolicyDiff = components['schemas']['PolicyDiff']

export function useReachability() {
  return useMutation({
    mutationFn: (body: { policy: string; from: string; to: string; proto?: string; port?: string }) =>
      unwrap(api.POST('/admin/v1/policy/reachability', { body })),
  })
}

export function usePolicyMatrix() {
  return useMutation({
    mutationFn: (body: { policy: string; groups?: string[] }) => unwrap(api.POST('/admin/v1/policy/matrix', { body })),
  })
}

export function useRunPolicyTests() {
  return useMutation({
    mutationFn: (body: { policy: string; tests: string }) => unwrap(api.POST('/admin/v1/policy/tests', { body })),
  })
}

// useFlowDiff (A1.2): the flows added/removed vs the active policy + the blast radius
// (real hosts whose firewall would change) for a draft.
export function useFlowDiff() {
  return useMutation({
    mutationFn: (body: { policy: string }) => unwrap(api.POST('/admin/v1/policy/diff', { body })),
  })
}

// --- mutations ---
// All use onSettled (not onSuccess) to refetch: a 409 "not pending" or a 404
// "already revoked" still means the list moved, so we always reconcile. Auth/step-up
// errors are handled centrally by the MutationCache (main.tsx); callers handle the
// action-specific outcomes (409/501/duplicate) for their toast copy.

export function useApproveEnrollment() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => unwrap(api.POST('/admin/v1/enrollments/{id}/approve', { params: { path: { id } } })),
    onSettled: () => qc.invalidateQueries({ queryKey: ['enrollments'] }),
  })
}

export function useDenyEnrollment() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, reason }: { id: string; reason?: string }) =>
      unwrap(api.POST('/admin/v1/enrollments/{id}/deny', { params: { path: { id } }, body: { reason: reason ?? '' } })),
    onSettled: () => qc.invalidateQueries({ queryKey: ['enrollments'] }),
  })
}

export function useCreateJoinKey() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: JoinKeyCreate) => unwrap(api.POST('/admin/v1/joinkeys', { body })),
    onSettled: () => qc.invalidateQueries({ queryKey: ['joinkeys'] }),
  })
}

export function useRevokeJoinKey() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (name: string) => unwrap(api.POST('/admin/v1/joinkeys/{name}/revoke', { params: { path: { name } } })),
    onSettled: () => qc.invalidateQueries({ queryKey: ['joinkeys'] }),
  })
}

export function useUpdateJoinKey() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ name, body }: { name: string; body: JoinKeyUpdate }) =>
      unwrap(api.PATCH('/admin/v1/joinkeys/{name}', { params: { path: { name } }, body })),
    onSettled: () => qc.invalidateQueries({ queryKey: ['joinkeys'] }),
  })
}
