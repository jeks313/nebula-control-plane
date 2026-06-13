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
export type Lighthouse = components['schemas']['Lighthouse']
export type RolloutStatus = components['schemas']['RolloutStatus']
export type RolloutHost = components['schemas']['RolloutHost']
export type AuditVerify = components['schemas']['AuditVerify']
export type ActivePolicy = components['schemas']['ActivePolicy']
export type Change = components['schemas']['Change']

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

export function useDevices() {
  return useQuery({
    queryKey: ['devices'],
    queryFn: () => unwrap(api.GET('/admin/v1/devices', { params: { query: { limit: 200 } } })),
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
