import { useQuery, useInfiniteQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { components } from './schema'
import { api, unwrap } from './client'
import { ApiError, parseProblem } from './errors'

export type FleetHealth = components['schemas']['FleetHealth']
export type GatewayStatus = components['schemas']['GatewayStatus']
export type GatewaysResponse = components['schemas']['GatewaysResponse']
export type Identity = components['schemas']['Identity']
export type Device = components['schemas']['Device']
export type AuditRow = components['schemas']['AuditRow']
export type Enrollment = components['schemas']['EnrollmentView']
export type JoinKey = components['schemas']['JoinKey']
export type JoinKeyCreate = components['schemas']['JoinKeyCreate']
export type JoinKeyCreated = components['schemas']['JoinKeyCreated']
export type JoinKeyUpdate = components['schemas']['JoinKeyUpdate']
export type IDPEntry = components['schemas']['IDPEntry']
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

export type CA = components['schemas']['CA']
export type CAListResponse = components['schemas']['CAListResponse']
export type CAAdoption = components['schemas']['CAAdoption']

export type EnrollmentStatus = 'pending' | 'issued' | 'denied'

// unwrap (client.ts) parses problem+json into a typed ApiError; a 401 is left to the
// AuthGate (which shows the login screen) rather than redirecting from inside a query.
export function useMe() {
  return useQuery({
    queryKey: ['me'],
    queryFn: () => unwrap(api.GET('/admin/v1/me')),
  })
}

// --- build version + changelog (GET /admin/v1/version) ---

export type ChangelogCommit = { hash: string; subject: string; date: string }
export type ChangelogDay = { date: string; commits: ChangelogCommit[] }
export type VersionInfo = { version: string; commit: string; build_time: string; days: ChangelogDay[] }

// useVersion reads this Harbor's build identity + embedded changelog. The values are fixed for the
// life of the page (baked into the binary), so it never needs to refetch.
export function useVersion() {
  return useQuery({
    queryKey: ['version'],
    queryFn: async (): Promise<VersionInfo> => {
      const { data, response } = await api.GET('/admin/v1/version')
      if (!response.ok) throw await parseProblem(response)
      return data as unknown as VersionInfo
    },
    staleTime: Infinity,
  })
}

export function useFleetHealth() {
  return useQuery({
    queryKey: ['fleet-health'],
    queryFn: () => unwrap(api.GET('/admin/v1/fleet/health')),
    refetchInterval: 15_000, // the rollup is one cheap server call; keep it fresh
  })
}

// useGateways — the pull-based enrollment gateways (ADR 0005) + their collect-loop health,
// for the dashboard Gateways pane. Polled like the fleet rollup so an outage surfaces fast.
export function useGateways() {
  return useQuery({
    queryKey: ['gateways'],
    queryFn: () => unwrap(api.GET('/admin/v1/gateways')),
    refetchInterval: 15_000,
  })
}

// useCAs — the M8 CA-rotation lifecycle (states, active/trusted, drain count, key-deletion) for the
// CA Rotation dashboard. Polled so a live rotation (drain / adoption / key-deletion countdown) stays
// fresh without a manual refresh.
export function useCAs() {
  return useQuery({
    queryKey: ['ca'],
    queryFn: () => unwrap(api.GET('/admin/v1/ca')),
    refetchInterval: 15_000,
  })
}

// useCAAdoption — per-CA trust-adoption progress (the "trust before you sign" gate the CLI enforces
// before `ca activate`). Enabled only when an id is given, so the page fetches it just for the staged
// CA an operator is watching toward 100%.
export function useCAAdoption(id: number | null) {
  return useQuery({
    queryKey: ['ca-adoption', id],
    queryFn: () => unwrap(api.GET('/admin/v1/ca/{id}/adoption', { params: { path: { id: id as number } } })),
    enabled: id != null,
    refetchInterval: 15_000,
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
      unwrap(api.GET('/admin/v1/enrollments', { params: { query: { status, limit: 200, before: pageParam } } })),
    initialPageParam: 0, // before=0 -> no cursor -> newest page first
    getNextPageParam: (last) => last.next_before ?? undefined,
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

// --- SSO user-trust config (ADR 0004) — the peer to cloud-trust ---

export type UserTrust = components['schemas']['UserTrustActive']

export function useUserTrustActive() {
  return useQuery({
    queryKey: ['usertrust'],
    queryFn: () => unwrap(api.GET('/admin/v1/usertrust/active')),
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
      void qc.invalidateQueries({ queryKey: ['usertrust'] })
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

// --- ADR 0011 Phase 1: declarative config (PUT /admin/v1/config/{kind}) ---
// The propose/approve flow for policy/cloudtrust/usertrust is replaced by a single
// declarative PUT. A non-privileged write is applied directly (200 + the stored row);
// a PRIVILEGED change (grants a reserved group, or any auto_issue=true) is instead
// routed to a distinct-second-approver dual-control commit (202 + the pending Change),
// which then shows up in the existing /approvals inbox. A 400 carries the exact
// validator message (e.g. usertrust auto_issue+reserved, a bad policy DSL); a 403 is
// the missing {kind}:manage permission.

export type ConfigRow = components['schemas']['ConfigRow']
export type ConfigKind = 'policy' | 'cloudtrust' | 'usertrust'

// PutConfigResult discriminates the two success outcomes the editors must show very
// differently: an immediate apply (200) vs a privileged change routed to a second
// approver (202). The HTTP status is the ONLY signal — both bodies are 2xx JSON — so
// we read it off the raw Response rather than going through unwrap (which drops it).
export type PutConfigResult =
  | { applied: true; routed: false; row: ConfigRow }
  | { applied: false; routed: true; change: Change }

// putConfig calls PUT /admin/v1/config/{kind} and maps the status. It throws the same
// typed ApiError as unwrap on a non-2xx (so the central MutationCache 401/step-up
// handling in main.tsx still fires, and a 400/403 surfaces as ApiError.detail/title).
async function putConfig(kind: ConfigKind, body: unknown): Promise<PutConfigResult> {
  // ConfigBody is `unknown` in the contract (shape varies by kind); openapi-fetch's
  // typed PUT can't model a per-kind body, so cast the body at this single seam.
  const { data, response } = await api.PUT('/admin/v1/config/{kind}', {
    params: { path: { kind } },
    body: body as never,
  })
  if (!response.ok) throw await parseProblem(response)
  if (data === undefined) throw new ApiError(response.status, 'empty response')
  if (response.status === 202) return { applied: false, routed: true, change: data as Change }
  return { applied: true, routed: false, row: data as ConfigRow }
}

// usePutPolicy — set the firewall policy. The body is the DSL carried as a JSON string
// (the ConfigBody contract). A valid policy is never privileged, so this always applies
// directly (200); the 202 branch is kept for the uniform shape. onSettled refetches the
// active policy + the approvals inbox (a 202 lands a pending change there).
export function usePutPolicy() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (dsl: string) => putConfig('policy', dsl),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['policy-active'] })
      void qc.invalidateQueries({ queryKey: ['approvals'] })
    },
  })
}

// usePutCloudTrust — set the WHOLE cloud-trust config ({default_groups, aws}). Granting
// any auto_issue scope is privileged and routes to a second approver (202); otherwise it
// applies directly (200). onSettled refetches the active config + the approvals inbox.
export function usePutCloudTrust() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { default_groups: string[]; aws: CloudTrustAccount[] }) => putConfig('cloudtrust', body),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['cloudtrust'] })
      void qc.invalidateQueries({ queryKey: ['approvals'] })
    },
  })
}

// usePutUserTrust — set the WHOLE user-trust config ({default_groups, idp_entries},
// ordered first-match-wins). Granting auto_issue is privileged (202); auto_issue on a
// reserved group is refused outright (400, the exact server message). onSettled refetches
// the active config + the approvals inbox.
export function usePutUserTrust() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { default_groups: string[]; idp_entries: IDPEntry[] }) => putConfig('usertrust', body),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['usertrust'] })
      void qc.invalidateQueries({ queryKey: ['approvals'] })
    },
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

// useDeviceRegroup sets a device's DESIRED groups (ADR 0002). The change takes effect on the
// host's next heartbeat-triggered renew; the device list re-fetches so the pending badge shows.
export function useDeviceRegroup() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ ip, groups }: { ip: string; groups: string[] }) =>
      unwrap(api.PATCH('/admin/v1/devices/{ip}/groups', { params: { path: { ip } }, body: { groups } })),
    onSettled: () => qc.invalidateQueries({ queryKey: ['devices'] }),
  })
}

// --- ADR 0013 bulk device re-group (name-pattern dry-run → guarded apply / dual-control) ---
// The endpoint is contract-generic (Record<string,never> bodies), so the shapes are typed here.

export type RegroupSelection = {
  name_pattern?: string
  overlay_ips?: string[]
  add?: string[]
  remove?: string[]
  replace?: string[]
  include_stale?: boolean
}
export type RegroupDryEntry = {
  overlay_ip: string
  enrollment_id: number
  name: string
  from: string[]
  target: string[]
  base_generation: number
  will_reduce: boolean
  elevates: boolean
}
export type RegroupSkip = { overlay_ip: string; name: string; reason: string }
export type RegroupPreview = {
  entries: RegroupDryEntry[]
  skipped: RegroupSkip[]
  capped: number
  requires_dual_control: boolean
}
export type RegroupApplyEntry = {
  overlay_ip: string
  enrollment_id: number
  base_generation: number
  target: string[]
}
export type RegroupResult = { overlay_ip: string; status: string }
export type RegroupApplyResult =
  | { routed: false; results: RegroupResult[] }
  | { routed: true; change: Change }

// useRegroupPreview — POST .../regroup?dry_run=true: resolve a selection + delta into per-device
// absolute targets + identity tokens + skips, with NO writes. A mutation since it POSTs a draft.
export function useRegroupPreview() {
  return useMutation({
    mutationFn: async (sel: RegroupSelection): Promise<RegroupPreview> => {
      const { data, response } = await api.POST('/admin/v1/devices/regroup', {
        params: { query: { dry_run: true } },
        body: sel,
      })
      if (!response.ok) throw await parseProblem(response)
      return data as unknown as RegroupPreview
    },
  })
}

export type RegroupMatchSample = { name: string; overlay_ip: string; eligible: boolean; reason?: string }
export type RegroupMatch = { matched: number; eligible: number; sample: RegroupMatchSample[]; skipped: Record<string, number> }

// useRegroupMatch — live "N devices match" hint for the bulk dialog (GET .../regroup/match). Read-only;
// keyed on the (already-debounced) pattern + include_stale, disabled for an empty pattern. Keeps the
// prior result while a new pattern is in flight so the hint doesn't flicker as you type.
export function useRegroupMatch(namePattern: string, includeStale: boolean) {
  return useQuery({
    queryKey: ['regroup-match', namePattern, includeStale],
    queryFn: async (): Promise<RegroupMatch> => {
      const { data, response } = await api.GET('/admin/v1/devices/regroup/match', {
        params: { query: { name_pattern: namePattern, include_stale: includeStale } },
      })
      if (!response.ok) throw await parseProblem(response)
      return data as unknown as RegroupMatch
    },
    enabled: namePattern.trim().length > 0,
    placeholderData: (prev) => prev,
  })
}

// useRegroupApply — POST .../regroup: commit the confirmed entries. 200 = applied directly
// (per-device results, generation-guarded); 202 = an elevating/large change routed to a distinct
// second approver (the pending Change). The HTTP status is the only discriminator (both 2xx JSON),
// so read it off the raw Response. onSettled refetches devices (pending badges) + approvals (202).
export function useRegroupApply() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (entries: RegroupApplyEntry[]): Promise<RegroupApplyResult> => {
      const { data, response } = await api.POST('/admin/v1/devices/regroup', { body: { entries } as never })
      if (!response.ok) throw await parseProblem(response)
      if (data === undefined) throw new ApiError(response.status, 'empty response')
      if (response.status === 202) return { routed: true, change: data as unknown as Change }
      return { routed: false, results: (data as unknown as { results: RegroupResult[] }).results }
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['devices'] })
      void qc.invalidateQueries({ queryKey: ['approvals'] })
    },
  })
}

// --- ADR 0010 IPAM (netblocks, allocations, growth-aware placement) ---

export type Netblock = components['schemas']['Netblock']
export type NetblockCreate = components['schemas']['NetblockCreateRequest']
export type NetblockUpdate = components['schemas']['NetblockUpdateRequest']
export type Allocation = components['schemas']['Allocation']

// The netblock set is tiny (central/default + a handful of carves), so it's a plain
// list like joinkeys/lighthouses — no paging. The create-overlay derives the pool
// extent + carves from this same list, so keep it the single source of truth.
export function useNetblocks() {
  return useQuery({
    queryKey: ['netblocks'],
    queryFn: () => unwrap(api.GET('/admin/v1/ipam/netblocks')),
  })
}

// Growth-aware placement suggestion for a /prefix carve. The same Go function is the
// authoritative submit-time default; this just pre-fills + drives the overlay. Disabled
// for an out-of-range prefix; a 409 "pool full" surfaces via the query error.
export function useNetblockSuggest(prefix: number) {
  return useQuery({
    queryKey: ['netblock-suggest', prefix],
    queryFn: () => unwrap(api.GET('/admin/v1/ipam/netblocks/suggest', { params: { query: { prefix } } })),
    enabled: prefix >= 1 && prefix <= 32,
    retry: false, // a 409 (no slot of this size) is a real answer, not a transient failure
  })
}

// Per-block allocations (overlay/heat data). Enabled only when a block name is given.
export function useNetblockAllocations(name: string | undefined) {
  return useQuery({
    queryKey: ['netblock-allocations', name],
    queryFn: () => unwrap(api.GET('/admin/v1/ipam/allocations', { params: { query: { netblock: name as string } } })),
    enabled: !!name,
  })
}

// Mutations invalidate the netblock list (and the suggestion, since a carve shifts where
// the next block lands). onSettled, not onSuccess: a 409/422 still means the world moved.
// Auth/step-up errors are handled centrally by the MutationCache (main.tsx).

export function useCreateNetblock() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: NetblockCreate) => unwrap(api.POST('/admin/v1/ipam/netblocks', { body })),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['netblocks'] })
      void qc.invalidateQueries({ queryKey: ['netblock-suggest'] })
    },
  })
}

export function useUpdateNetblock() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ name, body }: { name: string; body: NetblockUpdate }) =>
      unwrap(api.PATCH('/admin/v1/ipam/netblocks/{name}', { params: { path: { name } }, body })),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['netblocks'] })
      void qc.invalidateQueries({ queryKey: ['netblock-suggest'] })
    },
  })
}

export function useDeleteNetblock() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (name: string) =>
      unwrap(api.DELETE('/admin/v1/ipam/netblocks/{name}', { params: { path: { name } } })),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['netblocks'] })
      void qc.invalidateQueries({ queryKey: ['netblock-suggest'] })
    },
  })
}
