import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  useDevices,
  useDeviceRegroup,
  useRegroupPreview,
  useRegroupApply,
  type DeviceFilters,
  type DeviceCondition,
  type Device,
  type RegroupSelection,
  type RegroupPreview,
  type RegroupApplyEntry,
} from '../api/hooks'
import { usePermissions } from '../api/perms'
import { isApiError, isForbidden, isCentrallyHandled } from '../api/errors'
import { useToast } from '../components/Toast'
import { Dialog } from '../components/Dialog'
import { Card, Page, StateBlock, ErrorState, Button, Chip, cx } from '../components/ui'
import { JoinedVia } from '../components/provenance'

const RESERVED = ['control-plane', 'lighthouse']
const FIELD = 'w-full rounded-[6px] border border-edge bg-mesh-2 px-2 py-1.5 text-[13px] text-ink placeholder:text-ink-faint'

const CONDITION_LABEL: Record<DeviceCondition, string> = {
  expired: 'cert expired',
  expiring: 'cert expiring',
  stale: 'stale',
  clock_skewed: 'clock-skewed',
  unhealthy: 'unhealthy',
}

const FILTER_LABEL: Record<string, string> = {
  provider: 'provider',
  attest_account: 'account',
  join_key: 'join key',
  condition: 'condition',
}

export function Devices() {
  const { can } = usePermissions()
  const mayManage = can('device:manage')
  const [params, setParams] = useSearchParams()
  const filters: DeviceFilters = {
    provider: params.get('provider') ?? undefined,
    attest_account: params.get('attest_account') ?? undefined,
    join_key: params.get('join_key') ?? undefined,
    condition: (params.get('condition') as DeviceCondition | null) ?? undefined,
  }
  const activeFilters = Object.entries(filters).filter(([, v]) => v) as [string, string][]
  const q = useDevices(filters)
  const rows = q.data?.pages.flatMap((p) => p.devices) ?? []

  function setFilter(key: string, value: string) {
    const next = new URLSearchParams(params)
    next.set(key, value)
    setParams(next)
  }
  function clearFilter(key: string) {
    const next = new URLSearchParams(params)
    next.delete(key)
    setParams(next)
  }

  return (
    <Page
      title="Devices"
      subtitle="Hosts reporting in over the mesh — with how each one joined"
      actions={mayManage && <BulkRegroupButton pattern={params.get('name_pattern') ?? ''} />}
    >
      {activeFilters.length > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <span className="text-[12px] text-ink-faint">Filtered by</span>
          {activeFilters.map(([k, v]) => (
            <button
              key={k}
              onClick={() => clearFilter(k)}
              className="inline-flex items-center gap-1.5 rounded-full border border-edge bg-mesh-2 px-2.5 py-0.5 text-[12px] text-ink-dim hover:text-ink"
              title="Remove filter"
            >
              <span className="text-ink-faint">{FILTER_LABEL[k] ?? k}:</span>
              <span className="text-ink">{k === 'condition' ? CONDITION_LABEL[v as DeviceCondition] ?? v : v}</span>
              <span aria-hidden className="text-ink-faint">✕</span>
            </button>
          ))}
          <button onClick={() => setParams(new URLSearchParams())} className="text-[12px] text-ink-faint underline hover:text-ink-dim">
            clear all
          </button>
        </div>
      )}

      {q.isPending && <StateBlock kind="loading" message="Loading devices…" />}
      {q.isError && <ErrorState error={q.error} fallback="Couldn't load devices." />}
      {q.data &&
        (rows.length === 0 ? (
          <StateBlock kind="empty" message={activeFilters.length > 0 ? 'No devices match this filter.' : 'No devices yet.'} />
        ) : (
          <Card className="overflow-hidden">
            <table className="w-full text-left">
              <thead className="border-b border-edge text-[11px] uppercase tracking-wide text-ink-faint">
                <tr>
                  {['Overlay IP', 'Name', 'Joined via', 'Groups', 'Pilot', 'Cert expires', 'Health', 'Last seen'].map((h) => (
                    <th key={h} className="px-4 py-2 font-medium">{h}</th>
                  ))}
                  {mayManage && <th className="px-4 py-2 text-right font-medium">Actions</th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-edge">
                {rows.map((d) => (
                  <tr key={d.overlay_ip} className="hover:bg-mesh-2">
                    <td className="nums px-4 py-2 text-ink">{d.overlay_ip}</td>
                    <td className="px-4 py-2 text-ink">{d.name}</td>
                    <td className="px-4 py-2"><JoinedVia p={d} onFilter={setFilter} /></td>
                    <td className="px-4 py-2"><Groups d={d} /></td>
                    <td className="nums px-4 py-2 text-ink-dim">{d.pilot_version ?? '—'}</td>
                    <td className="nums px-4 py-2 text-ink-dim">{fmtDate(d.cert_not_after)}</td>
                    <td className={cx('px-4 py-2', healthTone(d.stale ? 'stale' : d.health))} title={d.stale && d.health ? `last reported "${d.health}" before going silent` : undefined}>{d.stale ? 'stale' : d.health ?? '—'}</td>
                    <td className="nums px-4 py-2 text-ink-faint">{fmtDate(d.last_seen)}</td>
                    {mayManage && (
                      <td className="px-4 py-2">
                        <div className="flex justify-end"><EditGroupsButton d={d} /></div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        ))}

      {q.hasNextPage && (
        <div className="mt-3 text-center">
          <Button onClick={() => q.fetchNextPage()} disabled={q.isFetchingNextPage}>
            {q.isFetchingNextPage ? 'Loading…' : 'Load more'}
          </Button>
        </div>
      )}
    </Page>
  )
}

function Groups({ d }: { d: Device }) {
  const groups = d.groups ?? []
  return (
    <span className="flex flex-wrap items-center gap-1">
      {groups.length === 0 ? <span className="text-ink-faint">—</span> : groups.map((g) => <Chip key={g}>{g}</Chip>)}
      {d.pending && (
        <span title={`pending re-issue → ${(d.desired_groups ?? []).join(', ') || 'none'} (applies on next heartbeat)`}>
          <Chip tone="warn">pending</Chip>
        </span>
      )}
      {d.reduction_pending_enforcement && (
        <span title="a removed group's old cert is still valid until it expires or is revoked (advisory)">
          <Chip tone="warn">advisory</Chip>
        </span>
      )}
    </span>
  )
}

// EditGroupsButton / EditGroupsDialog — single-device group reassignment (ADR 0002). Disabled
// for baseline-owned (control-plane/lighthouse) hosts, which the API also rejects.
function EditGroupsButton({ d }: { d: Device }) {
  const [open, setOpen] = useState(false)
  const reserved = (d.groups ?? []).some((g) => RESERVED.includes(g))
  return (
    <>
      <Button
        onClick={() => setOpen(true)}
        disabled={reserved}
        title={reserved ? 'Baseline-owned (control-plane / lighthouse) — not editable here' : undefined}
      >
        Edit groups
      </Button>
      {open && <EditGroupsDialog d={d} onClose={() => setOpen(false)} />}
    </>
  )
}

function EditGroupsDialog({ d, onClose }: { d: Device; onClose: () => void }) {
  const toast = useToast()
  const regroup = useDeviceRegroup()
  const [val, setVal] = useState((d.desired_groups ?? d.groups ?? []).join(', '))

  function submit() {
    const groups = val.split(',').map((g) => g.trim()).filter(Boolean)
    if (groups.some((g) => RESERVED.includes(g))) {
      toast.notify('control-plane / lighthouse are baseline-owned and cannot be assigned.', 'error')
      return
    }
    regroup.mutate(
      { ip: d.overlay_ip, groups },
      {
        onSuccess: () => {
          toast.notify(`Groups updated for ${d.name || d.overlay_ip} — applies on the host's next heartbeat.`, 'success')
          onClose()
        },
        onError: (err) => {
          if (isCentrallyHandled(err)) return
          if (isForbidden(err)) {
            toast.notify('You don’t have permission (device:manage).', 'error')
            return
          }
          toast.notify(isApiError(err) ? err.detail || err.title : 'Update failed.', 'error')
        },
      },
    )
  }

  return (
    <Dialog
      open
      onClose={onClose}
      title={`Edit groups — ${d.name || d.overlay_ip}`}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={regroup.isPending}>
            {regroup.isPending ? 'Saving…' : 'Save'}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <label className="block">
          <span className="mb-1 block text-[11px] uppercase tracking-wide text-ink-faint">Groups (comma-separated)</span>
          <input autoFocus value={val} onChange={(e) => setVal(e.target.value)} placeholder="laptops, prod" className={FIELD} />
        </label>
        <p className="text-[12px] text-ink-faint">
          Takes effect on the host’s next heartbeat-triggered renew (same overlay IP, hot-reload). Additions are
          effective on re-issue; <span className="text-warn">removals are advisory until the old cert is revoked</span>.
          control-plane / lighthouse can’t be assigned here.
        </p>
      </div>
    </Dialog>
  )
}

// --- Bulk re-group (ADR 0013): name-pattern select → dry-run preview → guarded apply ---

const SKIP_LABEL: Record<string, string> = {
  reserved: 'baseline-owned',
  stale: 'stale (not reporting)',
  ephemeral: 'ephemeral',
  reaped: 'reaped',
  no_op: 'already matches',
}

type DeltaMode = 'add' | 'remove' | 'replace'

function BulkRegroupButton({ pattern }: { pattern: string }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <Button variant="primary" onClick={() => setOpen(true)}>Re-group…</Button>
      {open && <BulkRegroupDialog initialPattern={pattern} onClose={() => setOpen(false)} />}
    </>
  )
}

function BulkRegroupDialog({ initialPattern, onClose }: { initialPattern: string; onClose: () => void }) {
  const toast = useToast()
  const preview = useRegroupPreview()
  const apply = useRegroupApply()
  const [pattern, setPattern] = useState(initialPattern)
  const [mode, setMode] = useState<DeltaMode>('add')
  const [groupsText, setGroupsText] = useState('')
  const [includeStale, setIncludeStale] = useState(false)
  const [result, setResult] = useState<RegroupPreview | null>(null)

  const groups = groupsText.split(',').map((g) => g.trim()).filter(Boolean)
  // editing any input invalidates a stale preview — the displayed targets must match what Apply sends.
  const reset = () => setResult(null)

  function runPreview() {
    if (!pattern.trim()) return toast.notify('Enter a device-name pattern (e.g. db-*).', 'error')
    if (groups.length === 0) return toast.notify('Enter at least one group.', 'error')
    if (groups.some((g) => RESERVED.includes(g)))
      return toast.notify('control-plane / lighthouse are baseline-owned and cannot be assigned.', 'error')
    const sel: RegroupSelection = { name_pattern: pattern.trim(), include_stale: includeStale }
    if (mode === 'add') sel.add = groups
    else if (mode === 'remove') sel.remove = groups
    else sel.replace = groups
    preview.mutate(sel, {
      onSuccess: setResult,
      onError: (err) => {
        if (isCentrallyHandled(err)) return
        toast.notify(isApiError(err) ? err.detail || err.title : 'Preview failed.', 'error')
      },
    })
  }

  function runApply() {
    if (!result || result.entries.length === 0) return
    const entries: RegroupApplyEntry[] = result.entries.map((e) => ({
      overlay_ip: e.overlay_ip,
      enrollment_id: e.enrollment_id,
      base_generation: e.base_generation,
      target: e.target,
    }))
    apply.mutate(entries, {
      onSuccess: (res) => {
        if (res.routed) {
          toast.notify(`Routed ${entries.length} device(s) to a second approver (change #${res.change.id}).`, 'success')
        } else {
          const applied = res.results.filter((r) => r.status === 'applied').length
          const skipped = res.results.length - applied
          toast.notify(
            `Re-grouped ${applied} device(s)${skipped ? `, ${skipped} skipped (changed since preview)` : ''} — applies on each host's next heartbeat.`,
            'success',
          )
        }
        onClose()
      },
      onError: (err) => {
        if (isCentrallyHandled(err)) return
        if (isForbidden(err)) return toast.notify('You don’t have permission (device:manage).', 'error')
        toast.notify(isApiError(err) ? err.detail || err.title : 'Apply failed.', 'error')
      },
    })
  }

  const nEntries = result?.entries.length ?? 0
  const applyLabel = apply.isPending
    ? 'Applying…'
    : result?.requires_dual_control
      ? `Submit ${nEntries} for approval`
      : `Apply to ${nEntries} device${nEntries === 1 ? '' : 's'}`

  return (
    <Dialog
      open
      onClose={onClose}
      title="Re-group devices"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          {result ? (
            <Button variant="primary" onClick={runApply} disabled={apply.isPending || nEntries === 0}>
              {applyLabel}
            </Button>
          ) : (
            <Button variant="primary" onClick={runPreview} disabled={preview.isPending}>
              {preview.isPending ? 'Previewing…' : 'Preview'}
            </Button>
          )}
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <label className="block">
          <span className="mb-1 block text-[11px] uppercase tracking-wide text-ink-faint">Device-name pattern</span>
          <input
            autoFocus
            value={pattern}
            onChange={(e) => { setPattern(e.target.value); reset() }}
            placeholder="db-*  (use * and ? wildcards)"
            className={FIELD}
          />
        </label>

        <div className="flex gap-1">
          {(['add', 'remove', 'replace'] as DeltaMode[]).map((m) => (
            <button
              key={m}
              onClick={() => { setMode(m); reset() }}
              className={cx(
                'flex-1 rounded-[6px] border px-2 py-1 text-[12px] capitalize transition-colors',
                mode === m ? 'border-permit/60 bg-permit/15 text-permit' : 'border-edge text-ink-dim hover:text-ink',
              )}
            >
              {m === 'replace' ? 'replace with' : m}
            </button>
          ))}
        </div>

        <label className="block">
          <span className="mb-1 block text-[11px] uppercase tracking-wide text-ink-faint">Groups (comma-separated)</span>
          <input
            value={groupsText}
            onChange={(e) => { setGroupsText(e.target.value); reset() }}
            placeholder="prod, db"
            className={FIELD}
          />
        </label>

        <label className="flex items-center gap-2 text-[12px] text-ink-dim">
          <input type="checkbox" checked={includeStale} onChange={(e) => { setIncludeStale(e.target.checked); reset() }} />
          Include stale (not-reporting) hosts
        </label>

        {result && <RegroupResultPanel result={result} />}

        <p className="text-[12px] text-ink-faint">
          Each change is an absolute set, applied on the host’s next heartbeat-triggered renew. Additions take effect on
          re-issue; <span className="text-warn">removals are advisory until the old cert expires or is revoked</span>.
          Elevating or large (&gt;25) changes route to a second approver.
        </p>
      </div>
    </Dialog>
  )
}

function RegroupResultPanel({ result }: { result: RegroupPreview }) {
  const { entries, skipped, capped, requires_dual_control } = result
  // collapse skips to "reason × n" for a compact summary
  const skipCounts = skipped.reduce<Record<string, number>>((acc, s) => {
    acc[s.reason] = (acc[s.reason] ?? 0) + 1
    return acc
  }, {})

  return (
    <div className="flex flex-col gap-2 rounded-md border border-edge bg-mesh-2 p-2.5">
      {entries.length === 0 ? (
        <p className="text-[13px] text-ink-dim">No devices would change.</p>
      ) : (
        <>
          <div className="flex items-center justify-between">
            <span className="text-[12px] text-ink-dim">{entries.length} device{entries.length === 1 ? '' : 's'} will change</span>
            {requires_dual_control && <Chip tone="warn">needs a second approver</Chip>}
          </div>
          <div className="max-h-48 divide-y divide-edge overflow-y-auto rounded border border-edge">
            {entries.map((e) => (
              <div key={e.overlay_ip} className="px-2 py-1.5">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="truncate text-[12px] text-ink">{e.name || e.overlay_ip}</span>
                  <span className="nums shrink-0 text-[11px] text-ink-faint">{e.overlay_ip}</span>
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-1 text-[11px]">
                  {(e.from.length ? e.from : ['—']).map((g, i) => <Chip key={`f${i}`}>{g}</Chip>)}
                  <span className="text-ink-faint">→</span>
                  {(e.target.length ? e.target : ['—']).map((g, i) => (
                    <Chip key={`t${i}`} tone={!e.from.includes(g) ? 'permit' : 'default'}>{g}</Chip>
                  ))}
                  {e.elevates && <Chip tone="warn">elevates</Chip>}
                  {e.will_reduce && <Chip tone="warn">reduces</Chip>}
                </div>
              </div>
            ))}
          </div>
        </>
      )}
      {capped > 0 && (
        <p className="text-[12px] text-warn">{capped} more matched but exceed the cap of 100 — narrow the pattern.</p>
      )}
      {Object.keys(skipCounts).length > 0 && (
        <p className="text-[12px] text-ink-faint">
          Skipped: {Object.entries(skipCounts).map(([r, n]) => `${n} ${SKIP_LABEL[r] ?? r}`).join(', ')}
        </p>
      )}
    </div>
  )
}

function healthTone(h?: string): string {
  if (h === 'ok' || h === 'healthy') return 'text-permit'
  if (h === 'stale' || h === 'degraded') return 'text-warn'
  if (h) return 'text-danger'
  return 'text-ink-faint'
}

function fmtDate(iso?: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString()
}
