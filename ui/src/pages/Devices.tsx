import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useDevices, useDeviceRegroup, type DeviceFilters, type DeviceCondition, type Device } from '../api/hooks'
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
    <Page title="Devices" subtitle="Hosts reporting in over the mesh — with how each one joined">
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
