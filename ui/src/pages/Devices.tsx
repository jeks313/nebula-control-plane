import { useSearchParams } from 'react-router-dom'
import { useDevices, type Device, type DeviceFilters, type DeviceCondition } from '../api/hooks'
import { Card, Page, StateBlock, ErrorState, Button, Chip, cx } from '../components/ui'

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
                </tr>
              </thead>
              <tbody className="divide-y divide-edge">
                {rows.map((d) => (
                  <tr key={d.overlay_ip} className="hover:bg-mesh-2">
                    <td className="nums px-4 py-2 text-ink">{d.overlay_ip}</td>
                    <td className="px-4 py-2 text-ink">{d.name}</td>
                    <td className="px-4 py-2"><Provenance d={d} onFilter={setFilter} /></td>
                    <td className="px-4 py-2"><Groups groups={d.groups} /></td>
                    <td className="nums px-4 py-2 text-ink-dim">{d.pilot_version ?? '—'}</td>
                    <td className="nums px-4 py-2 text-ink-dim">{fmtDate(d.cert_not_after)}</td>
                    <td className={cx('px-4 py-2', healthTone(d.health))}>{d.health ?? '—'}</td>
                    <td className="nums px-4 py-2 text-ink-faint">{fmtDate(d.last_seen)}</td>
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

// Provenance — how the host joined. Cloud-attested hosts show provider + account
// (+ region); token hosts show their join-key name. Each is clickable to filter the
// list down to that scope (server-side).
function Provenance({ d, onFilter }: { d: Device; onFilter: (k: string, v: string) => void }) {
  if (d.attest_provider) {
    return (
      <span className="flex flex-col gap-0.5">
        <span className="flex items-center gap-1.5">
          <button onClick={() => onFilter('provider', d.attest_provider!)} title="Filter by provider">
            <Chip tone="permit">{attestLabel(d.attest_provider)}</Chip>
          </button>
          {d.attest_account && (
            <button
              onClick={() => onFilter('attest_account', d.attest_account!)}
              className="nums font-mono text-[11px] text-ink-dim hover:text-ink"
              title={d.attest_principal ? `${d.attest_principal} — filter by account` : 'Filter by account'}
            >
              {d.attest_account}
            </button>
          )}
        </span>
        {d.attest_region && <span className="text-[11px] text-ink-faint">{d.attest_region}</span>}
      </span>
    )
  }
  if (d.join_key_name) {
    return (
      <span className="flex items-center gap-1.5">
        <span className="text-[11px] text-ink-faint">token</span>
        <button onClick={() => onFilter('join_key', d.join_key_name!)} title="Filter by join key">
          <Chip>{d.join_key_name}</Chip>
        </button>
      </span>
    )
  }
  return <span className="text-ink-faint">—</span>
}

function Groups({ groups }: { groups?: string[] }) {
  if (!groups || groups.length === 0) return <span className="text-ink-faint">—</span>
  return (
    <span className="flex flex-wrap gap-1">
      {groups.map((g) => (
        <Chip key={g}>{g}</Chip>
      ))}
    </span>
  )
}

function attestLabel(provider?: string): string {
  if (provider === 'aws') return 'AWS'
  if (provider === 'azure') return 'Azure'
  if (provider === 'gcp') return 'GCP'
  return provider || 'attested'
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
