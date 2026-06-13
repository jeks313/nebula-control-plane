import { useFleetHealth, type FleetHealth } from '../api/hooks'
import { Card, Page, StateBlock, ErrorState, cx } from '../components/ui'

const STATUS: Record<FleetHealth['status'], { label: string; dot: string; text: string }> = {
  healthy: { label: 'Healthy', dot: 'bg-permit', text: 'text-permit' },
  degraded: { label: 'Degraded', dot: 'bg-warn', text: 'text-warn' },
  critical: { label: 'Critical', dot: 'bg-danger', text: 'text-danger' },
}

const SEV_TEXT: Record<string, string> = {
  info: 'text-ink-dim',
  degraded: 'text-warn',
  critical: 'text-danger',
}

export function Dashboard() {
  const q = useFleetHealth()

  return (
    <Page title="Fleet" subtitle="Server-computed health for the whole mesh">
      {q.isLoading && <StateBlock kind="loading" message="Loading fleet health…" />}
      {q.isError && <ErrorState error={q.error} fallback="Couldn't reach Core — the mesh may be down (see the break-glass runbook)." />}
      {q.data && <Rollup h={q.data} />}
    </Page>
  )
}

function Rollup({ h }: { h: FleetHealth }) {
  const s = STATUS[h.status]
  const t = h.totals
  return (
    <div className="flex flex-col gap-4">
      {/* Hero: the one status answer, not a wall of gauges (§3.2). */}
      <Card className="mesh-grid overflow-hidden">
        <div className="flex items-center justify-between gap-6 p-6">
          <div className="flex items-center gap-3">
            <span className={cx('inline-block h-3 w-3 rounded-full', s.dot)} aria-hidden />
            <div>
              <div className={cx('text-[24px] font-semibold tracking-[-0.02em]', s.text)}>{s.label}</div>
              <div className="text-ink-dim">
                <span className="nums text-ink">{t.total}</span> hosts in the fleet
              </div>
            </div>
          </div>
        </div>
      </Card>

      {/* Totals — tabular, domain-named, drilldown-ready later. */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <Metric label="Total" value={t.total} />
        <Metric label="Expiring" value={t.expiring} tone={t.expiring > 0 ? 'warn' : undefined} />
        <Metric label="Expired" value={t.expired} tone={t.expired > 0 ? 'danger' : undefined} />
        <Metric label="Stale" value={t.stale} tone={t.stale > 0 ? 'warn' : undefined} />
        <Metric label="Clock-skewed" value={t.clock_skewed} tone={t.clock_skewed > 0 ? 'warn' : undefined} />
      </div>

      {/* Reasons — why the status is what it is (provenance by default). */}
      <Card>
        <div className="border-b border-edge px-4 py-2 text-[12px] text-ink-faint">Why</div>
        {h.reasons.length === 0 ? (
          <div className="px-4 py-6 text-center text-ink-faint">Nothing needs attention.</div>
        ) : (
          <ul className="divide-y divide-edge">
            {h.reasons.map((r) => (
              <li key={r.code} className="flex items-center gap-3 px-4 py-2.5">
                <span className={cx('nums w-8 text-right', SEV_TEXT[r.severity] ?? 'text-ink-dim')}>{r.count}</span>
                <span className="text-ink">{r.detail}</span>
                <span className="ml-auto font-mono text-[11px] text-ink-faint">{r.code}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  )
}

function Metric({ label, value, tone }: { label: string; value: number; tone?: 'warn' | 'danger' }) {
  const text = tone === 'danger' ? 'text-danger' : tone === 'warn' ? 'text-warn' : 'text-ink'
  return (
    <Card className="px-4 py-3">
      <div className="text-[11px] uppercase tracking-wide text-ink-faint">{label}</div>
      <div className={cx('nums mt-1 text-[22px]', text)}>{value}</div>
    </Card>
  )
}
