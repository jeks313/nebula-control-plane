import { Link } from 'react-router-dom'
import { useFleetHealth, type FleetHealth } from '../api/hooks'
import { Card, Page, StateBlock, ErrorState, cx } from '../components/ui'
import {
  Masthead,
  ActiveOps,
  ConvergenceCard,
  RenewalCliffCard,
  VersionLandscapeCard,
  TrustIntegrityCard,
  LighthousesCard,
  GatewaysCard,
  IPAMHealthCard,
  RecentReapsCard,
  RecentActivityCard,
} from '../components/fleet'

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
      <Masthead />
      {q.isLoading && <StateBlock kind="loading" message="Loading fleet health…" />}
      {q.isError && (
        <ErrorState error={q.error} fallback="Couldn't reach Core — the mesh may be down (see the break-glass runbook)." />
      )}
      {q.data && <HealthVerdict h={q.data} />}

      <ActiveOps />

      {/* The focused cards — every tile is backed by real data (§3.3). */}
      <div className="mt-5 grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
        <ConvergenceCard />
        <RenewalCliffCard />
        <VersionLandscapeCard />
        <TrustIntegrityCard />
        <LighthousesCard />
        <GatewaysCard />
        <IPAMHealthCard />
        <RecentReapsCard />
        <RecentActivityCard />
      </div>
    </Page>
  )
}

// HealthVerdict — the 3-second answer: one big status chip + severity-ordered reasons.
function HealthVerdict({ h }: { h: FleetHealth }) {
  const s = STATUS[h.status]
  return (
    <div className="flex flex-col gap-4">
      <Card className="mesh-grid overflow-hidden">
        <div className="flex items-center justify-between gap-6 p-6">
          <div className="flex items-center gap-3">
            <span className={cx('inline-block h-3 w-3 rounded-full', s.dot)} aria-hidden />
            <div>
              <div className={cx('text-[24px] font-semibold tracking-[-0.02em]', s.text)}>{s.label}</div>
              <div className="text-ink-dim">
                <span className="nums text-ink">{h.totals.total}</span> hosts in the fleet
              </div>
            </div>
          </div>
        </div>
      </Card>

      {h.reasons.length > 0 && (
        <Card>
          <div className="border-b border-edge px-4 py-2 text-[12px] text-ink-faint">Why</div>
          <ul className="divide-y divide-edge">
            {h.reasons.map((r) => {
              const inner = (
                <>
                  <span className={cx('nums w-8 text-right', SEV_TEXT[r.severity] ?? 'text-ink-dim')}>{r.count}</span>
                  <span className="text-ink">{r.detail}</span>
                  <span className="ml-auto font-mono text-[11px] text-ink-faint">{r.code}</span>
                  {r.link && <span aria-hidden className="text-ink-faint">›</span>}
                </>
              )
              return (
                <li key={r.code}>
                  {r.link ? (
                    <Link to={r.link} className="flex items-center gap-3 px-4 py-2.5 transition-colors hover:bg-mesh-2" title="View affected hosts">
                      {inner}
                    </Link>
                  ) : (
                    <div className="flex items-center gap-3 px-4 py-2.5">{inner}</div>
                  )}
                </li>
              )
            })}
          </ul>
        </Card>
      )}
    </div>
  )
}
