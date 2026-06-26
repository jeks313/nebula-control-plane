import type { ReactNode } from 'react'
import {
  useFleetHealth,
  useDevices,
  useAudit,
  useLighthouses,
  useAuditVerify,
  useCurrentRollout,
  useApprovals,
  useActivePolicy,
  useNetblocks,
  type Netblock,
} from '../api/hooks'
import { Card, StateBlock, ErrorState, Chip, cx } from './ui'
import { fmtDateTime } from '../lib/format'
import { utilizationTone } from '../lib/ipam'
import {
  versionCounts,
  expiryBuckets,
  soonestExpiring,
  convergence,
  laggingHosts,
  targetBundleVersion,
  totalWaves,
} from '../lib/fleet'

// A titled dashboard card with a uniform header.
function Tile({ title, hint, children }: { title: string; hint?: string; children: ReactNode }) {
  return (
    <Card className="flex flex-col overflow-hidden">
      <div className="flex items-baseline justify-between border-b border-edge px-4 py-2">
        <span className="text-[12px] font-medium text-ink">{title}</span>
        {hint && <span className="text-[11px] text-ink-faint">{hint}</span>}
      </div>
      <div className="flex-1 px-4 py-3">{children}</div>
    </Card>
  )
}

// A horizontal proportion bar (no chart lib — borders-first, §5).
function Bar({ pct, tone = 'permit' }: { pct: number; tone?: 'permit' | 'warn' | 'danger' }) {
  const bg = tone === 'danger' ? 'bg-danger' : tone === 'warn' ? 'bg-warn' : 'bg-permit'
  return (
    <div className="h-2 w-full overflow-hidden rounded-full bg-mesh-2">
      <div className={cx('h-full rounded-full', bg)} style={{ width: `${Math.max(0, Math.min(100, pct))}%` }} />
    </div>
  )
}

// Masthead — the plain-language fleet sentence (§3.1/§3.3). No region count: the
// backend has no region field, so we state what we actually know.
export function Masthead() {
  const health = useFleetHealth()
  const policy = useActivePolicy()
  const h = health.data
  if (!h) return null
  const total = h.totals.total
  const statusWord =
    h.status === 'healthy' ? 'all healthy' : h.status === 'degraded' ? 'running degraded' : 'in a critical state'
  const audit = h.audit_ok ? 'audit chain verified' : 'audit chain needs attention'
  const pol = policy.data?.published ? `policy published (v${policy.data.version})` : 'no policy published yet'
  return (
    <p className="mb-5 text-[15px] text-ink-dim">
      <span className="nums font-semibold text-ink">{total}</span> {total === 1 ? 'host' : 'hosts'} in the mesh — {statusWord},{' '}
      {audit}, {pol}.
    </p>
  )
}

// Active-operations strip — lights up only when a rollout is in flight / rolled back, or
// approvals are pending; collapses when idle (§3.3 #3).
export function ActiveOps() {
  const rollout = useCurrentRollout()
  const approvals = useApprovals('pending')
  const r = rollout.data
  const pending = approvals.data?.approvals ?? []
  const rolledBack = r?.rollout?.state === 'rolledback'
  const active = Boolean(r?.active && r.rollout)
  if (!active && !rolledBack && pending.length === 0) return null

  return (
    <Card className="mb-5 flex flex-col gap-2 px-4 py-3">
      {rolledBack && r?.rollout && (
        <div className="flex items-center gap-2 text-[13px] text-danger">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-danger" aria-hidden />
          {r.rollout.prev_version > 0
            ? `Rollout auto-rolled-back — fleet frozen on bundle v${r.rollout.prev_version}.`
            : 'Rollout auto-rolled-back — no prior version; fleet frozen on its baseline.'}
        </div>
      )}
      {active && r?.rollout && (
        <div className="flex items-center gap-2 text-[13px] text-ink">
          <span className="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-permit" aria-hidden />
          Rollout to bundle v{r.rollout.target_version} — {r.rollout.state}, wave{' '}
          <span className="nums">{r.rollout.active_wave + 1}</span>/<span className="nums">{totalWaves(r.hosts)}</span> converging.
        </div>
      )}
      {pending.map((p) => (
        <div key={p.id} className="flex items-center gap-2 text-[13px] text-warn">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-warn" aria-hidden />
          Awaiting approval: <span className="font-mono text-[12px]">{p.kind}</span>
          {p.target ? ` ${p.target}` : ''} — {p.quorum}-person, requested {fmtDateTime(p.created_at)}.
        </div>
      ))}
    </Card>
  )
}

// Convergence gauge (§3.3 #6) — % of fleet on the target bundle version.
export function ConvergenceCard() {
  const devices = useDevices()
  const rollout = useCurrentRollout()
  return (
    <Tile title="Fleet convergence" hint={truncatedHint(devices.data?.pages[0]?.next_after)}>
      {devices.isPending && <StateBlock kind="loading" message="…" />}
      {devices.isError && <ErrorState error={devices.error} fallback="Couldn't load devices." />}
      {devices.data &&
        (() => {
          const ds = devices.data.pages[0].devices
          if (ds.length === 0) return <StateBlock kind="empty" message="No hosts reporting yet." />
          const target = targetBundleVersion(ds, rollout.data?.active ? rollout.data.rollout?.target_version : undefined)
          const c = convergence(ds, target)
          const tone = c.pct >= 100 ? 'permit' : c.pct >= 80 ? 'warn' : 'danger'
          return (
            <div className="flex flex-col gap-2">
              <div className="flex items-baseline justify-between">
                <span className={cx('nums text-[24px] font-semibold', tone === 'permit' ? 'text-permit' : tone === 'warn' ? 'text-warn' : 'text-danger')}>
                  {c.pct}%
                </span>
                <span className="text-[12px] text-ink-dim">on bundle v{c.target}</span>
              </div>
              <Bar pct={c.pct} tone={tone} />
              <div className="text-[12px] text-ink-faint">
                <span className="nums">{c.onTarget}</span>/<span className="nums">{c.total}</span> converged
                {c.lagging > 0 && <> · <span className="nums text-warn">{c.lagging}</span> lagging</>}
              </div>
              {c.lagging > 0 && (
                <ul className="divide-y divide-edge border-t border-edge text-[12px]" aria-label="Lagging hosts">
                  {laggingHosts(ds, target)
                    .slice(0, 8)
                    .map((d) => (
                      <li key={d.overlay_ip} className="flex items-center justify-between gap-2 py-1.5">
                        <span className="truncate text-ink" title={d.overlay_ip}>{d.name || d.overlay_ip}</span>
                        <span className="nums shrink-0 text-warn" title={`on bundle v${d.applied_bundle_version}, target v${c.target}`}>
                          v{d.applied_bundle_version}
                        </span>
                      </li>
                    ))}
                  {c.lagging > 8 && <li className="py-1.5 text-ink-faint">+{c.lagging - 8} more lagging</li>}
                </ul>
              )}
            </div>
          )
        })()}
    </Tile>
  )
}

// Renewal cliff (§3.3 #5a) — cert-expiry outlook + soonest. Read-only: there is no
// force-renew endpoint yet (the agent renews itself), so this is the outage-budget view.
export function RenewalCliffCard() {
  const devices = useDevices()
  return (
    <Tile title="Renewal cliff" hint={truncatedHint(devices.data?.pages[0]?.next_after)}>
      {devices.isPending && <StateBlock kind="loading" message="…" />}
      {devices.isError && <ErrorState error={devices.error} fallback="Couldn't load devices." />}
      {devices.data &&
        (() => {
          const ds = devices.data.pages[0].devices
          if (ds.length === 0) return <StateBlock kind="empty" message="No certs to track yet." />
          const b = expiryBuckets(ds, Date.now())
          const soon = soonestExpiring(ds, 5)
          return (
            <div className="flex flex-col gap-3">
              <div className="grid grid-cols-3 gap-2 text-center">
                <Stat label="Expired" value={b.expired} tone={b.expired > 0 ? 'danger' : undefined} />
                <Stat label="≤ 30 days" value={b.soon} tone={b.soon > 0 ? 'warn' : undefined} />
                <Stat label="Later" value={b.later} />
              </div>
              {soon.length > 0 && (
                <ul className="divide-y divide-edge border-t border-edge text-[12px]">
                  {soon.map((s) => (
                    <li key={s.device.overlay_ip} className="flex items-center justify-between py-1.5">
                      <span className="text-ink">{s.device.name}</span>
                      <span className={cx('nums', s.expiresMs < Date.now() ? 'text-danger' : 'text-ink-dim')}>
                        {fmtDateTime(s.device.cert_not_after)}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )
        })()}
    </Tile>
  )
}

// Version landscape — pilot + nebula version distribution across the fleet.
export function VersionLandscapeCard() {
  const devices = useDevices()
  return (
    <Tile title="Version landscape" hint={truncatedHint(devices.data?.pages[0]?.next_after)}>
      {devices.isPending && <StateBlock kind="loading" message="…" />}
      {devices.isError && <ErrorState error={devices.error} fallback="Couldn't load devices." />}
      {devices.data &&
        (() => {
          const ds = devices.data.pages[0].devices
          if (ds.length === 0) return <StateBlock kind="empty" message="No hosts reporting yet." />
          return (
            <div className="flex flex-col gap-4">
              <VersionGroup label="Pilot" items={versionCounts(ds, (d) => d.pilot_version)} total={ds.length} />
              <VersionGroup label="Nebula" items={versionCounts(ds, (d) => d.nebula_version)} total={ds.length} />
            </div>
          )
        })()}
    </Tile>
  )
}

function VersionGroup({ label, items, total }: { label: string; items: { version: string; count: number }[]; total: number }) {
  return (
    <div>
      <div className="mb-1.5 text-[11px] uppercase tracking-wide text-ink-faint">{label}</div>
      <div className="flex flex-col gap-1.5">
        {items.map((v) => (
          <div key={v.version} className="flex items-center gap-2">
            <span className="w-28 shrink-0 truncate font-mono text-[11px] text-ink-dim" title={v.version}>{v.version}</span>
            <div className="flex-1"><Bar pct={total ? (v.count / total) * 100 : 0} tone="permit" /></div>
            <span className="nums w-8 text-right text-[11px] text-ink-dim">{v.count}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// Trust integrity (§3.3 #5c) — audit-chain verification, honestly labeled. Drift
// sparkline + genesis tile are omitted: no backend data for them yet.
export function TrustIntegrityCard() {
  const v = useAuditVerify()
  return (
    <Tile title="Trust integrity">
      {v.isPending && <StateBlock kind="loading" message="Verifying audit chain…" />}
      {v.isError && (
        <div className="text-[13px] text-warn">Audit verification unavailable — couldn’t run the check.</div>
      )}
      {v.data &&
        (v.data.status === 'verified' ? (
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-2 text-[13px] text-permit">
              <span className="inline-block h-2 w-2 rounded-full bg-permit" aria-hidden />
              Audit chain verified
            </div>
            <div className="text-[12px] text-ink-faint">
              <span className="nums">{v.data.verified_rows}</span> rows · {v.data.scope}
            </div>
          </div>
        ) : (
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-2 text-[13px] text-danger">
              <span className="inline-block h-2 w-2 rounded-full bg-danger" aria-hidden />
              Audit chain TAMPERED
            </div>
            <div className="text-[12px] text-ink-dim">{v.data.detail || 'integrity check failed'}</div>
          </div>
        ))}
    </Tile>
  )
}

// Lighthouses — the static registry, honestly labeled. Liveness/cert-expiry land when
// lighthouses heartbeat (no backend data today).
export function LighthousesCard() {
  const q = useLighthouses()
  const active = (q.data?.lighthouses ?? []).filter((l) => l.state === 'active')
  return (
    <Tile title="Lighthouses" hint="registry — liveness lands when lighthouses heartbeat">
      {q.isPending && <StateBlock kind="loading" message="…" />}
      {q.isError && <ErrorState error={q.error} fallback="Couldn't load lighthouses." />}
      {q.data &&
        (active.length === 0 ? (
          <StateBlock kind="empty" message="No lighthouses registered." />
        ) : (
          <ul className="flex flex-col gap-1.5 text-[12px]">
            {active.map((l) => (
              <li key={l.overlay_ip} className="flex items-center justify-between">
                <span className="nums font-mono text-ink">{l.overlay_ip}</span>
                <span className="text-ink-faint">{l.hostname || l.public_addrs[0] || '—'}</span>
              </li>
            ))}
          </ul>
        ))}
    </Tile>
  )
}

// Recent activity (§3.3 #7) — the latest audit highlights.
export function RecentActivityCard() {
  const q = useAudit()
  const rows = (q.data?.entries ?? []).slice(0, 6)
  return (
    <Tile title="Recent activity">
      {q.isPending && <StateBlock kind="loading" message="…" />}
      {q.isError && <ErrorState error={q.error} fallback="Couldn't load the audit log." />}
      {q.data &&
        (rows.length === 0 ? (
          <StateBlock kind="empty" message="No activity yet." />
        ) : (
          <ul className="flex flex-col gap-1.5 text-[12px]">
            {rows.map((e) => (
              <li key={e.seq} className="flex items-center gap-2">
                <span className="font-mono text-permit">{e.action}</span>
                <span className="truncate text-ink-dim">{e.target ?? ''}</span>
                <span className="ml-auto shrink-0 text-ink-faint">{e.actor}</span>
              </li>
            ))}
          </ul>
        ))}
    </Tile>
  )
}

// IPAM health (ADR 0010) — per-netblock utilization on the UTILIZATION axis (distinct
// from the create-overlay's growth-headroom colors): red > 90%, yellow > 75% on the
// allocated %, with the live used % shown alongside so high-allocated-low-used reads as
// "reclaim" and high-both as "grow". Over-threshold blocks are listed; healthy ones are
// summarized. Recent auto-grows / exhaustions are pulled from the audit log (the API has
// no dedicated grows/exhaustion endpoint — those are audit + Prometheus per the ADR, so
// we surface the audit side here and note the gap).
export function IPAMHealthCard() {
  const q = useNetblocks()
  const audit = useAudit()
  const blocks = q.data?.netblocks ?? []
  // Hot = over the yellow threshold (allocated > 75%), worst first.
  const hot = [...blocks].filter((b) => b.pct > 75).sort((a, b) => b.pct - a.pct)
  const events = (audit.data?.entries ?? [])
    .filter((e) => e.action === 'netblock-autogrow' || e.action === 'netblock-exhausted')
    .slice(0, 4)

  return (
    <Tile title="IPAM health" hint="utilization · grows/exhaustion from audit">
      {q.isPending && <StateBlock kind="loading" message="…" />}
      {q.isError && <ErrorState error={q.error} fallback="Couldn't load netblocks." />}
      {q.data &&
        (blocks.length === 0 ? (
          <StateBlock kind="empty" message="No netblocks carved yet." />
        ) : (
          <div className="flex flex-col gap-3">
            {hot.length === 0 ? (
              <div className="flex items-center gap-2 text-[13px] text-permit">
                <span className="inline-block h-2 w-2 rounded-full bg-permit" aria-hidden />
                All {blocks.length} netblock{blocks.length === 1 ? '' : 's'} under 75% allocated.
              </div>
            ) : (
              <ul className="flex flex-col gap-2">
                {hot.map((b) => (
                  <NetblockHealthRow key={b.name} b={b} />
                ))}
              </ul>
            )}
            {events.length > 0 && (
              <div className="border-t border-edge pt-2">
                <div className="mb-1.5 text-[11px] uppercase tracking-wide text-ink-faint">Recent grows / exhaustion</div>
                <ul className="flex flex-col gap-1 text-[12px]">
                  {events.map((e) => (
                    <li key={e.seq} className="flex items-center gap-2">
                      {e.action === 'netblock-exhausted' ? (
                        <Chip tone="danger">exhausted</Chip>
                      ) : (
                        <Chip tone="warn">auto-grow</Chip>
                      )}
                      <span className="truncate font-mono text-ink-dim">{e.target ?? ''}</span>
                      <span className="ml-auto shrink-0 text-ink-faint">{fmtDateTime(e.ts)}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        ))}
    </Tile>
  )
}

// Recent reaps (impl 2.12) — the device reaper turns passive cert-expiry into active
// reclamation: on a schedule it reclaims a gone host's overlay IP, prunes its stale
// heartbeat, and soft-marks the device. Because the reaped host's heartbeat is DELETED,
// it drops out of the heartbeat-driven Devices/fleet list — so the natural surface is the
// audit log, exactly like the IPAM "recent grows / exhaustion" panel above. We filter the
// shared audit feed for the reaper's per-reap action ('reaper-reap') and show host, reason
// (cert-expired | silent), whether the cert was revoked, and when. The reaper writes the
// detail as JSON {overlay_ip, reason, ip_reclaimed, revoked}; we parse it best-effort.
type reapDetail = { overlay_ip?: string; reason?: string; revoked?: boolean }

function parseReapDetail(details?: string): reapDetail {
  if (!details) return {}
  try {
    const d = JSON.parse(details) as reapDetail
    return d && typeof d === 'object' ? d : {}
  } catch {
    return {}
  }
}

export function RecentReapsCard() {
  const audit = useAudit()
  const reaps = (audit.data?.entries ?? []).filter((e) => e.action === 'reaper-reap').slice(0, 5)
  return (
    <Tile title="Recent reaps" hint="reclaimed hosts — from audit">
      {audit.isPending && <StateBlock kind="loading" message="…" />}
      {audit.isError && <ErrorState error={audit.error} fallback="Couldn't load the audit log." />}
      {audit.data &&
        (reaps.length === 0 ? (
          <StateBlock kind="empty" message="No hosts reaped recently." />
        ) : (
          <ul className="flex flex-col gap-1.5 text-[12px]">
            {reaps.map((e) => {
              const d = parseReapDetail(e.details)
              return (
                <li key={e.seq} className="flex items-center gap-2">
                  {d.reason === 'silent' ? <Chip tone="warn">silent</Chip> : <Chip tone="danger">cert-expired</Chip>}
                  <span className="truncate font-mono text-ink-dim" title={e.target ?? ''}>
                    {d.overlay_ip || e.target || '—'}
                  </span>
                  {d.revoked && <Chip tone="danger">revoked</Chip>}
                  <span className="ml-auto shrink-0 text-ink-faint">{fmtDateTime(e.ts)}</span>
                </li>
              )
            })}
          </ul>
        ))}
    </Tile>
  )
}

function NetblockHealthRow({ b }: { b: Netblock }) {
  const tone = utilizationTone(b.pct)
  // used % keys off the live count vs capacity. `used` is now wired (D23): the backend
  // counts allocations whose host heartbeats within the fleet stale window (StaleAfter),
  // so this is heartbeat-confirmed live utilization, not a placeholder.
  const usedPct = b.capacity > 0 ? (b.used / b.capacity) * 100 : 0
  return (
    <li className="flex flex-col gap-1">
      <div className="flex items-baseline justify-between text-[12px]">
        <span className="font-mono text-ink">{b.name}</span>
        <span className="text-ink-faint">
          <span className={cx('nums', tone === 'danger' ? 'text-danger' : 'text-warn')}>{b.pct.toFixed(1)}%</span> alloc ·{' '}
          <span className="nums">{usedPct.toFixed(1)}%</span> used
        </span>
      </div>
      <Bar pct={b.pct} tone={tone} />
    </li>
  )
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: 'warn' | 'danger' }) {
  const text = tone === 'danger' ? 'text-danger' : tone === 'warn' ? 'text-warn' : 'text-ink'
  return (
    <div>
      <div className={cx('nums text-[20px]', text)}>{value}</div>
      <div className="text-[11px] text-ink-faint">{label}</div>
    </div>
  )
}

// Aggregations are over one page of devices (default 200); say so when there are more,
// rather than silently implying fleet-wide totals.
function truncatedHint(nextAfter?: string): string | undefined {
  return nextAfter ? 'first 200 hosts' : undefined
}
