import { useCAs, useCAAdoption, type CA } from '../api/hooks'
import { Card, Page, StateBlock, ErrorState, Chip, cx } from '../components/ui'
import { fmtDateTime } from '../lib/format'

// CA Rotation (M8) — a read-only view of the certificate-authority rotation lifecycle: which CA is
// signing, which are trusted (in every signed bundle), how each draining CA is emptying out, and any
// pending signing-key deletion. The lifecycle actions (stage/activate/retire/force-renew/schedule
// key-deletion) are deliberately break-glass CLI only; this pane is purely to observe a rotation.

const STATE_TONE: Record<string, 'default' | 'warn' | 'permit' | 'danger'> = {
  active: 'permit',
  staged: 'warn',
  draining: 'warn',
  retired: 'default',
}

const STATE_ORDER: Record<string, number> = { active: 0, staged: 1, draining: 2, retired: 3 }

function shortFp(fp: string): string {
  return fp.length > 16 ? `${fp.slice(0, 8)}…${fp.slice(-4)}` : fp
}

// humanizeRemaining renders a seconds-remaining count as a coarse, human duration for the
// key-deletion countdown (e.g. "22d", "6h", "past").
function humanizeRemaining(sec: number): string {
  if (sec <= 0) return 'past'
  const d = Math.floor(sec / 86400)
  if (d >= 1) return `${d}d`
  const h = Math.floor(sec / 3600)
  if (h >= 1) return `${h}h`
  return `${Math.max(1, Math.floor(sec / 60))}m`
}

export function CARotation() {
  const q = useCAs()

  return (
    <Page
      title="CA Rotation"
      subtitle="The certificate-authority lifecycle and trust bundle — observe a rotation (actions are CLI break-glass)"
    >
      {q.isPending && <StateBlock kind="loading" message="Loading CAs…" />}
      {q.isError && <ErrorState error={q.error} fallback="Couldn't load the CA rotation state." />}
      {q.data && <CAList data={q.data} />}
    </Page>
  )
}

function CAList({ data }: { data: { cas: CA[]; summary: Record<string, number> } }) {
  const cas = [...data.cas].sort(
    (a, b) => (STATE_ORDER[a.state] ?? 9) - (STATE_ORDER[b.state] ?? 9) || a.name.localeCompare(b.name),
  )
  const trusted = cas.filter((c) => c.trusted).length

  if (cas.length === 0) {
    return <StateBlock kind="empty" message="No CAs recorded yet — the current CA is seeded on Core startup." />
  }

  return (
    <div className="flex flex-col gap-5">
      {/* Trust-bundle summary: what every signed bundle currently distributes. */}
      <div className="flex flex-wrap items-center gap-2 text-[12px] text-ink-dim">
        <span className="text-ink-faint">Trust bundle:</span>
        <Chip tone="permit">{trusted} CA{trusted === 1 ? '' : 's'} trusted fleet-wide</Chip>
        <span className="text-ink-faint">·</span>
        <span>{data.summary.active ?? 0} active</span>
        <span>{data.summary.staged ?? 0} staged</span>
        <span>{data.summary.draining ?? 0} draining</span>
        <span>{data.summary.retired ?? 0} retired</span>
      </div>

      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="border-b border-edge text-[11px] uppercase tracking-wide text-ink-faint">
              <tr>
                {['State', 'Name', 'Fingerprint', 'Not after', 'Live deps', 'Key deletion'].map((h) => (
                  <th key={h} className="px-4 py-2 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {cas.map((c) => (
                <CARow key={c.id} ca={c} />
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <p className="text-[11px] text-ink-faint">
        Signing cuts over to a newly-activated CA with zero downtime; a draining CA empties as hosts renew
        (accelerate with <span className="font-mono">harbor ca force-renew</span>), and its key is deleted only
        after retirement, within a cancellable KMS window.
      </p>
    </div>
  )
}

function CARow({ ca }: { ca: CA }) {
  const isStaged = ca.state === 'staged'
  return (
    <>
      <tr className={cx('border-b border-edge/60', ca.is_active && 'bg-permit/5')}>
        <td className="px-4 py-2">
          <Chip tone={STATE_TONE[ca.state] ?? 'default'}>{ca.state}</Chip>
          {ca.is_active && <span className="ml-1.5 text-[11px] text-permit">signing</span>}
        </td>
        <td className="px-4 py-2 font-mono text-[12px] text-ink">{ca.name}</td>
        <td className="px-4 py-2 font-mono text-[12px] text-ink-dim" title={ca.fingerprint}>{shortFp(ca.fingerprint)}</td>
        <td className="px-4 py-2 text-[12px] text-ink-dim">{ca.not_after ? fmtDateTime(ca.not_after) : '—'}</td>
        <td className="nums px-4 py-2 text-[12px]">
          <DrainCell ca={ca} />
        </td>
        <td className="px-4 py-2 text-[12px]">
          {ca.key_deletion ? (
            <span
              className={cx(ca.key_deletion.seconds_remaining <= 0 ? 'text-danger' : 'text-warn')}
              title={`Key destroyed ${fmtDateTime(ca.key_deletion.date)} (KMS window)`}
            >
              ⚠ key del {humanizeRemaining(ca.key_deletion.seconds_remaining)}
            </span>
          ) : (
            <span className="text-ink-faint">—</span>
          )}
        </td>
      </tr>
      {isStaged && (
        <tr className="border-b border-edge/60">
          <td />
          <td colSpan={5} className="px-4 pb-3">
            <AdoptionBar id={ca.id} />
          </td>
        </tr>
      )}
    </>
  )
}

// DrainCell shows a draining CA's live-dependent count (the drain progress toward 0) plus, when an
// accelerated drain is running, that it is force-renewing in waves.
function DrainCell({ ca }: { ca: CA }) {
  const deps = ca.live_dependents
  const label = deps < 0 ? '?' : deps.toLocaleString()
  return (
    <span className="inline-flex items-center gap-1.5 text-ink-dim">
      {label}
      {ca.state === 'draining' && deps > 0 && !ca.force_renew && <span className="text-ink-faint">draining</span>}
      {ca.force_renew && <Chip tone="warn">force-renew {Math.round(ca.force_renew.window_seconds / 60)}m</Chip>}
    </span>
  )
}

// AdoptionBar renders the trust-adoption progress for a staged CA — the "trust before you sign" gate
// that must reach 100% of live hosts before `ca activate` cuts signing over.
function AdoptionBar({ id }: { id: number }) {
  const q = useCAAdoption(id)
  if (q.isPending) return <span className="text-[11px] text-ink-faint">checking trust adoption…</span>
  if (q.isError) return <span className="text-[11px] text-ink-faint">adoption unavailable</span>
  const a = q.data!
  const pct = Math.round(a.percent)
  const full = a.fully_adopted
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center gap-2 text-[11px]">
        <span className="uppercase tracking-wide text-ink-faint">Trust adoption (activate gate)</span>
        <span className={cx('font-mono', full ? 'text-permit' : 'text-warn')}>
          {a.adopted}/{a.live} live · {pct}%
        </span>
        {full ? (
          <span className="text-permit">ready to activate</span>
        ) : (
          <span className="text-warn">{a.laggards.length} laggard{a.laggards.length === 1 ? '' : 's'} block the gate</span>
        )}
      </div>
      <div className="h-1.5 w-full max-w-[420px] overflow-hidden rounded-[3px] border border-edge bg-mesh-2">
        <div
          className={cx('h-full', full ? 'bg-permit' : 'bg-warn')}
          style={{ width: `${a.live > 0 ? pct : 100}%` }}
        />
      </div>
      {a.stale.length > 0 && (
        <span className="text-[11px] text-ink-faint">{a.stale.length} stale host(s) excluded from the gate</span>
      )}
    </div>
  )
}
