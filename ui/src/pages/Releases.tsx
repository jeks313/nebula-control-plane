import { useState, type ReactNode } from 'react'
import {
  useReleases,
  useStartReleaseRollout,
  useAbortReleaseRollout,
  type ReleaseLane,
  type ReleaseView,
  type ReleaseKind,
  type RolloutStatus,
} from '../api/hooks'
import { usePermissions } from '../api/perms'
import { isApiError, isForbidden, isCentrallyHandled } from '../api/errors'
import { useToast } from '../components/Toast'
import { Card, Page, StateBlock, ErrorState, Button, Chip, cx } from '../components/ui'
import { Dialog } from '../components/Dialog'
import { fmtDateTime } from '../lib/format'

// Releases (#39) — the nebula + pilot binary registries and a way to stage a fleet
// upgrade to a registered generation. Binaries are added out-of-band via the CLI
// (harbor nebula/pilot add); there is no upload here. Each kind rolls out on its own
// canary lane via the rollout engine, so the two can converge independently.

const KINDS: { kind: ReleaseKind; title: string; blurb: string }[] = [
  { kind: 'nebula', title: 'Nebula', blurb: 'The overlay data-plane binary each pilot supervises.' },
  { kind: 'pilot', title: 'Pilot', blurb: 'The agent itself — self-updates by re-exec, re-adopting its nebula.' },
]

export function Releases() {
  const { can } = usePermissions()
  const mayRoll = can('rollout:control')
  const q = useReleases()

  return (
    <Page
      title="Releases"
      subtitle="Nebula & pilot binaries and fleet upgrades — binaries are registered via the harbor CLI"
    >
      {q.isPending && <StateBlock kind="loading" message="Loading releases…" />}
      {q.isError && <ErrorState error={q.error} fallback="Couldn't load releases." />}
      {q.data && (
        <div className="flex flex-col gap-6">
          {KINDS.map(({ kind, title, blurb }) => (
            <LaneSection key={kind} kind={kind} title={title} blurb={blurb} lane={q.data[kind]} mayRoll={mayRoll} />
          ))}
        </div>
      )}
    </Page>
  )
}

function LaneSection({
  kind,
  title,
  blurb,
  lane,
  mayRoll,
}: {
  kind: ReleaseKind
  title: string
  blurb: string
  lane: ReleaseLane
  mayRoll: boolean
}) {
  const rollout = lane.rollout ?? null
  const active = Boolean(rollout?.active && rollout.rollout)
  const rolledBack = rollout?.rollout?.state === 'rolledback'

  return (
    <section>
      <div className="mb-2 flex items-baseline justify-between gap-4">
        <div>
          <h2 className="text-[15px] font-semibold text-ink">{title}</h2>
          <p className="text-[12px] text-ink-dim">{blurb}</p>
        </div>
        {mayRoll && active && rollout && <AbortButton kind={kind} title={title} />}
      </div>

      {rollout && (active || rolledBack) && <LaneRollout kind={kind} rollout={rollout} />}

      {lane.releases.length === 0 ? (
        <StateBlock
          kind="empty"
          message={`No ${title.toLowerCase()} releases registered. Add one with: harbor ${kind} add -version … -sha256 … -url …`}
        />
      ) : (
        <Card className="overflow-hidden">
          <table className="w-full text-left">
            <thead className="border-b border-edge text-[11px] uppercase tracking-wide text-ink-faint">
              <tr>
                {['Gen', 'Version', 'SHA-256', 'Status', 'Added'].map((h) => (
                  <th key={h} className="px-4 py-2 font-medium">{h}</th>
                ))}
                {mayRoll && <th className="px-4 py-2 text-right font-medium">Actions</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-edge">
              {lane.releases.map((r) => (
                <ReleaseRow
                  key={r.gen}
                  kind={kind}
                  kindTitle={title}
                  r={r}
                  isCurrent={r.gen === lane.current_gen}
                  mayRoll={mayRoll}
                  // can only stage when the lane is idle (no rollout in flight)
                  mayStage={mayRoll && !active}
                />
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </section>
  )
}

// LaneRollout — the in-flight (or rolled-back) state for this kind's lane, with per-wave
// host convergence. Mirrors the Dashboard active-ops strip but scoped to one lane.
function LaneRollout({ kind, rollout }: { kind: ReleaseKind; rollout: RolloutStatus }) {
  const rv = rollout.rollout
  if (!rv) return null
  const rolledBack = rv.state === 'rolledback'
  const hosts = rollout.hosts
  const converged = hosts.filter((h) => h.status === 'converged').length
  const failed = hosts.filter((h) => h.status === 'failed' || h.status === 'reverted').length

  return (
    <Card className={cx('mb-3 px-4 py-3', rolledBack ? 'border-danger/50' : 'border-permit/50')}>
      <div className="flex items-center gap-2 text-[13px]">
        {rolledBack ? (
          <>
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-danger" aria-hidden />
            <span className="text-danger">
              {rv.prev_version > 0
                ? `Rollout auto-rolled-back — fleet held on gen ${rv.prev_version}.`
                : 'Rollout auto-rolled-back — no prior generation; fleet left on its baseline binary.'}
            </span>
          </>
        ) : (
          <>
            <span className="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-permit" aria-hidden />
            <span className="text-ink">
              Rolling out {kind} gen <span className="nums">{rv.target_version}</span> — {rv.state}, wave{' '}
              <span className="nums">{rv.active_wave + 1}</span>.
            </span>
          </>
        )}
        <span className="ml-auto text-[12px] text-ink-dim">
          <span className="nums text-permit">{converged}</span> converged
          {failed > 0 && <span className="nums ml-2 text-danger">{failed} failed</span>}
          <span className="nums ml-2 text-ink-faint">/ {hosts.length} hosts</span>
        </span>
      </div>
    </Card>
  )
}

const STATUS_TONE: Record<string, 'permit' | 'warn' | 'default'> = {
  current: 'permit',
  candidate: 'warn',
}

function ReleaseRow({
  kind,
  kindTitle,
  r,
  isCurrent,
  mayRoll,
  mayStage,
}: {
  kind: ReleaseKind
  kindTitle: string
  r: ReleaseView
  isCurrent: boolean
  mayRoll: boolean
  mayStage: boolean
}) {
  return (
    <tr className="hover:bg-mesh-2">
      <td className="nums px-4 py-2 text-ink-dim">{r.gen}</td>
      <td className="px-4 py-2 font-mono text-[12px] text-ink">{r.version}</td>
      <td className="px-4 py-2 font-mono text-[11px] text-ink-faint" title={r.sha256}>{shortSha(r.sha256)}</td>
      <td className="px-4 py-2">
        <Chip tone={STATUS_TONE[r.status] ?? 'default'}>{r.status}</Chip>
      </td>
      <td className="nums px-4 py-2 text-ink-faint">{fmtDateTime(r.created_at)}</td>
      {mayRoll && (
        <td className="px-4 py-2">
          <div className="flex justify-end">
            {isCurrent ? (
              // matches the row's "current" chip — the settled, fleet-desired gen (not an
              // in-flight op; active rollouts show in the LaneRollout banner)
              <span className="text-[12px] text-ink-faint">current</span>
            ) : mayStage ? (
              <RolloutButton kind={kind} kindTitle={kindTitle} r={r} />
            ) : (
              <span className="text-[12px] text-ink-faint">—</span>
            )}
          </div>
        </td>
      )}
    </tr>
  )
}

function RolloutButton({ kind, kindTitle, r }: { kind: ReleaseKind; kindTitle: string; r: ReleaseView }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <Button variant="primary" onClick={() => setOpen(true)}>Roll out</Button>
      {open && <RolloutDialog kind={kind} kindTitle={kindTitle} r={r} onClose={() => setOpen(false)} />}
    </>
  )
}

const FIELD =
  'w-full rounded-[6px] border border-edge bg-mesh-2 px-2 py-1.5 text-[13px] text-ink placeholder:text-ink-faint'

function RolloutDialog({
  kind,
  kindTitle,
  r,
  onClose,
}: {
  kind: ReleaseKind
  kindTitle: string
  r: ReleaseView
  onClose: () => void
}) {
  const toast = useToast()
  const start = useStartReleaseRollout()
  const [f, setF] = useState({ canary: '', wave: '', observe: '', missing: '' })

  function submit() {
    start.mutate(
      {
        kind,
        body: {
          gen: r.gen,
          canary_size: numOrZero(f.canary),
          wave_size: numOrZero(f.wave),
          // minutes -> seconds; numOrZero guards non-numeric input (-> 0 = server default),
          // so all four numeric fields coerce identically.
          observe_seconds: numOrZero(f.observe) * 60,
          missing_after_seconds: numOrZero(f.missing) * 60,
        },
      },
      {
        onSuccess: () => {
          toast.notify(`Rolling out ${kind} ${r.version} (gen ${r.gen})`, 'success')
          onClose()
        },
        onError: (err) => {
          if (isCentrallyHandled(err)) return // the MutationCache is redirecting; no toast
          toast.notify(startError(err, kindTitle), 'error')
        },
      },
    )
  }

  return (
    <Dialog
      open
      onClose={onClose}
      title={`Roll out ${kindTitle} ${r.version}?`}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={start.isPending}>
            {start.isPending ? 'Starting…' : 'Start rollout'}
          </Button>
        </>
      }
    >
      <p className="text-[13px] text-ink-dim">
        Stages <span className="font-mono text-ink">{kind} {r.version}</span> (gen <span className="nums">{r.gen}</span>) across the
        fleet on the {kind} lane: a canary first, then widening wave by wave, with auto-rollback if a wave fails to
        converge. Blank fields use the server defaults.
      </p>
      <div className="mt-3 grid grid-cols-2 gap-2">
        <Labeled label="Canary size (hosts)">
          <input inputMode="numeric" value={f.canary} onChange={(e) => setF({ ...f, canary: e.target.value })} placeholder="default" className={FIELD} />
        </Labeled>
        <Labeled label="Wave size (hosts)">
          <input inputMode="numeric" value={f.wave} onChange={(e) => setF({ ...f, wave: e.target.value })} placeholder="default" className={FIELD} />
        </Labeled>
        <Labeled label="Observe per wave (min)">
          <input inputMode="numeric" value={f.observe} onChange={(e) => setF({ ...f, observe: e.target.value })} placeholder="10" className={FIELD} />
        </Labeled>
        <Labeled label="Missing-after (min)">
          <input inputMode="numeric" value={f.missing} onChange={(e) => setF({ ...f, missing: e.target.value })} placeholder="3" className={FIELD} />
        </Labeled>
      </div>
      <p className="mt-2 font-mono text-[11px] text-ink-faint" title={r.sha256}>sha256: {r.sha256}</p>
    </Dialog>
  )
}

function AbortButton({ kind, title }: { kind: ReleaseKind; title: string }) {
  const toast = useToast()
  const abort = useAbortReleaseRollout()
  const [open, setOpen] = useState(false)

  function onAbort() {
    abort.mutate(kind, {
      onSuccess: () => {
        toast.notify(`Aborted the ${title.toLowerCase()} rollout`, 'info')
        setOpen(false)
      },
      onError: (err) => {
        if (isCentrallyHandled(err)) return
        // 404/409 = no active rollout on this lane; onSettled refetched, so treat as done.
        if (isApiError(err) && (err.status === 404 || err.status === 409)) {
          toast.notify('No active rollout to abort.', 'info')
          setOpen(false)
          return
        }
        if (isForbidden(err)) {
          toast.notify('You don’t have permission to control rollouts.', 'error')
          return
        }
        toast.notify(isApiError(err) ? err.detail || err.title : 'Abort failed.', 'error')
      },
    })
  }

  return (
    <>
      <Button variant="danger" onClick={() => setOpen(true)}>Abort rollout</Button>
      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        title={`Abort the ${title} rollout?`}
        footer={
          <>
            <Button onClick={() => setOpen(false)}>Keep going</Button>
            <Button variant="danger" onClick={onAbort} disabled={abort.isPending}>Abort & roll back</Button>
          </>
        }
      >
        <p className="text-[13px] text-ink-dim">
          Hosts already on the new generation revert to the previous one; not-yet-upgraded hosts stay put. The lane
          returns to idle.
        </p>
      </Dialog>
    </>
  )
}

function Labeled({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-[11px] uppercase tracking-wide text-ink-faint">{label}</span>
      {children}
    </label>
  )
}

function shortSha(s: string): string {
  return s.length > 12 ? s.slice(0, 12) + '…' : s
}

function numOrZero(s: string): number {
  const n = Number(s)
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0
}

function startError(err: unknown, kindTitle: string): string {
  if (isForbidden(err)) return 'You don’t have permission to control rollouts.'
  if (isApiError(err)) {
    if (err.status === 409) return `A ${kindTitle.toLowerCase()} rollout is already in flight.`
    if (err.status === 400) return err.detail || 'Invalid rollout request.'
    if (err.status === 404) return 'Unknown release kind.'
    return err.detail || err.title
  }
  return 'Couldn’t start the rollout.'
}
