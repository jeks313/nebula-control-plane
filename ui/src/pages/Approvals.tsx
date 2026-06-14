import { useState } from 'react'
import {
  useApprovals,
  useApproval,
  useApproveChange,
  useDenyChange,
  useMe,
} from '../api/hooks'
import { usePermissions } from '../api/perms'
import { isApiError, isForbidden, isCentrallyHandled } from '../api/errors'
import { useToast } from '../components/Toast'
import { Card, Page, StateBlock, ErrorState, Button, Chip, cx } from '../components/ui'
import { Dialog } from '../components/Dialog'
import { fmtDateTime } from '../lib/format'
import { approveCount, canApprove, canDeny, isSelfApprovalDeadend } from '../lib/approvals'

// '' = All (the server returns every state, incl. the transient 'committing' window so
// an in-flight or crash-stuck commit is never invisible).
type Filter = '' | 'pending' | 'committed' | 'denied' | 'failed'

const TABS: { key: Filter; label: string }[] = [
  { key: 'pending', label: 'Pending' },
  { key: '', label: 'All' },
  { key: 'committed', label: 'Committed' },
  { key: 'denied', label: 'Denied' },
  { key: 'failed', label: 'Failed' },
]

const EMPTY: Record<Filter, string> = {
  '': 'No changes yet.',
  pending: 'No changes awaiting review.',
  committed: 'No committed changes yet.',
  denied: 'No denied changes.',
  failed: 'No failed changes.',
}

export function Approvals() {
  const [state, setState] = useState<Filter>('pending')
  const [openId, setOpenId] = useState<number | null>(null)
  const q = useApprovals(state)
  const rows = q.data?.approvals ?? []

  return (
    <Page title="Approvals" subtitle="Two-person control — every privileged change needs a distinct second admin">
      <div className="mb-4 flex gap-1">
        {TABS.map((t) => (
          <button
            key={t.key}
            onClick={() => setState(t.key)}
            className={cx(
              'rounded-[6px] px-3 py-1 text-[13px] transition-colors',
              state === t.key ? 'bg-mesh-2 text-ink' : 'text-ink-dim hover:bg-mesh-2',
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      {q.isPending && <StateBlock kind="loading" message="Loading approvals…" />}
      {q.isError && <ErrorState error={q.error} fallback="Couldn't load approvals." />}
      {q.data &&
        (rows.length === 0 ? (
          <StateBlock kind="empty" message={EMPTY[state]} />
        ) : (
          <Card className="overflow-hidden">
            <table className="w-full text-left">
              <thead className="border-b border-edge text-[11px] uppercase tracking-wide text-ink-faint">
                <tr>
                  {['Change', 'Target', 'Proposer', 'Quorum', 'State', 'Opened'].map((h) => (
                    <th key={h} className="px-4 py-2 font-medium">{h}</th>
                  ))}
                  <th className="px-4 py-2 text-right font-medium">Review</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-edge">
                {rows.map((c) => (
                  <tr key={c.id} className="hover:bg-mesh-2">
                    <td className="px-4 py-2"><Chip>{kindLabel(c.kind)}</Chip></td>
                    <td className="px-4 py-2 text-ink">{c.target || '—'}</td>
                    <td className="px-4 py-2 text-ink-dim">{c.proposer}</td>
                    <td className="nums px-4 py-2 text-ink-dim">{c.quorum}-person</td>
                    <td className="px-4 py-2"><StateChip state={c.state} /></td>
                    <td className="nums px-4 py-2 text-ink-faint">{fmtDateTime(c.created_at)}</td>
                    <td className="px-4 py-2">
                      <div className="flex justify-end">
                        <Button onClick={() => setOpenId(c.id)}>Review</Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        ))}

      {openId !== null && <ReviewDialog id={openId} onClose={() => setOpenId(null)} />}
    </Page>
  )
}

function ReviewDialog({ id, onClose }: { id: number; onClose: () => void }) {
  const toast = useToast()
  const me = useMe()
  const { can } = usePermissions()
  const mayDecide = can('approval:decide')
  const q = useApproval(id)
  const approve = useApproveChange()
  const deny = useDenyChange()
  const [denyOpen, setDenyOpen] = useState(false)
  const [reason, setReason] = useState('')

  const detail = q.data
  const change = detail?.change
  const signoffs = detail?.signoffs ?? []
  const principal = me.data?.principal ?? ''
  const gate = change ? canApprove(change, signoffs, principal, mayDecide) : { ok: false }
  const mayDeny = change ? canDeny(change, mayDecide) : false
  const deadend = change ? isSelfApprovalDeadend(change, principal, mayDecide) : false
  const busy = approve.isPending || deny.isPending

  function onApprove() {
    approve.mutate(id, {
      onSuccess: (c) => {
        toast.notify(c.state === 'committed' ? 'Approved — change committed.' : 'Approval recorded.', 'success')
        onClose()
      },
      onError: (err) => {
        if (isCentrallyHandled(err)) return // step-up redirect / login handled centrally
        toast.notify(decideError(err), 'error')
      },
    })
  }

  function onDeny() {
    deny.mutate(
      { id, reason: reason.trim() },
      {
        onSuccess: () => {
          toast.notify('Change denied.', 'info')
          setDenyOpen(false)
          onClose()
        },
        onError: (err) => {
          if (isCentrallyHandled(err)) return
          toast.notify(decideError(err), 'error')
        },
      },
    )
  }

  return (
    <Dialog
      open
      onClose={onClose}
      title={change ? `Review: ${kindLabel(change.kind)}` : 'Review change'}
      footer={
        change && change.state === 'pending' && mayDecide ? (
          <>
            <Button variant="danger" onClick={() => setDenyOpen(true)} disabled={busy}>Deny</Button>
            <Button variant="primary" onClick={onApprove} disabled={!gate.ok || busy} title={gate.reason}>
              Approve
            </Button>
          </>
        ) : (
          <Button onClick={onClose}>Close</Button>
        )
      }
    >
      {q.isPending && <StateBlock kind="loading" message="Loading change…" />}
      {q.isError && <ErrorState error={q.error} fallback="Couldn't load the change." />}
      {change && (
        <div className="flex flex-col gap-3">
          <div className="flex items-center gap-2 text-[12px] text-ink-dim">
            <StateChip state={change.state} />
            <span>proposed by <span className="text-ink">{change.proposer}</span></span>
            <span className="ml-auto nums text-ink-faint">{approveCount(signoffs)}/{change.quorum} approvals</span>
          </div>

          {deadend && (
            <div className="rounded-[6px] border border-warn/40 bg-warn/10 px-3 py-2 text-[12px] text-warn">
              You proposed this change — two-person control requires a different admin to approve it.
            </div>
          )}

          {/* The proposed payload (policy DSL / cloud-trust JSON) — what is being approved.
              Pretty-print JSON (cloud-trust) for readability; policy DSL is non-JSON so it
              falls through to the raw text. */}
          <div>
            <div className="mb-1 text-[11px] uppercase tracking-wide text-ink-faint">Payload</div>
            <pre className="max-h-60 overflow-auto rounded-[6px] border border-edge bg-mesh-2 px-3 py-2 font-mono text-[12px] text-ink">
              {prettyPayload(change.payload)}
            </pre>
          </div>

          <div>
            <div className="mb-1 text-[11px] uppercase tracking-wide text-ink-faint">Sign-offs</div>
            <ul className="flex flex-col gap-1 text-[12px]">
              {signoffs.map((s, i) => (
                <li key={`${s.actor}-${i}`} className="flex items-center gap-2">
                  <span className={s.decision === 'deny' ? 'text-danger' : 'text-permit'}>{s.decision}</span>
                  <span className="text-ink">{s.actor}</span>
                  <span className="ml-auto text-ink-faint">{fmtDateTime(s.created_at)}</span>
                </li>
              ))}
            </ul>
          </div>

          {change.state === 'pending' && mayDecide && !gate.ok && !deadend && gate.reason && (
            <div className="text-[12px] text-ink-faint">{gate.reason}</div>
          )}
        </div>
      )}

      {change && (
        <Dialog
          open={denyOpen}
          onClose={() => setDenyOpen(false)}
          title="Deny this change?"
          footer={
            <>
              <Button onClick={() => setDenyOpen(false)}>Cancel</Button>
              <Button variant="danger" onClick={onDeny} disabled={!mayDeny || deny.isPending}>Deny change</Button>
            </>
          }
        >
          <p className="text-[13px] text-ink-dim">A single deny vetoes the change (fail-closed). Optionally say why.</p>
          <input
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Reason (optional)"
            className="mt-3 w-full rounded-[6px] border border-edge bg-mesh-2 px-2 py-1.5 text-[13px] text-ink placeholder:text-ink-faint"
          />
        </Dialog>
      )}
    </Dialog>
  )
}

function StateChip({ state }: { state: string }) {
  const tone = state === 'committed' ? 'permit' : state === 'denied' || state === 'failed' ? 'danger' : 'warn'
  return <Chip tone={tone}>{state}</Chip>
}

function kindLabel(kind: string): string {
  if (kind === 'policy.publish') return 'Policy publish'
  if (kind === 'cloudtrust.publish') return 'Cloud-trust publish'
  return kind
}

// prettyPayload renders a JSON payload (cloud-trust) multi-line; non-JSON (policy DSL)
// falls through to the raw text.
function prettyPayload(payload?: string): string {
  if (!payload) return '(empty)'
  try {
    return JSON.stringify(JSON.parse(payload), null, 2)
  } catch {
    return payload
  }
}

function decideError(err: unknown): string {
  if (isForbidden(err)) return 'Your role cannot decide approvals.'
  if (isApiError(err)) {
    if (err.status === 409) return err.detail || 'This change moved — the queue has been refreshed.'
    if (err.status === 422) return 'Approved, but the change failed validation at commit and was not applied.'
    return err.detail || err.title
  }
  return 'Action failed.'
}
