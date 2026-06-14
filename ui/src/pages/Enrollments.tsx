import { useState } from 'react'
import {
  useEnrollments,
  useApproveEnrollment,
  useDenyEnrollment,
  type Enrollment,
  type EnrollmentStatus,
} from '../api/hooks'
import { usePermissions } from '../api/perms'
import { isApiError, isForbidden, isCentrallyHandled } from '../api/errors'
import { useToast } from '../components/Toast'
import { Card, Page, StateBlock, ErrorState, Button, Chip, cx } from '../components/ui'
import { Dialog } from '../components/Dialog'
import { fmtDateTime } from '../lib/format'

const TABS: { key: EnrollmentStatus; label: string }[] = [
  { key: 'pending', label: 'Pending' },
  { key: 'issued', label: 'Approved' },
  { key: 'denied', label: 'Denied' },
]

const EMPTY: Record<EnrollmentStatus, string> = {
  pending: 'No hosts are waiting for approval.',
  issued: 'No approved enrollments yet.',
  denied: 'No denied enrollments.',
}

export function Enrollments() {
  const [status, setStatus] = useState<EnrollmentStatus>('pending')
  const { can } = usePermissions()
  const mayDecide = can('enroll:decide')
  const q = useEnrollments(status)
  const rows = q.data?.pages.flatMap((p) => p.enrollments) ?? []
  const showActions = status === 'pending' && mayDecide

  return (
    <Page title="Enrollments" subtitle="Hosts requesting to join the mesh — approve issues a certificate">
      <div className="mb-4 flex gap-1">
        {TABS.map((t) => (
          <button
            key={t.key}
            onClick={() => setStatus(t.key)}
            className={cx(
              'rounded-[6px] px-3 py-1 text-[13px] transition-colors',
              status === t.key ? 'bg-mesh-2 text-ink' : 'text-ink-dim hover:bg-mesh-2',
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      {status === 'pending' && !mayDecide && (
        <div className="mb-3 text-[12px] text-ink-faint">Read-only: your role can&rsquo;t approve or deny enrollments.</div>
      )}

      {q.isPending && <StateBlock kind="loading" message="Loading enrollments…" />}
      {q.isError && <ErrorState error={q.error} fallback="Couldn't load enrollments." />}
      {q.data &&
        (rows.length === 0 ? (
          <StateBlock kind="empty" message={EMPTY[status]} />
        ) : (
          <Card className="overflow-hidden">
            <table className="w-full text-left">
              <thead className="border-b border-edge text-[11px] uppercase tracking-wide text-ink-faint">
                <tr>
                  {['Device', 'Fingerprint', 'Method', 'Groups', 'Requested', 'Overlay IP', 'Decided by'].map((h) => (
                    <th key={h} className="px-4 py-2 font-medium">{h}</th>
                  ))}
                  {showActions && <th className="px-4 py-2 text-right font-medium">Actions</th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-edge">
                {rows.map((e) => (
                  <tr key={e.enrollment_id} className="hover:bg-mesh-2">
                    <td className="px-4 py-2 text-ink">{e.device_name}</td>
                    <td className="nums px-4 py-2 font-mono text-[11px] text-ink-faint" title={e.pubkey_hash}>
                      {e.pubkey_hash.slice(0, 12)}…
                    </td>
                    <td className="px-4 py-2">
                      {e.attest_account ? (
                        <span className="flex flex-col gap-0.5">
                          <span><Chip tone="permit">{attestLabel(e.attest_provider)}</Chip></span>
                          <span className="nums font-mono text-[11px] text-ink-faint" title={e.attest_principal}>
                            {e.attest_account}
                            {e.attest_region ? ` · ${e.attest_region}` : ''}
                          </span>
                        </span>
                      ) : (
                        <span className="text-ink-dim">{e.join_key_name ? `token · ${e.join_key_name}` : e.method}</span>
                      )}
                    </td>
                    <td className="px-4 py-2">
                      <span className="flex flex-wrap gap-1">
                        {e.groups.length === 0 ? <span className="text-ink-faint">—</span> : e.groups.map((g) => <Chip key={g}>{g}</Chip>)}
                      </span>
                    </td>
                    <td className="nums px-4 py-2 text-ink-dim">{fmtDateTime(e.created_at)}</td>
                    <td className="nums px-4 py-2 text-ink-dim">{e.overlay_ip ?? '—'}</td>
                    <td className="px-4 py-2 text-ink-dim">{e.approver ?? '—'}</td>
                    {showActions && (
                      <td className="px-4 py-2">
                        <RowActions e={e} />
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

function RowActions({ e }: { e: Enrollment }) {
  const toast = useToast()
  const approve = useApproveEnrollment()
  const deny = useDenyEnrollment()
  const [denyOpen, setDenyOpen] = useState(false)
  const [reason, setReason] = useState('')
  const busy = approve.isPending || deny.isPending

  function onApprove() {
    approve.mutate(e.enrollment_id, {
      onSuccess: (d) =>
        toast.notify(`Approved ${e.device_name}${d.overlay_ip ? ` → ${d.overlay_ip}` : ''}`, 'success'),
      onError: (err) => {
        if (isCentrallyHandled(err)) return // the MutationCache is redirecting; no toast
        toast.notify(approveError(err), 'error')
      },
    })
  }

  function onDeny() {
    deny.mutate(
      { id: e.enrollment_id, reason: reason.trim() },
      {
        onSuccess: () => {
          toast.notify(`Denied ${e.device_name}`, 'info')
          setDenyOpen(false)
          setReason('')
        },
        onError: (err) => {
          if (isCentrallyHandled(err)) return
          toast.notify(decisionError(err), 'error')
        },
      },
    )
  }

  return (
    <div className="flex justify-end gap-2">
      <Button variant="primary" onClick={onApprove} disabled={busy}>Approve</Button>
      <Button variant="danger" onClick={() => setDenyOpen(true)} disabled={busy}>Deny</Button>
      <Dialog
        open={denyOpen}
        onClose={() => setDenyOpen(false)}
        title={`Deny ${e.device_name}?`}
        footer={
          <>
            <Button onClick={() => setDenyOpen(false)}>Cancel</Button>
            <Button variant="danger" onClick={onDeny} disabled={deny.isPending}>Deny enrollment</Button>
          </>
        }
      >
        <p className="text-[13px] text-ink-dim">The host is told it was rejected. Optionally include a reason it can read.</p>
        <input
          value={reason}
          onChange={(ev) => setReason(ev.target.value)}
          placeholder="Reason (optional)"
          className="mt-3 w-full rounded-[6px] border border-edge bg-mesh-2 px-2 py-1.5 text-[13px] text-ink placeholder:text-ink-faint"
        />
      </Dialog>
    </div>
  )
}

// The server returns no 404 for actions: a 409 "not pending" means the row was already
// decided or removed — tell the user to expect the refreshed queue (onSettled refetches).
function approveError(err: unknown): string {
  if (isForbidden(err)) return 'You don’t have permission to approve enrollments.'
  if (isApiError(err)) {
    if (err.status === 409) return 'No longer pending — the queue moved; it has been refreshed.'
    if (err.status === 501) return 'This Harbor is read-only (no CA configured) — it can’t issue certs. Deny still works.'
    return err.detail || err.title
  }
  return 'Approve failed.'
}

// attestLabel maps a provider id to a short display label (provider-agnostic).
function attestLabel(provider?: string): string {
  if (provider === 'aws') return 'AWS'
  if (provider === 'azure') return 'Azure'
  if (provider === 'gcp') return 'GCP'
  return provider || 'attested'
}

function decisionError(err: unknown): string {
  if (isForbidden(err)) return 'You don’t have permission to decide enrollments.'
  if (isApiError(err)) {
    if (err.status === 409) return 'No longer pending — the queue moved; it has been refreshed.'
    return err.detail || err.title
  }
  return 'Action failed.'
}
