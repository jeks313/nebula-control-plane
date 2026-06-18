import { useState, type ReactNode } from 'react'
import { useCloudTrust, useProposeCloudTrust, useNetblocks, type CloudTrust as CloudTrustConfig, type Netblock } from '../api/hooks'
import { usePermissions } from '../api/perms'
import { isApiError, isCentrallyHandled } from '../api/errors'
import { useToast } from '../components/Toast'
import { Card, Page, StateBlock, ErrorState, Button, Chip, cx } from '../components/ui'

// Cloud Trust — the dual-control-published cloud-attestation config: which cloud
// principals (AWS accounts/roles today) may attest into the mesh, and the groups +
// auto-issue posture each is granted. Editing republishes the WHOLE config as a new
// version through dual-control (no per-account patch); it takes effect only on approval.
export function CloudTrust() {
  const { can } = usePermissions()
  const mayPropose = can('cloudtrust:propose')
  const q = useCloudTrust()
  const cfg = q.data
  const [editing, setEditing] = useState(false)

  return (
    <Page
      title="Cloud Trust"
      subtitle="Which cloud accounts may attest into the mesh — and the groups they're granted"
      actions={
        mayPropose && cfg ? (
          <Button variant="primary" onClick={() => setEditing((v) => !v)}>
            {editing ? 'Close editor' : cfg.published ? 'Propose change' : 'Add accounts'}
          </Button>
        ) : undefined
      }
    >
      {q.isPending && <StateBlock kind="loading" message="Loading cloud-trust config…" />}
      {q.isError && <ErrorState error={q.error} fallback="Couldn't load the cloud-trust config." />}

      {mayPropose && editing && cfg && (
        <div className="mb-5">
          <CloudTrustEditor cfg={cfg} onClose={() => setEditing(false)} />
        </div>
      )}

      {cfg &&
        (!cfg.published ? (
          <StateBlock
            kind="empty"
            message={
              mayPropose
                ? 'No cloud-trust config published yet. Use “Add accounts” to propose the first version (dual-control).'
                : 'No cloud-trust config published yet. Publishing is a dual-control change.'
            }
          />
        ) : (
          <div className="flex flex-col gap-4">
            <Card className="px-4 py-3 text-[13px] text-ink-dim">
              Published as change <span className="nums text-ink">#{cfg.change_id}</span>. Default groups granted to every
              attested host:{' '}
              <span className="ml-1 inline-flex flex-wrap gap-1 align-middle">
                {(cfg.default_groups ?? []).length === 0 ? (
                  <span className="text-ink-faint">none</span>
                ) : (
                  (cfg.default_groups ?? []).map((g) => <Chip key={g} tone="permit">{g}</Chip>)
                )}
              </span>
            </Card>

            <Card className="overflow-hidden">
              <div className="border-b border-edge px-4 py-2 text-[12px] text-ink-faint">Trusted AWS accounts</div>
              <table className="w-full text-left">
                <thead className="border-b border-edge text-[11px] uppercase tracking-wide text-ink-faint">
                  <tr>
                    {['Account', 'Allowed roles (ARN)', 'Groups', 'Netblock', 'Admission'].map((h) => (
                      <th key={h} className="px-4 py-2 font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-edge">
                  {(cfg.aws ?? []).map((a) => (
                    <tr key={a.account} className="align-top hover:bg-mesh-2">
                      <td className="nums px-4 py-2 font-mono text-[12px] text-ink">{a.account}</td>
                      <td className="px-4 py-2 font-mono text-[11px] text-ink-dim">
                        {(a.arn_patterns ?? []).length === 0 ? (
                          <span className="text-ink-faint">any role in the account</span>
                        ) : (
                          <span className="flex flex-col gap-0.5">
                            {(a.arn_patterns ?? []).map((p) => <span key={p}>{p}</span>)}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2">
                        <span className="flex flex-wrap gap-1">
                          {(a.groups ?? []).length === 0 ? <span className="text-ink-faint">—</span> : (a.groups ?? []).map((g) => <Chip key={g}>{g}</Chip>)}
                        </span>
                      </td>
                      <td className="px-4 py-2 font-mono text-[12px]">
                        {a.netblock ? <span className="text-ink-dim">{a.netblock}</span> : <span className="text-ink-faint">default</span>}
                      </td>
                      <td className="px-4 py-2">
                        {a.auto_issue ? <Chip tone="warn">auto-issue</Chip> : <span className="text-ink-dim">manual approval</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          </div>
        ))}
    </Page>
  )
}

const FIELD = 'w-full rounded-[6px] border border-edge bg-mesh-2 px-2 py-1.5 text-[13px] text-ink placeholder:text-ink-faint'

type Row = { account: string; arnPatterns: string; groups: string; netblock: string; autoIssue: boolean }

function CloudTrustEditor({ cfg, onClose }: { cfg: CloudTrustConfig; onClose: () => void }) {
  const toast = useToast()
  const propose = useProposeCloudTrust()
  // Seeded once from the active config (the editor mounts fresh each time it opens, so
  // the async-loaded config never clobbers in-progress edits).
  const [defaultGroups, setDefaultGroups] = useState((cfg.default_groups ?? []).join(', '))
  const [rows, setRows] = useState<Row[]>(
    (cfg.aws ?? []).length > 0
      ? (cfg.aws ?? []).map((a) => ({
          account: a.account,
          arnPatterns: (a.arn_patterns ?? []).join(', '),
          groups: (a.groups ?? []).join(', '),
          netblock: a.netblock ?? '',
          autoIssue: !!a.auto_issue,
        }))
      : [{ account: '', arnPatterns: '', groups: '', netblock: '', autoIssue: false }],
  )
  const [description, setDescription] = useState('')

  const setRow = (i: number, patch: Partial<Row>) => setRows(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)))
  const addRow = () => setRows([...rows, { account: '', arnPatterns: '', groups: '', netblock: '', autoIssue: false }])
  const removeRow = (i: number) => setRows(rows.filter((_, j) => j !== i))

  function submit() {
    const aws = rows
      .filter((r) => r.account.trim())
      .map((r) => ({
        account: r.account.trim(),
        arn_patterns: splitList(r.arnPatterns),
        groups: splitList(r.groups),
        netblock: r.netblock,
        auto_issue: r.autoIssue,
      }))
    if (aws.length === 0) {
      toast.notify('Add at least one AWS account (a config with zero accounts is rejected).', 'error')
      return
    }
    const ids = aws.map((a) => a.account)
    if (new Set(ids).size !== ids.length) {
      toast.notify('Account ids must be unique.', 'error')
      return
    }
    propose.mutate(
      { default_groups: splitList(defaultGroups), aws, description: description.trim() },
      {
        onSuccess: (c) => {
          toast.notify(`Opened change #${c.id} — review it in Approvals.`, 'success')
          onClose()
        },
        onError: (err) => {
          if (isCentrallyHandled(err)) return // step-up re-auth handled centrally
          toast.notify(isApiError(err) ? err.detail || err.title : 'Propose failed.', 'error')
        },
      },
    )
  }

  return (
    <Card className="overflow-hidden">
      <div className="border-b border-edge px-4 py-2 text-[12px] font-medium text-ink">
        {cfg.published ? 'Propose a new cloud-trust version' : 'Propose the first cloud-trust config'}
      </div>
      <div className="flex flex-col gap-4 px-4 py-3">
        <div className="rounded-[6px] border border-warn/40 bg-warn/10 px-3 py-2 text-[12px] text-warn">
          This controls <strong>who may attest into the mesh</strong>. It is a two-person dual-control change — proposing
          opens an approval and it takes effect only after a different admin approves. Widening scope (accounts / ARN
          patterns) or admission (auto-issue) admits more hosts, so review carefully. Editing republishes the whole config:
          keep every account you want to retain.
        </div>

        <Labeled label="Default groups (granted to every attested host, comma-separated)">
          <input value={defaultGroups} onChange={(e) => setDefaultGroups(e.target.value)} placeholder="fleet" className={FIELD} />
        </Labeled>

        <div className="flex flex-col gap-3">
          <div className="text-[11px] uppercase tracking-wide text-ink-faint">Trusted AWS accounts</div>
          {rows.map((r, i) => (
            <AccountRow key={i} r={r} onChange={(p) => setRow(i, p)} onRemove={() => removeRow(i)} />
          ))}
          <div>
            <Button onClick={addRow}>+ Add account</Button>
          </div>
        </div>

        <Labeled label="Description (optional)">
          <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="why this change" className={FIELD} />
        </Labeled>

        <div className="flex gap-2 border-t border-edge pt-3">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={propose.isPending}>
            {propose.isPending ? 'Proposing…' : 'Propose change'}
          </Button>
        </div>
      </div>
    </Card>
  )
}

function AccountRow({ r, onChange, onRemove }: { r: Row; onChange: (p: Partial<Row>) => void; onRemove: () => void }) {
  const risky = r.autoIssue && !r.arnPatterns.trim()
  return (
    <div className="flex flex-col gap-2 rounded-[6px] border border-edge p-3">
      <div className="flex items-center gap-2">
        <input
          value={r.account}
          onChange={(e) => onChange({ account: e.target.value })}
          placeholder="AWS account id (e.g. 111122223333)"
          className={cx(FIELD, 'font-mono')}
        />
        <Button variant="danger" onClick={onRemove}>Remove</Button>
      </div>
      <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
        <Labeled label="Allowed roles (ARN globs; empty = any role)">
          <input
            value={r.arnPatterns}
            onChange={(e) => onChange({ arnPatterns: e.target.value })}
            placeholder="arn:aws:sts::111122223333:assumed-role/web-*/*"
            className={cx(FIELD, 'font-mono text-[12px]')}
          />
        </Labeled>
        <Labeled label="Groups granted">
          <input value={r.groups} onChange={(e) => onChange({ groups: e.target.value })} placeholder="web, servers" className={FIELD} />
        </Labeled>
        <Labeled label="Netblock (overlay IP source — ADR 0010)">
          <NetblockSelect value={r.netblock} onChange={(v) => onChange({ netblock: v })} />
        </Labeled>
      </div>
      <label className="flex items-center gap-2 text-[13px] text-ink">
        <input type="checkbox" checked={r.autoIssue} onChange={(e) => onChange({ autoIssue: e.target.checked })} /> Auto-issue (skip per-device approval)
      </label>
      {risky && (
        <span className="text-[12px] text-warn">
          ⚠ Auto-issue + any role: every role in this account is admitted automatically. Scope it with an ARN pattern.
        </span>
      )}
    </div>
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

// NetblockSelect — per-scope IPAM binding (ADR 0010). Empty = the default block. A stale
// binding (a since-removed named block) stays selectable so it's visible, not silently lost.
function NetblockSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const q = useNetblocks()
  const named = (q.data?.netblocks ?? []).filter((b: Netblock) => b.kind === 'named')
  const stale = value && !named.some((b) => b.name === value)
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)} className={cx(FIELD, 'font-mono')}>
      <option value="">Default (the bounded fallback block)</option>
      {named.map((b) => (
        <option key={b.name} value={b.name}>
          {b.name} — {b.cidr}
        </option>
      ))}
      {stale && <option value={value}>{value} (no longer a netblock)</option>}
    </select>
  )
}

function splitList(s: string): string[] {
  return s
    .split(',')
    .map((g) => g.trim())
    .filter(Boolean)
}
