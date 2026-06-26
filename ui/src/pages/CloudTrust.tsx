import { useState, type ReactNode } from 'react'
import { useIsMutating } from '@tanstack/react-query'
import { useCloudTrust, usePutCloudTrust, useNetblocks, type CloudTrust as CloudTrustConfig, type Netblock, type PutConfigResult } from '../api/hooks'
import { usePermissions } from '../api/perms'
import { isApiError, isCentrallyHandled, isForbidden } from '../api/errors'
import { useToast } from '../components/Toast'
import { Card, Page, StateBlock, ErrorState, Button, Chip, cx } from '../components/ui'
import { InstallCommand } from '../components/InstallCommand'
import { Dialog } from '../components/Dialog'

// Cloud Trust — the declarative cloud-attestation config (ADR 0011 Phase 1): which cloud
// principals (AWS accounts/roles today) may attest into the mesh, and the groups +
// auto-issue posture each is granted. Editing is per-account via modal forms (matching
// Join Keys / IPAM): each Add / Edit / Delete reassembles the WHOLE config and republishes
// it via PUT /config/cloudtrust (no per-account patch). A non-privileged change applies
// directly; granting auto_issue is PRIVILEGED and routes to a distinct second approver.
type Account = NonNullable<CloudTrustConfig['aws']>[number]
type PutAccount = { account: string; arn_patterns: string[]; groups: string[]; netblock: string; auto_issue: boolean }

export function CloudTrust() {
  const { can } = usePermissions()
  const mayManage = can('cloudtrust:manage')
  const q = useCloudTrust()
  const cfg = q.data
  const [createOpen, setCreateOpen] = useState(false)
  const [editDefaults, setEditDefaults] = useState(false)
  const accounts = cfg?.aws ?? []
  // Each op republishes the WHOLE config assembled from the current `cfg`, so a new op must
  // not start until the prior PUT AND its refetch land — otherwise it rebuilds from a stale
  // cfg and clobbers the previous change (lost update). `busy` gates every mutating control.
  const mutating = useIsMutating()
  const busy = q.isFetching || mutating > 0

  return (
    <Page
      title="Cloud Trust"
      subtitle="Which cloud accounts may attest into the mesh — and the groups they're granted"
      actions={mayManage && cfg ? <Button variant="primary" disabled={busy} onClick={() => setCreateOpen(true)}>Add account</Button> : undefined}
    >
      {q.isPending && <StateBlock kind="loading" message="Loading cloud-trust config…" />}
      {q.isError && <ErrorState error={q.error} fallback="Couldn't load the cloud-trust config." />}

      {cfg &&
        (!cfg.published && accounts.length === 0 ? (
          <StateBlock
            kind="empty"
            message={mayManage ? 'No cloud-trust config set yet. Use “Add account” to set the first version.' : 'No cloud-trust config set yet.'}
          />
        ) : (
          <div className="flex flex-col gap-4">
            <InstallCommand method="cloud" title="Enroll a cloud instance" />

            <Card className="flex items-center justify-between gap-3 px-4 py-3 text-[13px] text-ink-dim">
              <div>
                Active config v<span className="nums text-ink">{cfg.version}</span>. Default groups granted to every
                attested host:{' '}
                <span className="ml-1 inline-flex flex-wrap gap-1 align-middle">
                  {(cfg.default_groups ?? []).length === 0 ? (
                    <span className="text-ink-faint">none</span>
                  ) : (
                    (cfg.default_groups ?? []).map((g) => <Chip key={g} tone="permit">{g}</Chip>)
                  )}
                </span>
              </div>
              {mayManage && <Button disabled={busy} onClick={() => setEditDefaults(true)}>Edit defaults</Button>}
            </Card>

            <Card className="overflow-hidden">
              <div className="border-b border-edge px-4 py-2 text-[12px] text-ink-faint">Trusted AWS accounts</div>
              {accounts.length === 0 ? (
                <div className="px-4 py-6 text-center text-[13px] text-ink-faint">
                  No accounts yet. Use “Add account” to trust one.
                </div>
              ) : (
                <table className="w-full text-left">
                  <thead className="border-b border-edge text-[11px] uppercase tracking-wide text-ink-faint">
                    <tr>
                      {['Account', 'Allowed roles (ARN)', 'Groups', 'Netblock', 'Admission'].map((h) => (
                        <th key={h} className="px-4 py-2 font-medium">{h}</th>
                      ))}
                      {mayManage && <th className="px-4 py-2 text-right font-medium">Actions</th>}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-edge">
                    {accounts.map((a) => (
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
                        {mayManage && (
                          <td className="px-4 py-2">
                            <div className="flex justify-end gap-2">
                              <EditAccountButton cfg={cfg} account={a} busy={busy} />
                              <DeleteAccountButton cfg={cfg} account={a} busy={busy} />
                            </div>
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Card>
          </div>
        ))}

      {createOpen && cfg && <AccountDialog cfg={cfg} onClose={() => setCreateOpen(false)} />}
      {editDefaults && cfg && <DefaultsDialog cfg={cfg} onClose={() => setEditDefaults(false)} />}
    </Page>
  )
}

const FIELD = 'w-full rounded-[6px] border border-edge bg-mesh-2 px-2 py-1.5 text-[13px] text-ink placeholder:text-ink-faint'

type AccountForm = { account: string; arnPatterns: string; groups: string; netblock: string; autoIssue: boolean }

// otherAccounts normalizes every existing account EXCEPT the one keyed by `exclude` (the
// account id being edited/removed), so the reassembled PUT keeps the rest of the config.
function otherAccounts(cfg: CloudTrustConfig, exclude?: string): PutAccount[] {
  return (cfg.aws ?? [])
    .filter((a) => a.account !== exclude)
    .map((a) => ({
      account: a.account,
      arn_patterns: a.arn_patterns ?? [],
      groups: a.groups ?? [],
      netblock: a.netblock ?? '',
      auto_issue: !!a.auto_issue,
    }))
}

// AccountDialog handles both create (account editable) and edit (account is the immutable
// key). On save it reassembles { default_groups (unchanged), aws } and republishes.
function AccountDialog({ cfg, account, onClose }: { cfg: CloudTrustConfig; account?: Account; onClose: () => void }) {
  const toast = useToast()
  const put = usePutCloudTrust()
  const edit = !!account
  const [f, setF] = useState<AccountForm>({
    account: account?.account ?? '',
    arnPatterns: (account?.arn_patterns ?? []).join(', '),
    groups: (account?.groups ?? []).join(', '),
    netblock: account?.netblock ?? '',
    autoIssue: !!account?.auto_issue,
  })
  const [error, setError] = useState<string | null>(null)
  const risky = f.autoIssue && !f.arnPatterns.trim()

  function submit() {
    setError(null)
    const id = f.account.trim()
    if (!id) {
      setError('AWS account id is required.')
      return
    }
    // Adding a new account must not collide with an existing one (the server rejects dups too).
    if (!edit && (cfg.aws ?? []).some((a) => a.account === id)) {
      setError(`Account ${id} is already trusted — edit the existing entry instead.`)
      return
    }
    const entry: PutAccount = {
      account: id,
      arn_patterns: splitList(f.arnPatterns),
      groups: splitList(f.groups),
      netblock: f.netblock,
      auto_issue: f.autoIssue,
    }
    const aws = edit ? [...otherAccounts(cfg, account!.account), entry] : [...otherAccounts(cfg), entry]
    put.mutate(
      { default_groups: cfg.default_groups ?? [], aws },
      {
        onSuccess: (r) => {
          applyResult(r, toast, edit ? `Updated ${id}` : `Added ${id}`)
          onClose()
        },
        onError: (err) => {
          if (isCentrallyHandled(err)) return // 401 / step-up re-auth handled centrally
          if (isForbidden(err)) {
            setError('You lack the cloudtrust:manage permission.')
            return
          }
          setError(isApiError(err) ? err.detail || err.title : 'Save failed.')
        },
      },
    )
  }

  return (
    <Dialog
      open
      onClose={onClose}
      title={edit ? `Edit account ${account!.account}` : 'Add trusted AWS account'}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={put.isPending}>
            {put.isPending ? 'Saving…' : edit ? 'Save' : 'Add account'}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        {error && <ErrorBox>{error}</ErrorBox>}
        <Labeled label="AWS account id">
          <input
            autoFocus={!edit}
            disabled={edit}
            value={f.account}
            onChange={(e) => setF({ ...f, account: e.target.value })}
            placeholder="111122223333"
            className={cx(FIELD, 'font-mono', edit && 'opacity-60')}
          />
        </Labeled>
        <Labeled label="Allowed roles (ARN globs, comma-separated; empty = any role)">
          <input
            value={f.arnPatterns}
            onChange={(e) => setF({ ...f, arnPatterns: e.target.value })}
            placeholder="arn:aws:sts::111122223333:assumed-role/web-*/*"
            className={cx(FIELD, 'font-mono text-[12px]')}
          />
        </Labeled>
        <Labeled label="Groups granted (comma-separated)">
          <input value={f.groups} onChange={(e) => setF({ ...f, groups: e.target.value })} placeholder="web, servers" className={FIELD} />
        </Labeled>
        <Labeled label="Netblock (overlay IP source — ADR 0010)">
          <NetblockSelect value={f.netblock} onChange={(v) => setF({ ...f, netblock: v })} />
        </Labeled>
        <label className="flex items-start gap-2 text-[13px] text-ink">
          <input type="checkbox" checked={f.autoIssue} onChange={(e) => setF({ ...f, autoIssue: e.target.checked })} className="mt-0.5" />
          <span>
            Auto-issue certificates (skip per-device approval)
            {f.autoIssue && (
              <span className="mt-1 block text-[12px] text-warn">
                ⚠ Privileged change — routes to a distinct second approver before it takes effect.
                {risky && ' With no ARN pattern, every role in this account would be admitted automatically — scope it.'}
              </span>
            )}
          </span>
        </label>
      </div>
    </Dialog>
  )
}

function EditAccountButton({ cfg, account, busy }: { cfg: CloudTrustConfig; account: Account; busy: boolean }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <Button disabled={busy} onClick={() => setOpen(true)}>Edit</Button>
      {open && <AccountDialog cfg={cfg} account={account} onClose={() => setOpen(false)} />}
    </>
  )
}

function DeleteAccountButton({ cfg, account, busy }: { cfg: CloudTrustConfig; account: Account; busy: boolean }) {
  const toast = useToast()
  const put = usePutCloudTrust()
  const [open, setOpen] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const isLast = (cfg.aws ?? []).length <= 1

  function onDelete() {
    setError(null)
    if (isLast) {
      setError('This is the only account. A cloud-trust config must trust at least one account — add another first, or there’s nothing to remove.')
      return
    }
    put.mutate(
      { default_groups: cfg.default_groups ?? [], aws: otherAccounts(cfg, account.account) },
      {
        onSuccess: (r) => {
          applyResult(r, toast, `Removed ${account.account}`)
          setOpen(false)
        },
        onError: (err) => {
          if (isCentrallyHandled(err)) return
          if (isForbidden(err)) {
            setError('You lack the cloudtrust:manage permission.')
            return
          }
          setError(isApiError(err) ? err.detail || err.title : 'Remove failed.')
        },
      },
    )
  }

  return (
    <>
      <Button variant="danger" disabled={busy} onClick={() => setOpen(true)}>Remove</Button>
      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        title={`Remove account ${account.account}?`}
        footer={
          <>
            <Button onClick={() => setOpen(false)}>Cancel</Button>
            <Button variant="danger" onClick={onDelete} disabled={put.isPending}>{put.isPending ? 'Removing…' : 'Remove account'}</Button>
          </>
        }
      >
        <div className="flex flex-col gap-3">
          {error && <ErrorBox>{error}</ErrorBox>}
          <p className="text-[13px] text-ink-dim">
            Hosts attesting from this account can no longer enroll. Certificates already issued are unaffected. This republishes the cloud-trust config.
          </p>
        </div>
      </Dialog>
    </>
  )
}

function DefaultsDialog({ cfg, onClose }: { cfg: CloudTrustConfig; onClose: () => void }) {
  const toast = useToast()
  const put = usePutCloudTrust()
  const [groups, setGroups] = useState((cfg.default_groups ?? []).join(', '))
  const [error, setError] = useState<string | null>(null)

  function submit() {
    setError(null)
    put.mutate(
      { default_groups: splitList(groups), aws: otherAccounts(cfg) },
      {
        onSuccess: (r) => {
          applyResult(r, toast, 'Updated default groups')
          onClose()
        },
        onError: (err) => {
          if (isCentrallyHandled(err)) return
          if (isForbidden(err)) {
            setError('You lack the cloudtrust:manage permission.')
            return
          }
          setError(isApiError(err) ? err.detail || err.title : 'Save failed.')
        },
      },
    )
  }

  return (
    <Dialog
      open
      onClose={onClose}
      title="Edit default groups"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={put.isPending}>{put.isPending ? 'Saving…' : 'Save'}</Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        {error && <ErrorBox>{error}</ErrorBox>}
        <Labeled label="Default groups (granted to every attested host, comma-separated)">
          <input autoFocus value={groups} onChange={(e) => setGroups(e.target.value)} placeholder="fleet" className={FIELD} />
        </Labeled>
        <p className="text-[12px] text-ink-faint">
          Republishes the whole config. Granting a reserved (control-plane) group routes to a second approver.
        </p>
      </div>
    </Dialog>
  )
}

// applyResult — the shared 200-applied vs 202-routed-to-dual-control toast for every PUT.
function applyResult(r: PutConfigResult, toast: ReturnType<typeof useToast>, label: string) {
  if (r.applied) {
    toast.notify(`${label} — cloud-trust config applied (v${r.row.version}).`, 'success')
  } else {
    toast.notify(
      `${label}: this grants privileged access and needs a second approver — submitted as change #${r.change.id}; approve it from Approvals.`,
      'info',
    )
  }
}

function ErrorBox({ children }: { children: ReactNode }) {
  return <div className="rounded-[6px] border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">{children}</div>
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
