import { useState, type ReactNode } from 'react'
import {
  useJoinKeys,
  useCreateJoinKey,
  useRevokeJoinKey,
  useUpdateJoinKey,
  useNetblocks,
  type JoinKey,
  type JoinKeyCreated,
  type JoinKeyUpdate,
  type Netblock,
} from '../api/hooks'
import { usePermissions } from '../api/perms'
import { isApiError, isForbidden, isCentrallyHandled } from '../api/errors'
import { useToast } from '../components/Toast'
import { Card, Page, StateBlock, ErrorState, Button, Chip, cx } from '../components/ui'
import { InstallCommand } from '../components/InstallCommand'
import { Dialog } from '../components/Dialog'
import { fmtDateTime, usesLabel, downloadText } from '../lib/format'

export function JoinKeys() {
  const { can } = usePermissions()
  const mayManage = can('joinkey:manage')
  const q = useJoinKeys()
  const [createOpen, setCreateOpen] = useState(false)
  const keys = q.data?.joinkeys ?? []

  return (
    <Page
      title="Join Keys"
      subtitle="Bootstrap secrets for host enrollment — the secret is shown once at creation"
      actions={mayManage ? <Button variant="primary" onClick={() => setCreateOpen(true)}>Create join key</Button> : undefined}
    >
      <div className="mb-5">
        <InstallCommand method="joinkey" title="Enroll a host with a join key" />
      </div>

      {q.isPending && <StateBlock kind="loading" message="Loading join keys…" />}
      {q.isError && <ErrorState error={q.error} fallback="Couldn't load join keys." />}
      {q.data &&
        (keys.length === 0 ? (
          <StateBlock kind="empty" message="No join keys yet. Create one to let hosts enroll." />
        ) : (
          <Card className="overflow-hidden">
            <table className="w-full text-left">
              <thead className="border-b border-edge text-[11px] uppercase tracking-wide text-ink-faint">
                <tr>
                  {['Name', 'Groups', 'Netblock', 'Mode', 'Uses', 'Rate/hr', 'Expires', 'State', 'Created'].map((h) => (
                    <th key={h} className="px-4 py-2 font-medium">{h}</th>
                  ))}
                  {mayManage && <th className="px-4 py-2 text-right font-medium">Actions</th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-edge">
                {keys.map((k) => (
                  <tr key={k.name} className="hover:bg-mesh-2">
                    <td className="px-4 py-2 font-mono text-[12px] text-ink">{k.name}</td>
                    <td className="px-4 py-2">
                      <span className="flex flex-wrap gap-1">
                        {k.groups.length === 0 ? <span className="text-ink-faint">—</span> : k.groups.map((g) => <Chip key={g}>{g}</Chip>)}
                      </span>
                    </td>
                    <td className="px-4 py-2 font-mono text-[12px]">
                      {k.sub_range ? <span className="text-ink-dim">{k.sub_range}</span> : <span className="text-ink-faint">default</span>}
                    </td>
                    <td className="px-4 py-2">
                      {k.auto_issue ? <Chip tone="warn">auto-issue</Chip> : <span className="text-ink-dim">manual approval</span>}
                      {k.ephemeral && <span className="ml-1"><Chip>ephemeral</Chip></span>}
                    </td>
                    <td className="nums px-4 py-2 text-ink-dim">{usesLabel(k.used_count, k.max_uses)}</td>
                    <td className="nums px-4 py-2 text-ink-dim">{k.quota_per_hour > 0 ? k.quota_per_hour : '—'}</td>
                    <td className="nums px-4 py-2 text-ink-dim">{fmtDateTime(k.expires_at)}</td>
                    <td className="px-4 py-2">
                      {k.state === 'active' ? <span className="text-permit">active</span> : <span className="text-ink-faint">revoked</span>}
                    </td>
                    <td className="nums px-4 py-2 text-ink-faint">{fmtDateTime(k.created_at)}</td>
                    {mayManage && (
                      <td className="px-4 py-2">
                        <div className="flex justify-end gap-2">
                          {k.state === 'active' ? (
                            <>
                              <EditButton k={k} />
                              <RevokeButton name={k.name} />
                            </>
                          ) : (
                            <span className="text-ink-faint">—</span>
                          )}
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        ))}

      {createOpen && <CreateDialog onClose={() => setCreateOpen(false)} />}
    </Page>
  )
}

const FIELD =
  'w-full rounded-[6px] border border-edge bg-mesh-2 px-2 py-1.5 text-[13px] text-ink placeholder:text-ink-faint'

function CreateDialog({ onClose }: { onClose: () => void }) {
  const toast = useToast()
  const create = useCreateJoinKey()
  const [f, setF] = useState<KeyForm>({
    name: '',
    groups: '',
    subRange: '',
    maxUses: '',
    ttlDays: '',
    quotaPerHour: '',
    autoIssue: false,
    ephemeral: false,
  })
  const created = create.data

  function submit() {
    if (!f.name.trim()) {
      toast.notify('Name is required.', 'error')
      return
    }
    create.mutate(
      {
        name: f.name.trim(),
        groups: splitGroups(f.groups),
        sub_range: f.subRange,
        max_uses: numOrZero(f.maxUses),
        ttl_seconds: f.ttlDays ? Math.round(Number(f.ttlDays) * 86_400) : 0,
        quota_per_hour: numOrZero(f.quotaPerHour),
        auto_issue: f.autoIssue,
        ephemeral: f.ephemeral,
      },
      {
        onError: (err) => {
          if (isCentrallyHandled(err)) return // the MutationCache is redirecting; no toast
          toast.notify(createError(err), 'error')
        },
      },
    )
  }

  // After success the create.data carries the one-time secret — switch to the secret
  // modal (the secret lives only in this in-memory mutation state; reset() on close
  // discards it, so a reload loses it by design).
  if (created) return <SecretModal created={created} onClose={() => { create.reset(); onClose() }} />

  return (
    <Dialog
      open
      onClose={onClose}
      title="Create join key"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={create.isPending}>
            {create.isPending ? 'Creating…' : 'Create'}
          </Button>
        </>
      }
    >
      <JoinKeyFields f={f} setF={setF} mode="create" />
    </Dialog>
  )
}

type KeyForm = {
  name: string
  groups: string
  subRange: string // the bound netblock name; '' = the default block (ADR 0010)
  maxUses: string
  ttlDays: string
  quotaPerHour: string
  autoIssue: boolean
  ephemeral: boolean
}

// JoinKeyFields is the shared create/edit form body so the two stay in lockstep. In
// edit mode the name is immutable (path key) and the TTL is "blank = keep".
function JoinKeyFields({
  f,
  setF,
  mode,
  currentExpiry,
}: {
  f: KeyForm
  setF: (f: KeyForm) => void
  mode: 'create' | 'edit'
  currentExpiry?: string
}) {
  const edit = mode === 'edit'
  return (
    <div className="flex flex-col gap-3">
      <Labeled label="Name">
        <input
          autoFocus={!edit}
          disabled={edit}
          value={f.name}
          onChange={(e) => setF({ ...f, name: e.target.value })}
          placeholder="e.g. laptops-2026"
          className={cx(FIELD, edit && 'opacity-60')}
        />
      </Labeled>
      <Labeled label="Groups (comma-separated)">
        <input value={f.groups} onChange={(e) => setF({ ...f, groups: e.target.value })} placeholder="laptops, contractors" className={FIELD} />
      </Labeled>
      <Labeled label="Netblock (where these hosts draw their overlay IP — ADR 0010)">
        <NetblockSelect value={f.subRange} onChange={(v) => setF({ ...f, subRange: v })} />
      </Labeled>
      <div className="grid grid-cols-3 gap-2">
        <Labeled label="Max uses (0 = ∞)">
          <input inputMode="numeric" value={f.maxUses} onChange={(e) => setF({ ...f, maxUses: e.target.value })} placeholder="0" className={FIELD} />
        </Labeled>
        <Labeled label={edit ? 'TTL days (blank = keep)' : 'TTL days (0 = none)'}>
          <input inputMode="numeric" value={f.ttlDays} onChange={(e) => setF({ ...f, ttlDays: e.target.value })} placeholder={edit ? '—' : '0'} className={FIELD} />
        </Labeled>
        <Labeled label="Rate/hr (0 = none)">
          <input inputMode="numeric" value={f.quotaPerHour} onChange={(e) => setF({ ...f, quotaPerHour: e.target.value })} placeholder="0" className={FIELD} />
        </Labeled>
      </div>
      {edit && (
        <p className="text-[11px] text-ink-faint">
          Current expiry: {currentExpiry}. Leave TTL blank to keep it; enter 0 for never.
        </p>
      )}
      <label className="flex items-center gap-2 text-[13px] text-ink">
        <input type="checkbox" checked={f.ephemeral} onChange={(e) => setF({ ...f, ephemeral: e.target.checked })} /> Ephemeral hosts
      </label>
      <label className="flex items-start gap-2 text-[13px] text-ink">
        <input type="checkbox" checked={f.autoIssue} onChange={(e) => setF({ ...f, autoIssue: e.target.checked })} className="mt-0.5" />
        <span>
          Auto-issue certificates
          {f.autoIssue && (
            <span className="mt-1 block text-[12px] text-warn">
              ⚠ Skips per-device approval — any host with this secret is admitted automatically.
            </span>
          )}
        </span>
      </label>
    </div>
  )
}

function EditButton({ k }: { k: JoinKey }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <Button onClick={() => setOpen(true)}>Edit</Button>
      {open && <EditDialog k={k} onClose={() => setOpen(false)} />}
    </>
  )
}

function EditDialog({ k, onClose }: { k: JoinKey; onClose: () => void }) {
  const toast = useToast()
  const update = useUpdateJoinKey()
  const [f, setF] = useState<KeyForm>({
    name: k.name,
    groups: k.groups.join(', '),
    subRange: k.sub_range ?? '',
    maxUses: k.max_uses ? String(k.max_uses) : '',
    ttlDays: '',
    quotaPerHour: k.quota_per_hour ? String(k.quota_per_hour) : '',
    autoIssue: k.auto_issue,
    ephemeral: k.ephemeral,
  })

  function submit() {
    const body: JoinKeyUpdate = {
      groups: splitGroups(f.groups),
      sub_range: f.subRange,
      max_uses: numOrZero(f.maxUses),
      quota_per_hour: numOrZero(f.quotaPerHour),
      auto_issue: f.autoIssue,
      ephemeral: f.ephemeral,
    }
    const ttl = Number(f.ttlDays)
    if (f.ttlDays.trim() !== '' && Number.isFinite(ttl)) {
      body.ttl_seconds = Math.max(0, Math.round(ttl * 86_400)) // 0 = never; blank = unchanged
    }
    update.mutate(
      { name: k.name, body },
      {
        onSuccess: () => {
          toast.notify(`Updated ${k.name}`, 'success')
          onClose()
        },
        onError: (err) => {
          if (isCentrallyHandled(err)) return
          if (isForbidden(err)) {
            toast.notify('You don’t have permission to edit join keys.', 'error')
            return
          }
          toast.notify(isApiError(err) ? err.detail || err.title : 'Update failed.', 'error')
        },
      },
    )
  }

  return (
    <Dialog
      open
      onClose={onClose}
      title={`Edit ${k.name}`}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={update.isPending}>
            {update.isPending ? 'Saving…' : 'Save'}
          </Button>
        </>
      }
    >
      <JoinKeyFields f={f} setF={setF} mode="edit" currentExpiry={k.expires_at ? fmtDateTime(k.expires_at) : 'never'} />
    </Dialog>
  )
}

function SecretModal({ created, onClose }: { created: JoinKeyCreated; onClose: () => void }) {
  const toast = useToast()
  const [ack, setAck] = useState(false)
  return (
    <Dialog
      open
      onClose={() => {}} // gated: dismissal only via Done after acknowledgement (secret is shown once)
      title="Join key created"
      footer={<Button variant="primary" disabled={!ack} onClick={onClose}>Done</Button>}
    >
      <p className="text-[13px] text-warn">Copy this secret now — it is shown once and cannot be retrieved again.</p>
      <div className="mt-3 flex items-center gap-2">
        <code className="flex-1 overflow-x-auto rounded-[6px] border border-edge bg-mesh-2 px-2 py-1.5 font-mono text-[12px] text-ink">
          {created.secret}
        </code>
      </div>
      <div className="mt-2 flex gap-2">
        <Button
          onClick={() => {
            void navigator.clipboard?.writeText(created.secret)
            toast.notify('Secret copied to clipboard', 'success')
          }}
        >
          Copy
        </Button>
        <Button onClick={() => downloadText(`joinkey-${created.joinkey.name}.txt`, secretFile(created))}>Download</Button>
      </div>
      <div className="mt-3">
        <InstallCommand
          method="joinkey"
          env={{ NCP_JOIN_KEY: created.secret }}
          title="Ready-to-run install command (secret inlined)"
        />
      </div>
      <label className="mt-4 flex items-center gap-2 text-[13px] text-ink-dim">
        <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} /> I&rsquo;ve saved this secret
      </label>
    </Dialog>
  )
}

function RevokeButton({ name }: { name: string }) {
  const toast = useToast()
  const revoke = useRevokeJoinKey()
  const [open, setOpen] = useState(false)

  function onRevoke() {
    revoke.mutate(name, {
      onSuccess: () => {
        toast.notify(`Revoked ${name}`, 'info')
        setOpen(false)
      },
      onError: (err) => {
        if (isCentrallyHandled(err)) return // the MutationCache is redirecting; no toast
        // 404 = already revoked/gone; onSettled refetched the list, so treat as done.
        if (isApiError(err) && err.status === 404) {
          toast.notify(`${name} was already revoked`, 'info')
          setOpen(false)
          return
        }
        if (isForbidden(err)) {
          toast.notify('You don’t have permission to revoke join keys.', 'error')
          return
        }
        toast.notify(isApiError(err) ? err.detail || err.title : 'Revoke failed.', 'error')
      },
    })
  }

  return (
    <>
      <Button variant="danger" onClick={() => setOpen(true)}>Revoke</Button>
      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        title={`Revoke ${name}?`}
        footer={
          <>
            <Button onClick={() => setOpen(false)}>Cancel</Button>
            <Button variant="danger" onClick={onRevoke} disabled={revoke.isPending}>Revoke key</Button>
          </>
        }
      >
        <p className="text-[13px] text-ink-dim">
          New hosts can no longer enroll with this key. Certificates already issued are unaffected.
        </p>
      </Dialog>
    </>
  )
}

function Labeled({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className={cx('mb-1 block text-[11px] uppercase tracking-wide text-ink-faint')}>{label}</span>
      {children}
    </label>
  )
}

// NetblockSelect — a dropdown of named netblocks + a "Default" option (value ''), bound
// to the join-key's sub_range (ADR 0010). Empty = the bounded default block. If the
// key's current binding names a block that's since been removed, it's still shown so the
// operator sees (and can fix) the stale binding rather than silently losing it.
function NetblockSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const q = useNetblocks()
  const named = (q.data?.netblocks ?? []).filter((b: Netblock) => b.kind === 'named')
  const knownNames = new Set(named.map((b) => b.name))
  const stale = value && !knownNames.has(value)
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

function splitGroups(s: string): string[] {
  return s
    .split(',')
    .map((g) => g.trim())
    .filter(Boolean)
}

function numOrZero(s: string): number {
  const n = Number(s)
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0
}

function createError(err: unknown): string {
  if (isForbidden(err)) return 'You don’t have permission to create join keys.'
  if (isApiError(err)) {
    if (err.status === 409) return 'A join key with that name already exists.'
    if (err.status === 400) return err.detail || 'Invalid join key.'
    return err.detail || err.title
  }
  return 'Create failed.'
}

function secretFile(c: JoinKeyCreated): string {
  return [
    'Harbor join key',
    `name: ${c.joinkey.name}`,
    `secret: ${c.secret}`,
    `auto_issue: ${c.joinkey.auto_issue}`,
    `created: ${c.joinkey.created_at}`,
    '',
  ].join('\n')
}
