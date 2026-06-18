import { useMemo, useState, type ReactNode } from 'react'
import {
  useNetblocks,
  useNetblockSuggest,
  useCreateNetblock,
  useUpdateNetblock,
  useDeleteNetblock,
  useJoinKeys,
  useCloudTrust,
  type Netblock,
} from '../api/hooks'
import { usePermissions } from '../api/perms'
import { isApiError, isForbidden, isCentrallyHandled } from '../api/errors'
import { useToast } from '../components/Toast'
import { Card, Page, StateBlock, ErrorState, Button, Chip, cx } from '../components/ui'
import { Dialog } from '../components/Dialog'
import { fmtDateTime } from '../lib/format'
import {
  parseCidr,
  poolExtent,
  overlaySegments,
  utilizationTone,
  type Cidr,
  type SegmentColor,
} from '../lib/ipam'

const FIELD =
  'w-full rounded-[6px] border border-edge bg-mesh-2 px-2 py-1.5 text-[13px] text-ink placeholder:text-ink-faint'

// IPAM — ADR 0010 named netblocks. The pool's address space (central / default / named
// carves) is operator-managed and visualized; each named carve binds join sources to a
// CIDR. Mutations are gated on ipam:manage (server also requires step-up MFA).
export function IPAM() {
  const { can } = usePermissions()
  const mayManage = can('ipam:manage')
  const q = useNetblocks()
  const joinkeys = useJoinKeys()
  const cloudtrust = useCloudTrust()
  const [createOpen, setCreateOpen] = useState(false)

  const blocks = q.data?.netblocks ?? []
  // Derive "bound sources" client-side: a join-key's sub_range or a cloud-trust scope's
  // netblock that names this block. The API doesn't surface bindings on the netblock, so
  // we join the two existing lists here (D19).
  const bindings = useMemo(() => boundSources(joinkeys.data?.joinkeys, cloudtrust.data), [joinkeys.data, cloudtrust.data])

  return (
    <Page
      title="IPAM"
      subtitle="Named netblocks carved from the mesh pool — related hosts cluster by join source"
      actions={mayManage ? <Button variant="primary" onClick={() => setCreateOpen(true)}>Carve netblock</Button> : undefined}
    >
      {q.isPending && <StateBlock kind="loading" message="Loading netblocks…" />}
      {q.isError && <ErrorState error={q.error} fallback="Couldn't load netblocks." />}
      {q.data &&
        (blocks.length === 0 ? (
          <StateBlock kind="empty" message="No netblocks yet. Genesis seeds central + default; carve named blocks here." />
        ) : (
          <div className="flex flex-col gap-5">
            <Card className="overflow-hidden">
              <table className="w-full text-left">
                <thead className="border-b border-edge text-[11px] uppercase tracking-wide text-ink-faint">
                  <tr>
                    {['Name', 'CIDR', 'Kind', 'Bound sources', 'Capacity', 'Allocated', 'Utilization'].map((h) => (
                      <th key={h} className="px-4 py-2 font-medium">{h}</th>
                    ))}
                    {mayManage && <th className="px-4 py-2 text-right font-medium">Actions</th>}
                  </tr>
                </thead>
                <tbody className="divide-y divide-edge">
                  {blocks.map((b) => (
                    <NetblockRow key={b.name} b={b} sources={bindings.get(b.name) ?? []} mayManage={mayManage} />
                  ))}
                </tbody>
              </table>
            </Card>
          </div>
        ))}

      {createOpen && <CreateDialog blocks={blocks} onClose={() => setCreateOpen(false)} />}
    </Page>
  )
}

function NetblockRow({ b, sources, mayManage }: { b: Netblock; sources: string[]; mayManage: boolean }) {
  const tone = utilizationTone(b.pct)
  return (
    <tr className="align-top hover:bg-mesh-2">
      <td className="px-4 py-2 font-mono text-[12px] text-ink">{b.name}</td>
      <td className="nums px-4 py-2 font-mono text-[12px] text-ink-dim">{b.cidr}</td>
      <td className="px-4 py-2"><KindChip kind={b.kind} protectedBlock={b.protected} /></td>
      <td className="px-4 py-2">
        <span className="flex flex-wrap gap-1">
          {sources.length === 0 ? (
            <span className="text-ink-faint">{b.kind === 'default' ? 'unbound fallback' : '—'}</span>
          ) : (
            sources.map((s) => <Chip key={s}>{s}</Chip>)
          )}
        </span>
      </td>
      <td className="nums px-4 py-2 text-ink-dim">{b.capacity.toLocaleString()}</td>
      <td className="nums px-4 py-2 text-ink-dim">{b.allocated.toLocaleString()}</td>
      <td className="px-4 py-2">
        <div className="flex items-center gap-2">
          <UtilBar pct={b.pct} tone={tone} />
          <span className={cx('nums w-12 text-right text-[12px]', toneText(tone))}>{b.pct.toFixed(1)}%</span>
        </div>
      </td>
      {mayManage && (
        <td className="px-4 py-2">
          <div className="flex justify-end gap-2">
            {b.protected ? (
              <span className="text-[12px] text-ink-faint" title="Seeded at genesis — protected from edit/remove">protected</span>
            ) : (
              <>
                <EditButton b={b} />
                <DeleteButton b={b} />
              </>
            )}
          </div>
        </td>
      )}
    </tr>
  )
}

function KindChip({ kind, protectedBlock }: { kind: Netblock['kind']; protectedBlock: boolean }) {
  if (kind === 'reserved') return <Chip tone="warn">reserved{protectedBlock ? ' · central' : ''}</Chip>
  if (kind === 'default') return <Chip tone="permit">default</Chip>
  return <Chip>named</Chip>
}

function toneText(tone: 'permit' | 'warn' | 'danger'): string {
  return tone === 'danger' ? 'text-danger' : tone === 'warn' ? 'text-warn' : 'text-ink-dim'
}

// UtilBar — the per-netblock allocated-utilization bar (utilization axis: red>90/yellow>75).
function UtilBar({ pct, tone }: { pct: number; tone: 'permit' | 'warn' | 'danger' }) {
  const bg = tone === 'danger' ? 'bg-danger' : tone === 'warn' ? 'bg-warn' : 'bg-permit'
  return (
    <div className="h-2 w-32 overflow-hidden rounded-full bg-mesh-2">
      <div className={cx('h-full rounded-full', bg)} style={{ width: `${Math.max(0, Math.min(100, pct))}%` }} />
    </div>
  )
}

// ── the growth-envelope overlay (create selector) ───────────────────────────────────

const SEG_BG: Record<SegmentColor, string> = {
  green: 'bg-ipam-green',
  purple: 'bg-ipam-purple',
  red: 'bg-ipam-red',
  yellow: 'bg-ipam-yellow',
}

// AddressMap — a horizontal proportional address-bar of the whole pool, colored by the
// growth-envelope semantics (green/purple/red/yellow). The pending carve (if any) is
// overlaid as purple with its own red/yellow envelope so the operator sees exactly what
// they're about to claim. A guide only — the server re-validates the actual /P on submit.
function AddressMap({ pool, blocks, pending }: { pool: Cidr; blocks: Netblock[]; pending: Cidr | null }) {
  const segments = useMemo(() => {
    const carves = blocks
      .map((b) => {
        const c = parseCidr(b.cidr)
        return c ? { cidr: c, name: b.name, growable: b.kind === 'named' } : null
      })
      .filter((x): x is { cidr: Cidr; name: string; growable: boolean } => x !== null)
    return overlaySegments({ pool, blocks: carves, pending: pending ? { cidr: pending } : null })
  }, [pool, blocks, pending])

  const total = 2 ** (32 - pool.bits)
  return (
    <div className="flex flex-col gap-2">
      <div className="flex h-8 w-full overflow-hidden rounded-[4px] border border-edge">
        {segments.map((s, i) => {
          const widthPct = (s.size / total) * 100
          const title = `${segColorLabel(s.color)} — /${s.bits}${s.label ? ` (${s.label})` : ''}`
          return (
            <div
              key={`${s.base}-${i}`}
              className={cx(SEG_BG[s.color], 'flex items-center justify-center overflow-hidden')}
              style={{ width: `${widthPct}%` }}
              title={title}
            >
              {s.label && widthPct > 6 && (
                <span className="truncate px-1 text-[10px] font-medium text-black/80">{s.label}</span>
              )}
            </div>
          )
        })}
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-ink-dim">
        <Legend color="green" label="free + clear (suggested)" />
        <Legend color="purple" label="carved block" />
        <Legend color="red" label="doubling buddy (caps growth)" />
        <Legend color="yellow" label="growth envelope" />
      </div>
    </div>
  )
}

function segColorLabel(c: SegmentColor): string {
  return c === 'green' ? 'free + clear' : c === 'purple' ? 'carved' : c === 'red' ? 'doubling buddy' : 'growth envelope'
}

function Legend({ color, label }: { color: SegmentColor; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={cx('inline-block h-2.5 w-2.5 rounded-[2px]', SEG_BG[color])} aria-hidden />
      {label}
    </span>
  )
}

// ── create ──────────────────────────────────────────────────────────────────────────

function CreateDialog({ blocks, onClose }: { blocks: Netblock[]; onClose: () => void }) {
  const toast = useToast()
  const create = useCreateNetblock()
  const pool = useMemo(() => poolExtent(blocks), [blocks])

  const [name, setName] = useState('')
  const [prefix, setPrefix] = useState(24)
  // cidr is the actual carve. It tracks the suggestion until the operator overrides it
  // (then `overridden` pins their value through subsequent suggestion changes).
  const [cidr, setCidr] = useState('')
  const [overridden, setOverridden] = useState(false)
  const [description, setDescription] = useState('')

  const suggest = useNetblockSuggest(prefix)
  // When not overridden, mirror the server's growth-aware suggestion into the field.
  const effectiveCidr = overridden ? cidr : suggest.data?.cidr ?? cidr
  const pendingParsed = parseCidr(effectiveCidr)

  function submit() {
    if (!name.trim()) {
      toast.notify('Name is required.', 'error')
      return
    }
    if (!effectiveCidr.trim() || !pendingParsed) {
      toast.notify('Enter a valid CIDR (e.g. 10.44.20.0/24).', 'error')
      return
    }
    create.mutate(
      { name: name.trim(), cidr: effectiveCidr.trim(), description: description.trim() },
      {
        onSuccess: (b) => {
          toast.notify(`Carved ${b.name} (${b.cidr})`, 'success')
          onClose()
        },
        onError: (err) => {
          if (isCentrallyHandled(err)) return // step-up re-auth handled centrally
          toast.notify(createError(err), 'error')
        },
      },
    )
  }

  return (
    <Dialog
      open
      onClose={onClose}
      title="Carve a netblock"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={create.isPending}>
            {create.isPending ? 'Carving…' : 'Carve netblock'}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <Labeled label="Name">
          <input autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. office-vpn" className={FIELD} />
        </Labeled>

        <Labeled label="Size (prefix length)">
          <div className="flex items-center gap-3">
            <input
              type="range"
              min={16}
              max={30}
              value={prefix}
              onChange={(e) => {
                setPrefix(Number(e.target.value))
                setOverridden(false) // a new size re-pulls the suggestion
              }}
              className="flex-1"
            />
            <span className="nums w-20 text-right text-[13px] text-ink">
              /{prefix}
              <span className="ml-1 text-ink-faint">({hostsForPrefix(prefix)})</span>
            </span>
          </div>
        </Labeled>

        <Labeled label="CIDR (pre-filled by the growth-aware suggester; override allowed)">
          <input
            value={effectiveCidr}
            onChange={(e) => {
              setCidr(e.target.value)
              setOverridden(true)
            }}
            placeholder={suggest.isFetching ? 'computing suggestion…' : '10.44.20.0/24'}
            className={cx(FIELD, 'font-mono')}
          />
          {suggest.isError && (
            <span className="mt-1 block text-[12px] text-warn">
              {isApiError(suggest.error) && suggest.error.status === 409
                ? 'No free slot of this size in the pool — pick a smaller size or override.'
                : 'Couldn’t compute a suggestion; enter a CIDR manually.'}
            </span>
          )}
          {overridden && (
            <button
              className="mt-1 text-[12px] text-permit hover:underline"
              onClick={() => setOverridden(false)}
            >
              ↺ Use the suggested placement
            </button>
          )}
        </Labeled>

        <div>
          <span className="mb-1.5 block text-[11px] uppercase tracking-wide text-ink-faint">Pool address map</span>
          {pool ? (
            <AddressMap pool={pool} blocks={blocks} pending={pendingParsed} />
          ) : (
            <p className="text-[12px] text-ink-faint">No pool extent yet (genesis seeds central + default).</p>
          )}
        </div>

        <Labeled label="Description (optional)">
          <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="what joins here" className={FIELD} />
        </Labeled>

        <p className="text-[11px] text-ink-faint">
          The map is a guide. The carve is the exact CIDR above; the server enforces non-overlap, the pool bounds, and the
          fixed central/default blocks on submit.
        </p>
      </div>
    </Dialog>
  )
}

// ── edit ────────────────────────────────────────────────────────────────────────────

function EditButton({ b }: { b: Netblock }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <Button onClick={() => setOpen(true)}>Edit</Button>
      {open && <EditDialog b={b} onClose={() => setOpen(false)} />}
    </>
  )
}

function EditDialog({ b, onClose }: { b: Netblock; onClose: () => void }) {
  const toast = useToast()
  const update = useUpdateNetblock()
  const [cidr, setCidr] = useState(b.cidr)
  const [description, setDescription] = useState(b.description ?? '')

  function submit() {
    if (!parseCidr(cidr)) {
      toast.notify('Enter a valid CIDR (e.g. 10.44.20.0/24).', 'error')
      return
    }
    update.mutate(
      { name: b.name, body: { cidr, description } },
      {
        onSuccess: () => {
          toast.notify(`Updated ${b.name}`, 'success')
          onClose()
        },
        onError: (err) => {
          if (isCentrallyHandled(err)) return
          if (isForbidden(err)) {
            toast.notify('You don’t have permission to edit netblocks.', 'error')
            return
          }
          if (isApiError(err) && err.status === 422) {
            toast.notify('That range would strand live allocations — reclaim those hosts first.', 'error')
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
      title={`Edit ${b.name}`}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={update.isPending}>
            {update.isPending ? 'Saving…' : 'Save'}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <Labeled label="CIDR">
          <input value={cidr} onChange={(e) => setCidr(e.target.value)} className={cx(FIELD, 'font-mono')} />
        </Labeled>
        <Labeled label="Description">
          <input value={description} onChange={(e) => setDescription(e.target.value)} className={FIELD} />
        </Labeled>
        <p className="text-[11px] text-ink-faint">
          Carved {fmtDateTime(b.created_at)}
          {b.created_by ? ` by ${b.created_by}` : ''}. An edit that would strand live allocations is refused.
        </p>
      </div>
    </Dialog>
  )
}

// ── delete ──────────────────────────────────────────────────────────────────────────

function DeleteButton({ b }: { b: Netblock }) {
  const toast = useToast()
  const del = useDeleteNetblock()
  const [open, setOpen] = useState(false)

  function onDelete() {
    del.mutate(b.name, {
      onSuccess: () => {
        toast.notify(`Removed ${b.name}`, 'info')
        setOpen(false)
      },
      onError: (err) => {
        if (isCentrallyHandled(err)) return
        if (isApiError(err) && err.status === 404) {
          toast.notify(`${b.name} was already removed`, 'info')
          setOpen(false)
          return
        }
        if (isForbidden(err)) {
          toast.notify('You don’t have permission to remove netblocks.', 'error')
          return
        }
        if (isApiError(err) && (err.status === 409 || err.status === 422)) {
          toast.notify('Can’t remove — the block is protected or has live allocations.', 'error')
          return
        }
        toast.notify(isApiError(err) ? err.detail || err.title : 'Remove failed.', 'error')
      },
    })
  }

  return (
    <>
      <Button variant="danger" onClick={() => setOpen(true)}>Remove</Button>
      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        title={`Remove ${b.name}?`}
        footer={
          <>
            <Button onClick={() => setOpen(false)}>Cancel</Button>
            <Button variant="danger" onClick={onDelete} disabled={del.isPending}>Remove netblock</Button>
          </>
        }
      >
        <p className="text-[13px] text-ink-dim">
          Frees {b.cidr} back to the pool. Refused if any host still holds an address in this block — reclaim those first.
          Join sources bound to it fall back to <span className="text-ink">default</span>.
        </p>
      </Dialog>
    </>
  )
}

// ── helpers ───────────────────────────────────────────────────────────────────────────

function Labeled({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-[11px] uppercase tracking-wide text-ink-faint">{label}</span>
      {children}
    </label>
  )
}

function hostsForPrefix(prefix: number): string {
  const hosts = 2 ** (32 - prefix) - 1
  return `${hosts.toLocaleString()} host${hosts === 1 ? '' : 's'}`
}

function createError(err: unknown): string {
  if (isForbidden(err)) return 'You don’t have permission to carve netblocks.'
  if (isApiError(err)) {
    if (err.status === 409) return err.detail || 'That CIDR overlaps an existing netblock, or the name is taken.'
    if (err.status === 400) return err.detail || 'Invalid netblock.'
    return err.detail || err.title
  }
  return 'Carve failed.'
}

// boundSources maps each netblock NAME to the join sources bound to it (join-key
// sub_range, cloud-trust scope netblock). The API doesn't surface bindings on the
// netblock row, so we derive them from the two existing lists (D19).
function boundSources(
  joinkeys: { name: string; sub_range?: string; state?: string }[] | undefined,
  cloudtrust: { aws?: { account: string; netblock?: string }[] } | undefined,
): Map<string, string[]> {
  const m = new Map<string, string[]>()
  const add = (block: string, source: string) => {
    if (!block) return
    const cur = m.get(block) ?? []
    cur.push(source)
    m.set(block, cur)
  }
  for (const k of joinkeys ?? []) {
    if (k.state === 'revoked') continue
    if (k.sub_range) add(k.sub_range, `key:${k.name}`)
  }
  for (const a of cloudtrust?.aws ?? []) {
    if (a.netblock) add(a.netblock, `aws:${a.account}`)
  }
  return m
}
