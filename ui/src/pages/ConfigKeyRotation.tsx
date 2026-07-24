import { useConfigKeys, useConfigKeyAdoption, type ConfigKey, type ConfigKeyListResponse } from '../api/hooks'
import { Card, Page, StateBlock, ErrorState, Chip, cx } from '../components/ui'
import { fmtDateTime } from '../lib/format'

// Config-Key Rotation (M8.5) — a read-only view of the config-signing-key rotation lifecycle: which
// key is signing the config bundle, which are trusted (advertised in every bundle's
// config_signing_keys), and any pending signing-key deletion. The config-signing key is a co-equal
// TCB root distinct from the CA; online rotation works the same way (stage → trust → activate →
// drain → retire). The lifecycle actions (stage/activate/retire/schedule key-deletion) are
// deliberately break-glass CLI only; this pane is purely to observe a rotation.

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

export function ConfigKeyRotation() {
  const q = useConfigKeys()

  return (
    <Page
      title="Config-Key Rotation"
      subtitle="The config-signing-key lifecycle and trust bundle — observe a rotation (actions are CLI break-glass)"
    >
      {q.isPending && <StateBlock kind="loading" message="Loading config-signing keys…" />}
      {q.isError && <ErrorState error={q.error} fallback="Couldn't load the config-key rotation state." />}
      {q.data && <ConfigKeyList data={q.data} />}
    </Page>
  )
}

function ConfigKeyList({ data }: { data: ConfigKeyListResponse }) {
  const keys = [...data.config_keys].sort(
    (a, b) => (STATE_ORDER[a.state] ?? 9) - (STATE_ORDER[b.state] ?? 9) || a.name.localeCompare(b.name),
  )
  const trusted = keys.filter((c) => c.trusted).length

  if (keys.length === 0) {
    return (
      <StateBlock
        kind="empty"
        message="No config-signing keys recorded yet — the current key is seeded on Core startup."
      />
    )
  }

  return (
    <div className="flex flex-col gap-5">
      {/* Trust-bundle summary: what every signed bundle currently distributes as config_signing_keys. */}
      <div className="flex flex-wrap items-center gap-2 text-[12px] text-ink-dim">
        <span className="text-ink-faint">Trust bundle:</span>
        <Chip tone="permit">{trusted} key{trusted === 1 ? '' : 's'} trusted fleet-wide</Chip>
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
                {['State', 'Name', 'Fingerprint', 'Backend', 'Created', 'Key deletion'].map((h) => (
                  <th key={h} className="px-4 py-2 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {keys.map((c) => (
                <ConfigKeyRow key={c.id} ck={c} />
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <p className="text-[11px] text-ink-faint">
        Signing cuts over to a newly-activated key with zero downtime once the whole live fleet trusts it; a
        draining key is retired only after 100% adoption of the new active key, and its signing key is deleted
        only after retirement, within a cancellable KMS window.
      </p>
    </div>
  )
}

function ConfigKeyRow({ ck }: { ck: ConfigKey }) {
  const isStaged = ck.state === 'staged'
  return (
    <>
      <tr className={cx('border-b border-edge/60', ck.is_active && 'bg-permit/5')}>
        <td className="px-4 py-2">
          <Chip tone={STATE_TONE[ck.state] ?? 'default'}>{ck.state}</Chip>
          {ck.is_active && <span className="ml-1.5 text-[11px] text-permit">signing</span>}
        </td>
        <td className="px-4 py-2 font-mono text-[12px] text-ink">{ck.name}</td>
        <td className="px-4 py-2 font-mono text-[12px] text-ink-dim" title={ck.fingerprint}>{shortFp(ck.fingerprint)}</td>
        <td className="px-4 py-2 text-[12px]">
          {ck.has_backend ? (
            <span className="text-ink-dim">backend</span>
          ) : (
            <span className="text-ink-faint" title="imported to trust only — no signing backend">trust-only</span>
          )}
        </td>
        <td className="px-4 py-2 text-[12px] text-ink-dim">{ck.created_at ? fmtDateTime(ck.created_at) : '—'}</td>
        <td className="px-4 py-2 text-[12px]">
          {ck.key_deletion ? (
            <span
              className={cx(ck.key_deletion.seconds_remaining <= 0 ? 'text-danger' : 'text-warn')}
              title={`Key destroyed ${fmtDateTime(ck.key_deletion.date)} (KMS window)`}
            >
              ⚠ key del {humanizeRemaining(ck.key_deletion.seconds_remaining)}
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
            <AdoptionBar id={ck.id} />
          </td>
        </tr>
      )}
    </>
  )
}

// AdoptionBar renders the trust-adoption progress for a staged config-signing key — the "trust
// before you sign" gate that must reach 100% of live hosts before `config-key activate` cuts signing
// over.
function AdoptionBar({ id }: { id: number }) {
  const q = useConfigKeyAdoption(id)
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
