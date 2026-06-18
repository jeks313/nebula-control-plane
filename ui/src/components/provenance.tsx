import { Chip } from './ui'

export type Provenance = {
  attest_provider?: string
  attest_account?: string
  attest_principal?: string
  attest_region?: string
  join_key_name?: string
  // ephemeral marks a host that joined via an ephemeral join key (shorter cert TTL;
  // foundation for the auto-reaping device lifecycle, impl 2.12). Shown as a small badge.
  ephemeral?: boolean
}

// JoinedVia renders how a host joined the mesh — its attestation site (provider +
// account + region) or the join key it used — consistently on the Devices and
// Enrollments screens. When onFilter is given the provider/account/key are clickable
// to scope the list (Devices); otherwise they are static (Enrollments). `fallback` is
// shown (dim) when there is no provenance — e.g. an enrollment's raw method.
export function JoinedVia({
  p,
  onFilter,
  fallback,
}: {
  p: Provenance
  onFilter?: (key: string, value: string) => void
  fallback?: string
}) {
  // SSO (ADR 0004): the provider-agnostic columns carry provider="sso",
  // account=issuer/realm, principal=email (else subject). Render it as a first-class
  // "SSO — <email> @ <issuer>" so an operator sees WHO SSO-enrolled the host, not just
  // an opaque "sso" tag. The principal (email) is shown inline, not hidden in a tooltip.
  if (p.attest_provider === 'sso') {
    return (
      <span className="flex flex-col gap-0.5">
        <span className="flex items-center gap-1.5">
          {onFilter ? (
            <button onClick={() => onFilter('provider', 'sso')} title="Filter by SSO">
              <Chip tone="permit">SSO</Chip>
            </button>
          ) : (
            <Chip tone="permit">SSO</Chip>
          )}
          {p.attest_principal && <span className="text-[11px] text-ink-dim">{p.attest_principal}</span>}
        </span>
        {p.attest_account &&
          (onFilter ? (
            <button
              onClick={() => onFilter('attest_account', p.attest_account!)}
              className="text-left text-[11px] text-ink-faint hover:text-ink-dim"
              title="Filter by issuer"
            >
              @ {p.attest_account}
            </button>
          ) : (
            <span className="text-[11px] text-ink-faint">@ {p.attest_account}</span>
          ))}
      </span>
    )
  }
  if (p.attest_provider) {
    return (
      <span className="flex flex-col gap-0.5">
        <span className="flex items-center gap-1.5">
          {onFilter ? (
            <button onClick={() => onFilter('provider', p.attest_provider!)} title="Filter by provider">
              <Chip tone="permit">{attestLabel(p.attest_provider)}</Chip>
            </button>
          ) : (
            <Chip tone="permit">{attestLabel(p.attest_provider)}</Chip>
          )}
          {p.attest_account &&
            (onFilter ? (
              <button
                onClick={() => onFilter('attest_account', p.attest_account!)}
                className="nums font-mono text-[11px] text-ink-dim hover:text-ink"
                title={p.attest_principal ? `${p.attest_principal} — filter by account` : 'Filter by account'}
              >
                {p.attest_account}
              </button>
            ) : (
              <span className="nums font-mono text-[11px] text-ink-faint" title={p.attest_principal}>
                {p.attest_account}
              </span>
            ))}
        </span>
        {p.attest_region && <span className="text-[11px] text-ink-faint">{p.attest_region}</span>}
      </span>
    )
  }
  if (p.join_key_name) {
    return (
      <span className="flex items-center gap-1.5">
        <span className="text-[11px] text-ink-faint">token</span>
        {onFilter ? (
          <button onClick={() => onFilter('join_key', p.join_key_name!)} title="Filter by join key">
            <Chip>{p.join_key_name}</Chip>
          </button>
        ) : (
          <Chip>{p.join_key_name}</Chip>
        )}
        {p.ephemeral && <EphemeralBadge />}
      </span>
    )
  }
  return fallback ? <span className="text-ink-dim">{fallback}</span> : <span className="text-ink-faint">—</span>
}

// EphemeralBadge marks a host that joined via an ephemeral join key — it holds a
// short-lived cert (Config.EphemeralCertTTL) and is the foundation for the auto-reaping
// device lifecycle (impl 2.12, still future). Uses the warn tone so it reads as a
// transient/short-lived hint, mirroring the existing join-key chip styling.
function EphemeralBadge() {
  return (
    <span title="Joined via an ephemeral join key — short-lived cert (auto-reaping is future, impl 2.12)">
      <Chip tone="warn">ephemeral</Chip>
    </span>
  )
}

export function attestLabel(provider?: string): string {
  if (provider === 'aws') return 'AWS'
  if (provider === 'azure') return 'Azure'
  if (provider === 'gcp') return 'GCP'
  return provider || 'attested'
}
