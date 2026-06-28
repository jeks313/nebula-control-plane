import type { ReactNode } from 'react'
import { NavLink } from 'react-router-dom'
import { useMe, useVersion } from '../api/hooks'
import { logout } from '../api/auth'
import { harborEnvironment, isProduction } from '../api/config'
import { cx } from './ui'

const NAV = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/enrollments', label: 'Enrollments', end: false },
  { to: '/devices', label: 'Devices', end: false },
  { to: '/joinkeys', label: 'Join Keys', end: false },
  { to: '/cloudtrust', label: 'Cloud Trust', end: false },
  { to: '/usertrust', label: 'User Trust', end: false },
  { to: '/ipam', label: 'IPAM', end: false },
  { to: '/policy', label: 'Policy', end: false },
  { to: '/releases', label: 'Releases', end: false },
  { to: '/approvals', label: 'Approvals', end: false },
  { to: '/audit', label: 'Audit', end: false },
]

// VersionBadge shows this Harbor's deployed build (CalVer · commit) in the sidebar footer and links
// to the full changelog. The value is baked into the binary, so it always reflects what's running.
function VersionBadge() {
  const v = useVersion()
  return (
    <NavLink
      to="/changelog"
      title={v.data ? `Deployed ${v.data.version} · ${v.data.commit} — full changelog` : 'changelog'}
      className={({ isActive }) =>
        cx(
          'flex items-baseline gap-1.5 rounded-[4px] px-2 py-1 text-[11px] transition-colors',
          isActive ? 'bg-mesh-2 text-ink' : 'text-ink-dim hover:bg-mesh-2 hover:text-ink',
        )
      }
    >
      <span className="font-mono">{v.data ? v.data.version : '…'}</span>
      {v.data?.commit && v.data.commit !== 'none' && (
        <span className="font-mono text-ink-faint">· {v.data.commit}</span>
      )}
    </NavLink>
  )
}

export function Shell({ children }: { children: ReactNode }) {
  const me = useMe()
  // Environment posture comes from the server (injected into index.html), never
  // inferred from the URL. Fail-closed: tint unless the server affirms production.
  const nonProd = !isProduction()
  const envLabel = harborEnvironment()

  return (
    <div className="flex h-full">
      <aside className="flex w-56 shrink-0 flex-col border-r border-edge bg-mesh-1">
        <div className="flex h-12 items-center gap-2 border-b border-edge px-4">
          <span className="inline-block h-2.5 w-2.5 rounded-[2px] bg-permit" aria-hidden />
          <span className="font-semibold tracking-[-0.01em] text-ink">Harbor</span>
        </div>
        <nav className="flex flex-col gap-0.5 p-2">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.end}
              className={({ isActive }) =>
                cx(
                  'rounded-[4px] px-3 py-1.5 text-ink-dim transition-colors',
                  isActive ? 'bg-mesh-2 text-ink' : 'hover:bg-mesh-2 hover:text-ink',
                )
              }
            >
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto p-3">
          <VersionBadge />
          <div className="mt-1 px-2 text-[11px] text-ink-faint">mesh-only console</div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        {nonProd && (
          <div className="flex items-center justify-center gap-2 bg-warn/15 px-4 py-1 text-[12px] text-warn">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-warn" aria-hidden />
            {envLabel === 'development' ? 'Development' : envLabel} environment — not a production control plane
          </div>
        )}
        <header className="flex h-12 shrink-0 items-center justify-between border-b border-edge px-6">
          <div className="text-ink-faint">
            <kbd className="rounded-[4px] border border-edge bg-mesh-2 px-1.5 py-0.5 text-[11px]">⌘K</kbd>
            <span className="ml-2 text-[12px]">search & actions (soon)</span>
          </div>
          <div className="flex items-center gap-3 text-[12px]">
            {me.data ? (
              <>
                <span className="text-ink-dim">
                  {me.data.principal}
                  {me.data.roles.length > 0 && (
                    <span className="ml-1.5 text-ink-faint">[{me.data.roles.join(', ')}]</span>
                  )}
                </span>
                <button
                  onClick={logout}
                  className="rounded-[4px] border border-edge px-2 py-0.5 text-ink-dim hover:bg-mesh-2 hover:text-ink"
                >
                  Sign out
                </button>
              </>
            ) : (
              <span className="text-ink-faint">…</span>
            )}
          </div>
        </header>

        <main className="min-h-0 flex-1 overflow-auto">{children}</main>
      </div>
    </div>
  )
}
