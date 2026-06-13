import type { ReactNode } from 'react'
import { useMe } from '../api/hooks'
import { isUnauthenticated, errorMessage } from '../api/errors'
import { Login } from '../pages/Login'

// AuthGate is the SPA's single, authority-free auth boundary. It renders the app ONLY
// for an authenticated session, driven entirely by /me (the server is the source of
// truth — never inferred from the URL). While /me is in flight it shows a neutral
// splash (never the authed chrome, so an unauthenticated visitor sees no flash); a 401
// shows the login screen; any other failure to reach /me is an honest "can't reach
// Core" error, not a login bounce.
export function AuthGate({ children }: { children: ReactNode }) {
  const me = useMe()

  if (me.isPending) return <Splash />
  if (me.isError) {
    if (isUnauthenticated(me.error)) return <Login />
    return <Splash error={me.error} />
  }
  return <>{children}</>
}

function Splash({ error }: { error?: unknown }) {
  return (
    <div className="mesh-grid flex h-full items-center justify-center p-6">
      <div className="max-w-sm text-center">
        <span className="mx-auto mb-3 inline-block h-3 w-3 rounded-[2px] bg-permit" aria-hidden />
        {error ? (
          <>
            <div className="text-ink">Can&rsquo;t reach Core</div>
            <div className="mt-1 text-[12px] text-ink-dim">
              {errorMessage(error, 'The mesh may be down — see the break-glass runbook.')}
            </div>
            <button
              onClick={() => window.location.reload()}
              className="mt-4 rounded-[4px] border border-edge px-3 py-1 text-[12px] text-ink-dim hover:bg-mesh-2 hover:text-ink"
            >
              Retry
            </button>
          </>
        ) : (
          <div className="text-ink-dim">Loading…</div>
        )}
      </div>
    </div>
  )
}
