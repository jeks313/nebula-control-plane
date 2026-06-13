import { useQuery } from '@tanstack/react-query'
import { fetchProviders, providerLabel, redirectToLogin, currentReturnTo } from '../api/auth'
import { Card, StateBlock } from '../components/ui'

// The unauthenticated landing screen. It discovers the configured login methods from
// the server (/admin/v1/auth/providers) and renders one button each; clicking does a
// full-page redirect into the server's session login (OIDC/SAML/GitHub), returning to
// where the user was. The SPA holds no credentials — it only kicks off the flow.
export function Login() {
  const providers = useQuery({
    queryKey: ['auth-providers'],
    queryFn: fetchProviders,
    staleTime: 60_000,
  })
  const list = providers.data ?? []
  const returnTo = currentReturnTo()

  return (
    <div className="mesh-grid flex h-full items-center justify-center p-6">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center gap-2">
          <span className="inline-block h-3 w-3 rounded-[2px] bg-permit" aria-hidden />
          <span className="text-[18px] font-semibold tracking-[-0.01em] text-ink">Harbor</span>
        </div>
        <Card className="p-5">
          <h1 className="text-[16px] font-semibold text-ink">Sign in</h1>
          <p className="mt-1 text-[12px] text-ink-dim">
            Mesh-only control plane. Authenticate to continue.
          </p>
          <div className="mt-4 flex flex-col gap-2">
            {providers.isPending ? (
              <StateBlock kind="loading" message="Loading sign-in options…" />
            ) : list.length > 0 ? (
              list.map((name) => (
                <button
                  key={name}
                  onClick={() => redirectToLogin({ provider: name, returnTo })}
                  className="rounded-[6px] border border-edge bg-mesh-2 px-3 py-2 text-[13px] text-ink hover:border-permit/60 hover:bg-mesh-2/70"
                >
                  {providerLabel(name)}
                </button>
              ))
            ) : (
              // No discovery (older server, or none enumerated) → let the server pick
              // its default provider.
              <button
                onClick={() => redirectToLogin({ returnTo })}
                className="rounded-[6px] border border-edge bg-mesh-2 px-3 py-2 text-[13px] text-ink hover:border-permit/60 hover:bg-mesh-2/70"
              >
                Sign in
              </button>
            )}
          </div>
        </Card>
      </div>
    </div>
  )
}
