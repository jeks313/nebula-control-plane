// Hand-built admin-auth URLs + browser navigations. The /admin/v1/auth/* routes are
// deliberately NOT in the OpenAPI surface — they are browser-redirect endpoints, not
// JSON resources. The SPA holds NO authority (P-UI-1): it only ever NAVIGATES the
// browser to them; the server owns the session (httpOnly cookie), provider choice,
// and return_to validation. We mirror that validation here as defense in depth.

const AUTH_BASE = '/admin/v1/auth'

// safeReturnPath mirrors the server's safeReturnTo (the server RE-validates; this just
// avoids ever building an off-origin redirect): a same-origin PATH only. A backslash
// or control char (browsers fold "\" into host confusion) or "//" (protocol-relative)
// or any non-"/"-leading value collapses to "/".
export function safeReturnPath(path: string): string {
  if (!path || path[0] !== '/') return '/'
  if (path.startsWith('//')) return '/'
  // eslint-disable-next-line no-control-regex
  if (/[\\\x00-\x1f]/.test(path)) return '/'
  return path
}

export function currentReturnTo(): string {
  return safeReturnPath(window.location.pathname + window.location.search)
}

// loginUrl builds the server login redirect. provider omitted => the server default
// (first configured). stepUp => force fresh MFA (OIDC prompt=login&max_age=0, SAML
// ForceAuthn; GitHub has no MFA signal and ignores it, by design).
export function loginUrl(opts: { provider?: string; returnTo?: string; stepUp?: boolean } = {}): string {
  const p = new URLSearchParams()
  if (opts.provider) p.set('provider', opts.provider)
  p.set('return_to', safeReturnPath(opts.returnTo ?? '/'))
  if (opts.stepUp) p.set('step_up', '1')
  return `${AUTH_BASE}/login?${p.toString()}`
}

// csrfTokenFrom extracts the JS-readable harbor_csrf cookie value (pure; testable).
// This runs on every mutation (the CSRF middleware), so it must NEVER throw: a
// malformed percent sequence falls back to the raw value rather than a URIError that
// would reject the request opaquely (the server validates the token anyway, so a bad
// value just yields a clean CSRF 403 through the normal error path).
export function csrfTokenFrom(cookie: string): string {
  const m = cookie.match(/(?:^|;\s*)harbor_csrf=([^;]*)/)
  if (!m) return ''
  try {
    return decodeURIComponent(m[1])
  } catch {
    return m[1]
  }
}

export function csrfToken(): string {
  return csrfTokenFrom(document.cookie)
}

// Human-friendly labels for the known provider names (the discovery endpoint returns
// bare names; presentation lives client-side).
const PROVIDER_LABELS: Record<string, string> = {
  oidc: 'Sign in with SSO',
  github: 'Sign in with GitHub',
  saml: 'Sign in with SSO (SAML)',
  mock: 'Sign in (dev mock IdP)',
}

export function providerLabel(name: string): string {
  return PROVIDER_LABELS[name] ?? `Sign in with ${name}`
}

// ---- runtime navigations (full-page; never fetch — these are 302 redirect flows) ----

export function redirectToLogin(opts: { provider?: string; returnTo?: string } = {}): void {
  window.location.href = loginUrl({ provider: opts.provider, returnTo: opts.returnTo ?? currentReturnTo() })
}

// redirectToStepUp re-authenticates with fresh MFA and returns to where the user was,
// so a privileged action can be retried after step-up.
export function redirectToStepUp(returnTo?: string): void {
  window.location.href = loginUrl({ stepUp: true, returnTo: returnTo ?? currentReturnTo() })
}

interface ProvidersBody {
  providers?: unknown
}

// fetchProviders returns the configured login methods (first = default). On any
// failure it returns [] so the Login page falls back to a single server-default
// "Sign in" button — never a blank screen.
export async function fetchProviders(): Promise<string[]> {
  try {
    const res = await fetch(`${AUTH_BASE}/providers`, {
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
    })
    if (!res.ok) return []
    const body = (await res.json()) as ProvidersBody
    return Array.isArray(body.providers) ? body.providers.filter((p): p is string => typeof p === 'string') : []
  } catch {
    return []
  }
}

// logout: POST (no CSRF required — it's mounted outside the CSRF wrapper) to revoke the server
// session + clear the cookies, THEN reload at the SPA root. AuthGate's /me then 401s (session gone)
// and renders <Login/> with manual Sign in buttons. Do NOT redirect to loginUrl() — that hits the
// server login endpoint, which immediately re-initiates SSO (Entra silently re-authenticates since
// there's no SLO) and lands the user straight back in — the "signout just refreshes and comes back"
// bug. window.location forces a full reload so in-memory auth state is dropped too.
export async function logout(): Promise<void> {
  try {
    await fetch(`${AUTH_BASE}/logout`, { method: 'POST', credentials: 'same-origin' })
  } finally {
    window.location.href = '/'
  }
}
