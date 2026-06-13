import createClient from 'openapi-fetch'
import type { paths } from './schema'

// Same-origin typed client for /admin/v1 (the SPA is served by Core via go:embed;
// in `vite dev` the dev server proxies /admin to a local admin-api). Mutations will
// carry the double-submit CSRF header (added when we build write actions).
export const api = createClient<paths>({ baseUrl: window.location.origin })

// The SPA holds no authority: on 401 it hands off to the server's session login
// (OIDC/SAML/mock IdP → httpOnly cookie), returning to where the user was.
export function loginRedirect(): void {
  const here = window.location.pathname + window.location.search
  window.location.href = `/admin/v1/auth/login?return_to=${encodeURIComponent(here)}`
}

export function logout(): void {
  const csrf = readCookie('harbor_csrf')
  void fetch('/admin/v1/auth/logout', {
    method: 'POST',
    headers: csrf ? { 'X-CSRF-Token': csrf } : {},
    credentials: 'same-origin',
  }).finally(() => loginRedirect())
}

function readCookie(name: string): string {
  const m = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'))
  return m ? decodeURIComponent(m[1]) : ''
}
