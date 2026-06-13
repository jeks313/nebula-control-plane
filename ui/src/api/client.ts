import createClient, { type Middleware } from 'openapi-fetch'
import type { paths } from './schema'
import { ApiError, parseProblem } from './errors'
import { csrfToken } from './auth'

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

// Attach the double-submit CSRF token to every mutating request automatically, so
// future typed mutations (api.POST/PUT/DELETE) are CSRF-correct by construction. The
// server compares the X-CSRF-Token header (constant-time) against the server-side
// session secret — NOT against the cookie — so mirroring the JS-readable harbor_csrf
// cookie into the header is the correct (and required) client behavior. Safe methods
// carry no token (and the server exempts them).
const csrfMiddleware: Middleware = {
  onRequest({ request }) {
    if (!SAFE_METHODS.has(request.method.toUpperCase())) {
      const token = csrfToken()
      if (token) request.headers.set('X-CSRF-Token', token)
    }
    return request
  },
}

// Same-origin typed client for /admin/v1 (the SPA is served by Core via go:embed; in
// `vite dev` the dev server proxies /admin to a local admin-api). Guard `window` so the
// module is import-safe outside a browser (unit tests run in a node environment).
const baseUrl = typeof window !== 'undefined' ? window.location.origin : ''
export const api = createClient<paths>({ baseUrl })
api.use(csrfMiddleware)

// unwrap turns an openapi-fetch result into data, or throws a typed ApiError (parsing
// problem+json, incl. the step-up `code`). Used by both reads and future mutations so
// every error is uniform. It does NOT redirect on 401 — the AuthGate owns auth state,
// so a lost session surfaces as the login screen, not a surprise full-page nav.
export async function unwrap<T>(
  call: Promise<{ data?: T; error?: unknown; response: Response }>,
): Promise<T> {
  const { data, response } = await call
  if (!response.ok) throw await parseProblem(response)
  if (data === undefined) throw new ApiError(response.status, 'empty response')
  return data
}
