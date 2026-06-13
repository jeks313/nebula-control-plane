// Typed admin-API errors. Every Harbor error body is RFC 9457 problem+json
// (application/problem+json) with the minimal shape {title, status, detail?}; only
// the step-up 403 additionally carries a machine `code: "step_up_required"`. We
// parse them all uniformly so the UI can branch on status/code, never on prose.
// (No `type`/`instance` fields are ever emitted by the server — don't rely on them.)

export class ApiError extends Error {
  readonly status: number
  readonly title: string
  readonly detail?: string
  readonly code?: string

  constructor(status: number, title: string, detail?: string, code?: string) {
    super(detail || title || `request failed: ${status}`)
    this.name = 'ApiError'
    this.status = status
    this.title = title
    this.detail = detail
    this.code = code
  }
}

// classifyProblem builds an ApiError from a status + an already-parsed body. This is
// the pure, unit-tested core; it tolerates a non-object body (e.g. a non-JSON 502).
export function classifyProblem(status: number, body: unknown): ApiError {
  const b = body && typeof body === 'object' ? (body as Record<string, unknown>) : {}
  const title = typeof b.title === 'string' ? b.title : `request failed: ${status}`
  const detail = typeof b.detail === 'string' ? b.detail : undefined
  const code = typeof b.code === 'string' ? b.code : undefined
  return new ApiError(status, title, detail, code)
}

// parseProblem reads a problem+json body off a fetch Response (best-effort: a body
// that isn't JSON still yields a typed ApiError carrying the HTTP status).
export async function parseProblem(res: Response): Promise<ApiError> {
  let body: unknown
  try {
    body = await res.clone().json()
  } catch {
    body = undefined // non-JSON error body (proxy/edge failure) — status still useful
  }
  return classifyProblem(res.status, body)
}

export function isApiError(e: unknown): e is ApiError {
  return e instanceof ApiError
}

// A lost/absent session — the AuthGate turns this into the login screen.
export function isUnauthenticated(e: unknown): boolean {
  return isApiError(e) && e.status === 401
}

// The privileged action needs RECENT MFA — re-auth via ?step_up=1 and retry.
export function isStepUpRequired(e: unknown): boolean {
  return isApiError(e) && e.status === 403 && e.code === 'step_up_required'
}

// An RBAC/permission denial — a 403 that is NOT the step-up case (do not retry).
export function isForbidden(e: unknown): boolean {
  return isApiError(e) && e.status === 403 && e.code !== 'step_up_required'
}

// True when the global MutationCache handler (main.tsx) already owns this error —
// a lost session (401) or a step-up requirement — and is redirecting. A per-call
// onError must NOT also surface a toast for these, or it flashes over the login/re-auth.
export function isCentrallyHandled(e: unknown): boolean {
  return isUnauthenticated(e) || isStepUpRequired(e)
}

// A human message for inline rendering: prefer the server's detail, then its title,
// then a caller fallback (used for opaque network failures with no problem body).
export function errorMessage(e: unknown, fallback = 'Something went wrong.'): string {
  if (isApiError(e)) return e.detail || e.title || fallback
  if (e instanceof Error && e.message) return e.message
  return fallback
}
