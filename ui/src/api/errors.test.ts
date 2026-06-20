import { describe, it, expect } from 'vitest'
import {
  ApiError,
  classifyProblem,
  isApiError,
  isUnauthenticated,
  isStepUpRequired,
  isForbidden,
  errorMessage,
} from './errors'

describe('classifyProblem', () => {
  it('parses a full problem+json body', () => {
    const e = classifyProblem(403, {
      title: 'step-up required',
      status: 403,
      detail: 'reauth and retry',
      code: 'step_up_required',
    })
    expect(e).toBeInstanceOf(ApiError)
    expect(e.status).toBe(403)
    expect(e.title).toBe('step-up required')
    expect(e.detail).toBe('reauth and retry')
    expect(e.code).toBe('step_up_required')
  })

  it('tolerates a non-object body (non-JSON 5xx)', () => {
    const e = classifyProblem(502, 'gateway boom')
    expect(e.status).toBe(502)
    expect(e.title).toBe('request failed: 502')
    expect(e.detail).toBeUndefined()
    expect(e.code).toBeUndefined()
  })

  it('ignores non-string fields', () => {
    const e = classifyProblem(400, { title: 123, detail: {}, code: [] })
    expect(e.title).toBe('request failed: 400')
    expect(e.detail).toBeUndefined()
    expect(e.code).toBeUndefined()
  })
})

describe('error classifiers', () => {
  const stepUp = classifyProblem(403, { title: 'step-up required', code: 'step_up_required' })
  const rbac = classifyProblem(403, { title: 'forbidden', detail: 'requires permission: policy:manage' })
  const unauth = classifyProblem(401, { title: 'unauthenticated' })
  const csrf = classifyProblem(403, { title: 'csrf' })

  it('distinguishes step-up from a plain RBAC 403', () => {
    expect(isStepUpRequired(stepUp)).toBe(true)
    expect(isForbidden(stepUp)).toBe(false) // step-up is recoverable, not an RBAC denial
    expect(isStepUpRequired(rbac)).toBe(false)
    expect(isForbidden(rbac)).toBe(true)
    expect(isStepUpRequired(csrf)).toBe(false) // a non-step-up 403 is never step-up
  })

  it('detects unauthenticated', () => {
    expect(isUnauthenticated(unauth)).toBe(true)
    expect(isUnauthenticated(stepUp)).toBe(false)
    expect(isUnauthenticated(rbac)).toBe(false)
  })

  it('guards non-ApiError values', () => {
    expect(isApiError(new Error('x'))).toBe(false)
    expect(isUnauthenticated(null)).toBe(false)
    expect(isStepUpRequired('nope')).toBe(false)
    expect(isForbidden(undefined)).toBe(false)
  })
})

describe('errorMessage', () => {
  it('prefers detail, then title, then fallback', () => {
    expect(errorMessage(classifyProblem(403, { title: 'forbidden', detail: 'requires permission: x' }))).toBe(
      'requires permission: x',
    )
    expect(errorMessage(classifyProblem(403, { title: 'forbidden' }))).toBe('forbidden')
    expect(errorMessage(new Error(''), 'fallback')).toBe('fallback')
    expect(errorMessage({}, 'fallback')).toBe('fallback')
  })
})
