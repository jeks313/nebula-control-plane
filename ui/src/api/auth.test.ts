import { describe, it, expect } from 'vitest'
import { safeReturnPath, loginUrl, csrfTokenFrom, providerLabel } from './auth'

describe('safeReturnPath (open-redirect defense in depth)', () => {
  it('keeps same-origin paths', () => {
    expect(safeReturnPath('/')).toBe('/')
    expect(safeReturnPath('/devices')).toBe('/devices')
    expect(safeReturnPath('/fleet/health?expiry=7d')).toBe('/fleet/health?expiry=7d')
    expect(safeReturnPath('/a/b#frag')).toBe('/a/b#frag')
  })

  it('collapses off-origin / malicious targets to "/"', () => {
    expect(safeReturnPath('//evil.com')).toBe('/') // protocol-relative
    expect(safeReturnPath('/\\evil.com')).toBe('/') // backslash → host confusion
    expect(safeReturnPath('https://evil.com')).toBe('/') // absolute URL
    expect(safeReturnPath('relative')).toBe('/') // no leading slash
    expect(safeReturnPath('')).toBe('/')
    expect(safeReturnPath('/x\ny')).toBe('/') // control char
  })
})

describe('loginUrl', () => {
  it('builds the default login url (server picks the provider)', () => {
    expect(loginUrl()).toBe('/admin/v1/auth/login?return_to=%2F')
  })

  it('includes provider + return_to, no step_up by default', () => {
    const u = new URL('http://h' + loginUrl({ provider: 'oidc', returnTo: '/devices' }))
    expect(u.pathname).toBe('/admin/v1/auth/login')
    expect(u.searchParams.get('provider')).toBe('oidc')
    expect(u.searchParams.get('return_to')).toBe('/devices')
    expect(u.searchParams.get('step_up')).toBeNull()
  })

  it('sets step_up=1 and still sanitizes return_to', () => {
    const u = new URL('http://h' + loginUrl({ stepUp: true, returnTo: '//evil.com' }))
    expect(u.searchParams.get('step_up')).toBe('1')
    expect(u.searchParams.get('return_to')).toBe('/') // sanitized
  })
})

describe('csrfTokenFrom', () => {
  it('extracts the harbor_csrf value', () => {
    expect(csrfTokenFrom('a=1; harbor_csrf=tok123; b=2')).toBe('tok123')
    expect(csrfTokenFrom('harbor_csrf=only')).toBe('only')
  })

  it('url-decodes the value', () => {
    expect(csrfTokenFrom('harbor_csrf=a%2Bb%3D')).toBe('a+b=')
  })

  it('returns "" when absent', () => {
    expect(csrfTokenFrom('other=1')).toBe('')
    expect(csrfTokenFrom('')).toBe('')
  })

  it('does not match a different cookie that ends with the name', () => {
    expect(csrfTokenFrom('not_harbor_csrf=nope')).toBe('')
  })

  it('never throws on a malformed percent sequence (mutation hot path)', () => {
    expect(() => csrfTokenFrom('harbor_csrf=100%done')).not.toThrow()
    expect(csrfTokenFrom('harbor_csrf=100%done')).toBe('100%done')
    expect(csrfTokenFrom('harbor_csrf=trailing%')).toBe('trailing%')
  })
})

describe('providerLabel', () => {
  it('labels known providers and falls back for unknown', () => {
    expect(providerLabel('github')).toBe('Sign in with GitHub')
    expect(providerLabel('oidc')).toBe('Sign in with SSO')
    expect(providerLabel('saml')).toBe('Sign in with SSO (SAML)')
    expect(providerLabel('acme')).toBe('Sign in with acme')
  })
})
