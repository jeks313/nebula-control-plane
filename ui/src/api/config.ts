// Runtime config injected by Core into index.html at serve time (the server is the
// source of truth for environment posture; the client must not infer it from the
// URL/protocol). In `vite dev` the placeholder is left unreplaced, which reads as
// non-production — exactly what we want for local development.
declare global {
  interface Window {
    __HARBOR__?: { environment?: string; installerBaseURL?: string }
  }
}

export function harborEnvironment(): string {
  const env = window.__HARBOR__?.environment
  // Missing (CSP-blocked/unset) or the un-substituted `vite dev` token → development.
  if (!env || env === '__HARBOR_ENV__') return 'development'
  return env
}

// Fail-closed: only an explicit "production" from the server is treated as prod.
export function isProduction(): boolean {
  return harborEnvironment() === 'production'
}

// installerBaseURL is the public artifact-bucket base the per-method installer scripts
// (install-{joinkey,sso,cloud}.sh) live under — injected by Core (-installer-base-url).
// Empty when unset (dev, or the un-substituted `vite dev` token): the console then shows
// a generic "fetch the script yourself" hint instead of a ready-to-run one-liner.
export function installerBaseURL(): string {
  const u = window.__HARBOR__?.installerBaseURL
  if (!u || u === '__HARBOR_INSTALLER_BASE__') return ''
  return u.replace(/\/+$/, '') // no trailing slash — we append /install-<method>.sh
}
