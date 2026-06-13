import { useQuery } from '@tanstack/react-query'
import type { components } from './schema'
import { api, loginRedirect } from './client'

export type FleetHealth = components['schemas']['FleetHealth']
export type Identity = components['schemas']['Identity']
export type Device = components['schemas']['Device']
export type AuditRow = components['schemas']['AuditRow']

// get is a small wrapper: it surfaces a 401 by handing off to the session login,
// and turns any non-2xx into a thrown error TanStack Query can render.
async function get<T>(fn: () => Promise<{ data?: T; error?: unknown; response: Response }>): Promise<T> {
  const { data, response } = await fn()
  if (response.status === 401) {
    loginRedirect()
    throw new Error('unauthenticated')
  }
  if (!response.ok || data === undefined) {
    throw new Error(`request failed: ${response.status}`)
  }
  return data
}

export function useMe() {
  return useQuery({
    queryKey: ['me'],
    queryFn: () => get(() => api.GET('/admin/v1/me')),
  })
}

export function useFleetHealth() {
  return useQuery({
    queryKey: ['fleet-health'],
    queryFn: () => get(() => api.GET('/admin/v1/fleet/health')),
    refetchInterval: 15_000, // the rollup is one cheap server call; keep it fresh
  })
}

export function useDevices() {
  return useQuery({
    queryKey: ['devices'],
    queryFn: () => get(() => api.GET('/admin/v1/devices', { params: { query: { limit: 200 } } })),
  })
}

export function useAudit() {
  return useQuery({
    queryKey: ['audit'],
    queryFn: () => get(() => api.GET('/admin/v1/audit', { params: { query: { limit: 50 } } })),
  })
}
