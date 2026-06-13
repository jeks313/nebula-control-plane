import { useQuery } from '@tanstack/react-query'
import type { components } from './schema'
import { api, unwrap } from './client'

export type FleetHealth = components['schemas']['FleetHealth']
export type Identity = components['schemas']['Identity']
export type Device = components['schemas']['Device']
export type AuditRow = components['schemas']['AuditRow']

// unwrap (client.ts) parses problem+json into a typed ApiError; a 401 is left to the
// AuthGate (which shows the login screen) rather than redirecting from inside a query.
export function useMe() {
  return useQuery({
    queryKey: ['me'],
    queryFn: () => unwrap(api.GET('/admin/v1/me')),
  })
}

export function useFleetHealth() {
  return useQuery({
    queryKey: ['fleet-health'],
    queryFn: () => unwrap(api.GET('/admin/v1/fleet/health')),
    refetchInterval: 15_000, // the rollup is one cheap server call; keep it fresh
  })
}

export function useDevices() {
  return useQuery({
    queryKey: ['devices'],
    queryFn: () => unwrap(api.GET('/admin/v1/devices', { params: { query: { limit: 200 } } })),
  })
}

export function useAudit() {
  return useQuery({
    queryKey: ['audit'],
    queryFn: () => unwrap(api.GET('/admin/v1/audit', { params: { query: { limit: 50 } } })),
  })
}
