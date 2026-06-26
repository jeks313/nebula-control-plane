import { describe, it, expect } from 'vitest'
import {
  versionCounts,
  expiryBuckets,
  soonestExpiring,
  convergence,
  laggingHosts,
  targetBundleVersion,
  totalWaves,
} from './fleet'
import type { Device, RolloutHost } from '../api/hooks'

function dev(p: Partial<Device>): Device {
  return { overlay_ip: '10.0.0.1', name: 'h', applied_bundle_version: 1, clock_offset_ms: 0, ...p }
}

const NOW = Date.parse('2026-06-13T00:00:00Z')
const iso = (deltaDays: number) => new Date(NOW + deltaDays * 86_400_000).toISOString()

describe('versionCounts', () => {
  it('tallies and sorts by count desc then version, mapping missing to unknown', () => {
    const ds = [dev({ pilot_version: '1.0' }), dev({ pilot_version: '1.0' }), dev({ pilot_version: '1.1' }), dev({})]
    expect(versionCounts(ds, (d) => d.pilot_version)).toEqual([
      { version: '1.0', count: 2 },
      { version: '1.1', count: 1 },
      { version: 'unknown', count: 1 },
    ])
  })
})

describe('expiryBuckets', () => {
  it('buckets certs by expiry window, counting unknown/invalid', () => {
    const ds = [
      dev({ cert_not_after: iso(-1) }), // expired
      dev({ cert_not_after: iso(10) }), // soon
      dev({ cert_not_after: iso(29) }), // soon
      dev({ cert_not_after: iso(60) }), // later
      dev({}), // unknown (no cert reported)
      dev({ cert_not_after: 'garbage' }), // unknown (invalid)
    ]
    expect(expiryBuckets(ds, NOW)).toEqual({ expired: 1, soon: 2, later: 1, unknown: 2 })
  })
})

describe('soonestExpiring', () => {
  it('returns nearest-first, excludes unknown dates, caps at n', () => {
    const ds = [
      dev({ name: 'c', cert_not_after: iso(30) }),
      dev({ name: 'a', cert_not_after: iso(-5) }),
      dev({ name: 'b', cert_not_after: iso(2) }),
      dev({ name: 'x' }),
    ]
    expect(soonestExpiring(ds, 2).map((s) => s.device.name)).toEqual(['a', 'b'])
  })
})

describe('convergence', () => {
  it('computes the on-target percentage (floored)', () => {
    const ds = [
      dev({ applied_bundle_version: 5 }),
      dev({ applied_bundle_version: 5 }),
      dev({ applied_bundle_version: 5 }),
      dev({ applied_bundle_version: 4 }),
    ]
    expect(convergence(ds, 5)).toEqual({ target: 5, onTarget: 3, lagging: 1, total: 4, pct: 75 })
  })
  it('an empty fleet is 0%', () => {
    expect(convergence([], 5)).toEqual({ target: 5, onTarget: 0, lagging: 0, total: 0, pct: 0 })
  })
})

describe('laggingHosts', () => {
  it('returns only off-target hosts, furthest behind first then by name', () => {
    const ds = [
      dev({ name: 'ontarget', applied_bundle_version: 5 }),
      dev({ name: 'b', applied_bundle_version: 4 }),
      dev({ name: 'a', applied_bundle_version: 4 }),
      dev({ name: 'old', applied_bundle_version: 2 }),
    ]
    expect(laggingHosts(ds, 5).map((d) => d.name)).toEqual(['old', 'a', 'b'])
  })
  it('is empty when the whole fleet is on target', () => {
    expect(laggingHosts([dev({ applied_bundle_version: 5 })], 5)).toEqual([])
  })
})

describe('targetBundleVersion', () => {
  it('prefers an explicit active-rollout target', () => {
    expect(targetBundleVersion([dev({ applied_bundle_version: 1 })], 9)).toBe(9)
  })
  it('falls back to the most common applied version', () => {
    const ds = [dev({ applied_bundle_version: 7 }), dev({ applied_bundle_version: 7 }), dev({ applied_bundle_version: 3 })]
    expect(targetBundleVersion(ds)).toBe(7)
  })
})

describe('totalWaves', () => {
  const host = (wave: number): RolloutHost => ({ overlay_ip: 'x', wave, status: 'waiting' })
  it('counts waves from 0-based host indices (canary = wave 0)', () => {
    // backend assigns contiguous 0-based waves; {0,1,2} is a 3-wave rollout
    expect(totalWaves([host(0), host(2), host(1)])).toBe(3)
    expect(totalWaves([host(0)])).toBe(1)
  })
  it('is 0 with no hosts', () => {
    expect(totalWaves([])).toBe(0)
  })
})
