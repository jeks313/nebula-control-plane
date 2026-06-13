import type { Device, RolloutHost } from '../api/hooks'

// Pure fleet aggregations computed client-side from the devices list (the backend
// exposes no funnel/landscape/convergence endpoint — but every field we need is on the
// Device row). All time-dependent helpers take nowMs so they're deterministic to test.

const DAY_MS = 86_400_000

export interface VersionCount {
  version: string
  count: number
}

// versionCounts tallies a version field across devices (empty/missing -> "unknown"),
// ordered by count desc then version asc.
export function versionCounts(devices: Device[], pick: (d: Device) => string | undefined): VersionCount[] {
  const m = new Map<string, number>()
  for (const d of devices) {
    const v = pick(d) || 'unknown'
    m.set(v, (m.get(v) ?? 0) + 1)
  }
  return [...m.entries()]
    .map(([version, count]) => ({ version, count }))
    .sort((a, b) => b.count - a.count || a.version.localeCompare(b.version))
}

export interface ExpiryBuckets {
  expired: number
  soon: number // within 30 days
  later: number
  unknown: number
}

// expiryBuckets buckets cert_not_after relative to now: expired, soon (<=30d), later,
// unknown (no/invalid date — the host hasn't reported a cert).
export function expiryBuckets(devices: Device[], nowMs: number): ExpiryBuckets {
  const b: ExpiryBuckets = { expired: 0, soon: 0, later: 0, unknown: 0 }
  for (const d of devices) {
    const t = parseMs(d.cert_not_after)
    if (t === null) b.unknown++
    else if (t < nowMs) b.expired++
    else if (t - nowMs <= 30 * DAY_MS) b.soon++
    else b.later++
  }
  return b
}

export interface SoonExpiry {
  device: Device
  expiresMs: number
}

// soonestExpiring returns the n devices with the nearest known cert expiry, soonest
// first (already-expired sort first). Devices with no/invalid date are excluded.
export function soonestExpiring(devices: Device[], n: number): SoonExpiry[] {
  return devices
    .map((d) => ({ device: d, expiresMs: parseMs(d.cert_not_after) }))
    .filter((x): x is SoonExpiry => x.expiresMs !== null)
    .sort((a, b) => a.expiresMs - b.expiresMs)
    .slice(0, n)
}

export interface Convergence {
  target: number
  onTarget: number
  lagging: number
  total: number
  pct: number
}

// convergence buckets applied_bundle_version against the target. pct floors; total 0 -> 0.
export function convergence(devices: Device[], target: number): Convergence {
  let onTarget = 0
  for (const d of devices) if (d.applied_bundle_version === target) onTarget++
  const total = devices.length
  return {
    target,
    onTarget,
    lagging: total - onTarget,
    total,
    pct: total ? Math.floor((onTarget / total) * 100) : 0,
  }
}

// targetBundleVersion: what the fleet should converge to — the active rollout's target
// if one is running, else the most common applied_bundle_version (the de-facto current).
export function targetBundleVersion(devices: Device[], rolloutTarget?: number): number {
  if (typeof rolloutTarget === 'number') return rolloutTarget
  const counts = new Map<number, number>()
  for (const d of devices) counts.set(d.applied_bundle_version, (counts.get(d.applied_bundle_version) ?? 0) + 1)
  let best = 0
  let bestN = -1
  for (const [v, n] of counts) {
    if (n > bestN || (n === bestN && v > best)) {
      best = v
      bestN = n
    }
  }
  return best
}

// totalWaves derives the rollout's wave COUNT "Y" (there is no field for it — the
// backend exposes only the 0-based active wave "X"). Host waves are 0-based and
// contiguous (canary = wave 0), so the count is max(host.wave) + 1; 0 when no hosts.
export function totalWaves(hosts: RolloutHost[]): number {
  if (hosts.length === 0) return 0
  return hosts.reduce((m, h) => Math.max(m, h.wave), 0) + 1
}

function parseMs(iso?: string): number | null {
  if (!iso) return null
  const t = Date.parse(iso)
  return Number.isNaN(t) ? null : t
}
