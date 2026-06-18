import { describe, it, expect } from 'vitest'
import {
  parseCidr,
  formatCidr,
  cidrSize,
  envelopeBits,
  poolExtent,
  resolvePoolExtent,
  overlaySegments,
  utilizationTone,
  type Cidr,
} from './ipam'
import type { Netblock } from '../api/hooks'

function nb(p: Partial<Netblock>): Netblock {
  return {
    name: 'b',
    cidr: '10.44.0.0/24',
    kind: 'named',
    protected: false,
    capacity: 254,
    allocated: 0,
    used: 0,
    pct: 0,
    created_at: '',
    ...p,
  }
}

describe('parseCidr / formatCidr', () => {
  it('parses and normalizes to the network address', () => {
    const c = parseCidr('10.44.20.130/24')
    expect(c).not.toBeNull()
    expect(formatCidr(c as Cidr)).toBe('10.44.20.0/24')
  })
  it('rejects malformed input', () => {
    expect(parseCidr('not-a-cidr')).toBeNull()
    expect(parseCidr('10.44.0.0/33')).toBeNull()
    expect(parseCidr('10.44.0.256/24')).toBeNull()
  })
})

describe('cidrSize', () => {
  it('is 2^(32-bits)', () => {
    expect(cidrSize(24)).toBe(256)
    expect(cidrSize(27)).toBe(32)
    expect(cidrSize(16)).toBe(65536)
  })
})

describe('envelopeBits', () => {
  it('rounds a /27 up to a /24 envelope (MARGIN_BITS=3, floor /24)', () => {
    expect(envelopeBits(27, 16)).toBe(24)
  })
  it('never goes below the /24 floor', () => {
    expect(envelopeBits(25, 16)).toBe(24) // 25-3=22, clamped up to 24
  })
  it('never exceeds the requested prefix', () => {
    expect(envelopeBits(24, 16)).toBe(24)
  })
})

describe('poolExtent', () => {
  it('derives the smallest enclosing aligned pool from central + default + carves', () => {
    // A block in the upper half forces the enclosure up to a full /16.
    const blocks = [
      nb({ name: 'central', cidr: '10.44.0.0/27', kind: 'reserved' }),
      nb({ name: 'default', cidr: '10.44.64.0/18', kind: 'default' }),
      nb({ name: 'far', cidr: '10.44.200.0/24' }),
    ]
    const pool = poolExtent(blocks)
    expect(pool).not.toBeNull()
    expect(formatCidr(pool as Cidr)).toBe('10.44.0.0/16')
  })
  it('fits tightly when blocks only reach the lower half (extent = the tightest aligned CIDR)', () => {
    // central /27 + default /18 (ends at 10.44.128.0) span exactly a /17 — the derived
    // extent is only as wide as the carves reach (the bare pool prefix isn't on the API).
    const blocks = [
      nb({ name: 'central', cidr: '10.44.0.0/27', kind: 'reserved' }),
      nb({ name: 'default', cidr: '10.44.64.0/18', kind: 'default' }),
    ]
    expect(formatCidr(poolExtent(blocks) as Cidr)).toBe('10.44.0.0/17')
  })
  it('returns null when there are no parsable blocks', () => {
    expect(poolExtent([])).toBeNull()
  })
})

describe('resolvePoolExtent', () => {
  // The API now returns the configured pool (D21); the overlay prefers it so free space
  // ABOVE the highest block is visible — the block-derived extent is only a fallback.
  const blocks = [
    nb({ name: 'central', cidr: '10.44.0.0/27', kind: 'reserved' }),
    nb({ name: 'default', cidr: '10.44.64.0/18', kind: 'default' }),
  ]
  it('prefers the API pool prefix (shows free space above the highest block)', () => {
    // Blocks only reach a /17, but the API pool is the full /16 — the extent is the /16.
    expect(formatCidr(resolvePoolExtent('10.44.0.0/16', blocks) as Cidr)).toBe('10.44.0.0/16')
  })
  it('falls back to the block-derived extent when pool is absent (older server)', () => {
    expect(formatCidr(resolvePoolExtent(undefined, blocks) as Cidr)).toBe('10.44.0.0/17')
  })
  it('falls back to the block-derived extent when pool is unparsable', () => {
    expect(formatCidr(resolvePoolExtent('garbage', blocks) as Cidr)).toBe('10.44.0.0/17')
  })
  it('returns null when neither a pool nor blocks are available', () => {
    expect(resolvePoolExtent(undefined, [])).toBeNull()
  })
})

describe('overlaySegments — the four-color growth-envelope overlay', () => {
  const pool = parseCidr('10.44.0.0/16') as Cidr

  it('colors a free pool entirely green', () => {
    const segs = overlaySegments({ pool, blocks: [] })
    expect(segs).toHaveLength(1)
    expect(segs[0].color).toBe('green')
  })

  it('renders a named carve as purple with a red buddy and yellow envelope remainder', () => {
    // A /27 at 10.44.1.0 -> /24 envelope at 10.44.1.0 (start-of-envelope placement).
    const block = parseCidr('10.44.1.0/27') as Cidr
    const segs = overlaySegments({
      pool,
      blocks: [{ cidr: block, name: 'office', growable: true }],
    })
    // The /27 block itself.
    const purple = segs.find((s) => s.color === 'purple')
    expect(purple).toBeDefined()
    expect(purple?.base).toBe(block.base)
    expect(purple?.size).toBe(cidrSize(27))
    expect(purple?.label).toBe('office')
    // Its immediate doubling buddy (the next /27) is red.
    const red = segs.find((s) => s.color === 'red')
    expect(red).toBeDefined()
    expect(red?.base).toBe(block.base + cidrSize(27))
    expect(red?.size).toBe(cidrSize(27))
    // The rest of the /24 envelope (6 more /27s) is yellow.
    const yellow = segs.find((s) => s.color === 'yellow')
    expect(yellow).toBeDefined()
    expect(yellow?.size).toBe(cidrSize(24) - 2 * cidrSize(27))
    // Everything beyond the envelope is green.
    expect(segs.some((s) => s.color === 'green')).toBe(true)
  })

  it('gives central/default no growth zone (growable:false) — purple only', () => {
    const central = parseCidr('10.44.0.0/27') as Cidr
    const segs = overlaySegments({
      pool,
      blocks: [{ cidr: central, name: 'central', growable: false }],
    })
    expect(segs.some((s) => s.color === 'red')).toBe(false)
    expect(segs.some((s) => s.color === 'yellow')).toBe(false)
    expect(segs.find((s) => s.color === 'purple')?.label).toBe('central')
  })

  it('overlays a pending carve as purple with its own envelope', () => {
    const pending = parseCidr('10.44.2.0/27') as Cidr
    const segs = overlaySegments({ pool, blocks: [], pending: { cidr: pending } })
    const purple = segs.find((s) => s.color === 'purple')
    expect(purple?.base).toBe(pending.base)
    expect(purple?.label).toBe('(new)')
    expect(segs.some((s) => s.color === 'red')).toBe(true)
  })

  it('segments tile the whole pool with no gaps', () => {
    const block = parseCidr('10.44.1.0/27') as Cidr
    const segs = overlaySegments({ pool, blocks: [{ cidr: block, name: 'x', growable: true }] })
    const total = segs.reduce((acc, s) => acc + s.size, 0)
    expect(total).toBe(cidrSize(16))
    // contiguous
    for (let i = 1; i < segs.length; i++) {
      expect(segs[i].base).toBe(segs[i - 1].base + segs[i - 1].size)
    }
  })
})

describe('utilizationTone — the *utilization* axis (red>90, yellow>75)', () => {
  it('maps thresholds', () => {
    expect(utilizationTone(95)).toBe('danger')
    expect(utilizationTone(80)).toBe('warn')
    expect(utilizationTone(50)).toBe('permit')
    expect(utilizationTone(90)).toBe('warn') // strictly >90 is danger; 90 is not
    expect(utilizationTone(75)).toBe('permit') // strictly >75 is warn; 75 is not
  })
})
