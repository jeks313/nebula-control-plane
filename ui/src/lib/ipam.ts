import type { Netblock } from '../api/hooks'

// Pure IPv4 address-math + the ADR-0010 growth-envelope overlay model. Kept pure (no
// React) so the four-color overlay semantics are unit-testable and the create selector
// stays a thin render of `overlaySegments(...)`. IPv4 only (the mesh pool is IPv4); all
// addresses fit in a JS number (< 2^32), so we work in unsigned 32-bit integer space.

// MARGIN_BITS is the single knob (ADR default 3): a /P block soft-claims a /(P-MARGIN)
// growth envelope (a /27 -> /24, 8x headroom), which is both where the suggester places
// AND how far the red/yellow growth zone extends. Mirrors the server-side default.
export const MARGIN_BITS = 3
// ENVELOPE_FLOOR: the envelope never gets coarser than this (a /24), matching the Go side.
const ENVELOPE_FLOOR = 24

export interface Cidr {
  base: number // network address as a uint32
  bits: number // prefix length
}

// parseCidr parses "a.b.c.d/NN" into {base, bits}, normalizing base to the network
// address. Returns null on any malformed input (so callers can branch, never throw).
export function parseCidr(s: string): Cidr | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(s.trim())
  if (!m) return null
  const octets = [m[1], m[2], m[3], m[4]].map(Number)
  if (octets.some((o) => o < 0 || o > 255)) return null
  const bits = Number(m[5])
  if (bits < 0 || bits > 32) return null
  const addr = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0
  return { base: maskBase(addr, bits), bits }
}

// maskBase zeroes the host bits, yielding the network address for a prefix length.
function maskBase(addr: number, bits: number): number {
  if (bits <= 0) return 0
  if (bits >= 32) return addr >>> 0
  const mask = (0xffffffff << (32 - bits)) >>> 0
  return (addr & mask) >>> 0
}

// cidrSize is the address count of a /bits block (2^(32-bits)).
export function cidrSize(bits: number): number {
  return 2 ** (32 - bits)
}

// formatAddr renders a uint32 as dotted-quad.
export function formatAddr(addr: number): string {
  const a = addr >>> 0
  return `${(a >>> 24) & 0xff}.${(a >>> 16) & 0xff}.${(a >>> 8) & 0xff}.${a & 0xff}`
}

export function formatCidr(c: Cidr): string {
  return `${formatAddr(c.base)}/${c.bits}`
}

// cidrEnd is the (exclusive) end address of a CIDR.
function cidrEnd(c: Cidr): number {
  return c.base + cidrSize(c.bits)
}

// envelopeBits is the growth-envelope prefix for a requested /P:
// E = clamp(P - MARGIN_BITS, lower=ENVELOPE_FLOOR, upper=P). The lower clamp also can't
// be coarser than the pool itself (handled by the caller passing the pool bits).
export function envelopeBits(p: number, poolBits: number): number {
  const floor = Math.max(ENVELOPE_FLOOR, poolBits)
  const e = p - MARGIN_BITS
  return Math.min(p, Math.max(floor, e))
}

// ── pool extent ───────────────────────────────────────────────────────────────────
//
// The list response now carries the configured `pool` prefix (D21), so the overlay
// extent shows free space ABOVE the highest block. `resolvePoolExtent` prefers that
// authoritative value and only falls back to the block-derived `poolExtent` when the
// API omits it (an older server) — the legacy D19 workaround, kept as a fallback.

// resolvePoolExtent returns the address-map extent: the API-provided pool when present
// and parsable, else the smallest CIDR enclosing all blocks (the D19 fallback).
export function resolvePoolExtent(pool: string | undefined, blocks: Netblock[]): Cidr | null {
  if (pool) {
    const p = parseCidr(pool)
    if (p) return p
  }
  return poolExtent(blocks)
}

// poolExtent derives the enclosing pool CIDR from the netblock list alone: the smallest
// power-of-two CIDR that contains every netblock, aligned to the lowest block's base.
// The D19 fallback for when the API omits the bare `pool` field. Returns null if there
// are no blocks / all are unparsable.
export function poolExtent(blocks: Netblock[]): Cidr | null {
  const cidrs = blocks.map((b) => parseCidr(b.cidr)).filter((c): c is Cidr => c !== null)
  if (cidrs.length === 0) return null
  let lo = Infinity
  let hi = -Infinity
  for (const c of cidrs) {
    lo = Math.min(lo, c.base)
    hi = Math.max(hi, cidrEnd(c))
  }
  // Smallest CIDR whose base <= lo and end >= hi. Walk prefixes coarse-enough to cover
  // the span, anchored on a base aligned to that prefix at or below lo.
  for (let bits = 32; bits >= 0; bits--) {
    const size = cidrSize(bits)
    const base = Math.floor(lo / size) * size
    if (base <= lo && base + size >= hi) return { base, bits }
  }
  return { base: 0, bits: 0 }
}

// ── the four-color overlay ──────────────────────────────────────────────────────────

export type SegmentColor = 'green' | 'purple' | 'red' | 'yellow'

export interface OverlaySegment {
  base: number
  bits: number // the finest prefix that tiles this segment (for the label)
  size: number // address count (drives proportional width)
  color: SegmentColor
  label?: string // a carved block's name, on its purple segment
}

// The ADR semantics, made visible:
//   purple = an allocated/carved block (the /P, incl. central/default)
//   red    = a block's immediate doubling buddy (taking it caps the block at /P)
//   yellow = the rest of that block's growth envelope (caps growth short of the envelope)
//   green  = free AND clear of every envelope (the suggester's target)
// A `pending` carve (the size the operator is choosing) is overlaid as purple at its
// suggested/typed CIDR, with ITS OWN red+yellow envelope, so the operator sees exactly
// what they're about to claim against the existing blocks' zones.

// A half-open address range [start, end). Used for the yellow remainder, which is NOT
// generally a single power-of-two block (a /27 in a /24 envelope leaves a 192-address
// remainder), so it can't be a Cidr.
interface Range {
  start: number
  end: number
}

interface Zone {
  red: Cidr | null // the immediate doubling buddy of a carved block (always exactly a /P)
  yellow: Range[] // the rest of the envelope (excluding the block and its red buddy)
}

// envelopeZone computes the red buddy + yellow remainder for one carved /P block, given
// the pool bits (so the envelope can't exceed the pool). central/default get no growth
// zone in the ADR (they're deliberately sized and don't auto-grow), but a named block's
// kind isn't known here — the caller decides which blocks get a zone.
function envelopeZone(block: Cidr, poolBits: number): Zone {
  const e = envelopeBits(block.bits, poolBits)
  if (e >= block.bits) return { red: null, yellow: [] } // no headroom (already at/above envelope)
  // Start-of-envelope placement (the ADR's load-bearing invariant) means the block sits
  // at the base of its /E envelope, so the whole envelope lies AT and ABOVE the block:
  //   [envBase .. envBase+blockSize)            = the block            (purple, not here)
  //   [envBase+blockSize .. envBase+2*blockSize) = the doubling buddy   (red)
  //   [envBase+2*blockSize .. envEnd)            = the rest of the envelope (yellow)
  const envBase = maskBase(block.base, e)
  const blockSize = cidrSize(block.bits)
  const envEnd = envBase + cidrSize(e)
  const redBase = envBase + blockSize
  const red: Cidr | null = redBase < envEnd ? { base: redBase >>> 0, bits: block.bits } : null
  const yellowStart = envBase + 2 * blockSize
  const yellow: Range[] = yellowStart < envEnd ? [{ start: yellowStart, end: envEnd }] : []
  return { red, yellow }
}

// colorAt resolves the color of a single address against the carved blocks + their zones.
// Precedence: purple > red > yellow > green. A pending block's own purple/red/yellow takes
// the same precedence (it IS a carve, just unsaved).
function colorAt(addr: number, carves: { cidr: Cidr; zone: Zone }[]): SegmentColor {
  // purple: inside any carved block
  for (const c of carves) if (addr >= c.cidr.base && addr < cidrEnd(c.cidr)) return 'purple'
  // red: inside any block's immediate buddy
  for (const c of carves) if (c.zone.red && addr >= c.zone.red.base && addr < cidrEnd(c.zone.red)) return 'red'
  // yellow: inside any block's remaining envelope
  for (const c of carves) for (const y of c.zone.yellow) if (addr >= y.start && addr < y.end) return 'yellow'
  return 'green'
}

export interface OverlayInput {
  pool: Cidr
  // Carved blocks already persisted. `growable` marks blocks whose growth envelope draws
  // a red/yellow zone (named carves); central/default are passed growable:false.
  blocks: { cidr: Cidr; name: string; growable: boolean }[]
  // The carve the operator is composing (optional). It is rendered purple with its own
  // full red/yellow envelope — the "what am I about to take" preview.
  pending?: { cidr: Cidr } | null
}

// overlaySegments walks the pool at the resolution of the finest carve/envelope boundary
// and coalesces equal-colored runs into proportional segments for the address-bar. Pure
// and deterministic in (pool, blocks, pending).
export function overlaySegments(input: OverlayInput): OverlaySegment[] {
  const { pool, blocks, pending } = input
  const carves: { cidr: Cidr; zone: Zone; name?: string }[] = []
  for (const b of blocks) {
    carves.push({ cidr: b.cidr, zone: b.growable ? envelopeZone(b.cidr, pool.bits) : { red: null, yellow: [] }, name: b.name })
  }
  if (pending) carves.push({ cidr: pending.cidr, zone: envelopeZone(pending.cidr, pool.bits), name: '(new)' })

  // Boundaries: pool start/end + every carve/red/yellow edge. Walk between consecutive
  // boundaries, color the midpoint, coalesce equal runs. The boundary set is tiny.
  const edges = new Set<number>([pool.base, cidrEnd(pool)])
  for (const c of carves) {
    edges.add(c.cidr.base)
    edges.add(cidrEnd(c.cidr))
    if (c.zone.red) {
      edges.add(c.zone.red.base)
      edges.add(cidrEnd(c.zone.red))
    }
    for (const y of c.zone.yellow) {
      edges.add(y.start)
      edges.add(y.end)
    }
  }
  const sorted = [...edges].filter((e) => e >= pool.base && e <= cidrEnd(pool)).sort((a, b) => a - b)

  const raw: OverlaySegment[] = []
  for (let i = 0; i < sorted.length - 1; i++) {
    const start = sorted[i]
    const end = sorted[i + 1]
    if (end <= start) continue
    const color = colorAt(start, carves)
    // A purple segment carries the name of the block that owns it (for the label).
    let label: string | undefined
    if (color === 'purple') {
      const owner = carves.find((c) => start >= c.cidr.base && start < cidrEnd(c.cidr))
      label = owner?.name
    }
    raw.push({ base: start, bits: spanBits(start, end), size: end - start, color, label })
  }
  // Coalesce adjacent same-color, same-label runs (keeps the SVG segment count low).
  const out: OverlaySegment[] = []
  for (const seg of raw) {
    const prev = out[out.length - 1]
    if (prev && prev.color === seg.color && prev.label === seg.label && prev.base + prev.size === seg.base) {
      prev.size += seg.size
      prev.bits = spanBits(prev.base, prev.base + prev.size)
    } else {
      out.push({ ...seg })
    }
  }
  return out
}

// spanBits is the prefix length of the largest aligned block that fits in [start,end);
// purely cosmetic (used to label a free span like "/18"). Falls back to the run size.
function spanBits(start: number, end: number): number {
  const span = end - start
  for (let bits = 0; bits <= 32; bits++) {
    if (cidrSize(bits) <= span) return bits
  }
  return 32
}

// utilizationTone maps an allocated-% to the ADR's *utilization* axis (a DIFFERENT axis
// from the create-overlay growth colors): red > 90, yellow > 75, else permit. Used by
// the netblock table bars and the Dashboard IPAM health panel.
export function utilizationTone(pct: number): 'permit' | 'warn' | 'danger' {
  if (pct > 90) return 'danger'
  if (pct > 75) return 'warn'
  return 'permit'
}
