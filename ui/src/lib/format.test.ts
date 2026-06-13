import { describe, it, expect } from 'vitest'
import { usesLabel, fmtDateTime } from './format'

describe('usesLabel', () => {
  it('shows used / max', () => {
    expect(usesLabel(3, 10)).toBe('3 / 10')
    expect(usesLabel(0, 1)).toBe('0 / 1')
  })
  it('shows infinity when the cap is 0 (unlimited)', () => {
    expect(usesLabel(3, 0)).toBe('3 / ∞')
  })
})

describe('fmtDateTime', () => {
  it('returns an em dash for missing/invalid/zero values', () => {
    expect(fmtDateTime()).toBe('—')
    expect(fmtDateTime('')).toBe('—')
    expect(fmtDateTime('not-a-date')).toBe('—')
  })
  it('formats a valid ISO timestamp', () => {
    expect(fmtDateTime('2026-06-13T10:00:00Z')).not.toBe('—')
  })
})
