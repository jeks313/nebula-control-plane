import { describe, it, expect } from 'vitest'
import { approveCount, canApprove, canDeny, isSelfApprovalDeadend } from './approvals'
import type { Change, Signoff } from '../api/hooks'

const so = (actor: string, decision: 'approve' | 'deny'): Signoff => ({ actor, decision, created_at: '2026-06-13T00:00:00Z' })
const change = (p: Partial<Change>): Pick<Change, 'state' | 'proposer'> => ({ state: 'pending', proposer: 'alice', ...p })

describe('approveCount', () => {
  it('counts only approve signoffs', () => {
    expect(approveCount([so('a', 'approve'), so('b', 'deny'), so('c', 'approve')])).toBe(2)
    expect(approveCount([])).toBe(0)
  })
})

describe('canApprove (dual-control mirror)', () => {
  it('allows a distinct admin to approve a pending change', () => {
    expect(canApprove(change({ proposer: 'alice' }), [so('alice', 'approve')], 'bob', true)).toEqual({ ok: true })
  })
  it('blocks without permission', () => {
    expect(canApprove(change({}), [], 'bob', false).ok).toBe(false)
  })
  it('blocks self-approval', () => {
    const g = canApprove(change({ proposer: 'alice' }), [so('alice', 'approve')], 'alice', true)
    expect(g.ok).toBe(false)
    expect(g.reason).toMatch(/no self-approval/i)
  })
  it('blocks a second sign-off by the same actor', () => {
    expect(canApprove(change({ proposer: 'alice' }), [so('alice', 'approve'), so('bob', 'approve')], 'bob', true).ok).toBe(false)
  })
  it('blocks once the change is no longer pending', () => {
    expect(canApprove(change({ state: 'committed', proposer: 'alice' }), [], 'bob', true).ok).toBe(false)
  })
})

describe('canDeny', () => {
  it('lets a permitted admin veto a pending change (incl the proposer withdrawing)', () => {
    expect(canDeny({ state: 'pending' }, true)).toBe(true)
  })
  it('blocks without permission or when not pending', () => {
    expect(canDeny({ state: 'pending' }, false)).toBe(false)
    expect(canDeny({ state: 'committed' }, true)).toBe(false)
  })
})

describe('isSelfApprovalDeadend', () => {
  it('flags a pending change the current admin proposed', () => {
    expect(isSelfApprovalDeadend(change({ proposer: 'alice' }), 'alice', true)).toBe(true)
    expect(isSelfApprovalDeadend(change({ proposer: 'alice' }), 'bob', true)).toBe(false)
  })
})
