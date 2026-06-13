import type { Change, Signoff } from '../api/hooks'

// Pure dual-control helpers — a client mirror of the server rules (the server enforces
// every one of these and is the source of truth; this just drives sensible disabled
// states + tooltips, defense in depth).

export function approveCount(signoffs: Signoff[]): number {
  return signoffs.filter((s) => s.decision === 'approve').length
}

export interface Gate {
  ok: boolean
  reason?: string
}

// canApprove: a distinct admin may approve a still-pending change once, and never their
// own proposal (no self-approval). Returns a reason when blocked, for the tooltip.
export function canApprove(
  change: Pick<Change, 'state' | 'proposer'>,
  signoffs: Signoff[],
  principal: string,
  hasPerm: boolean,
): Gate {
  if (!hasPerm) return { ok: false, reason: 'Your role cannot approve changes.' }
  if (change.state !== 'pending') return { ok: false, reason: 'This change is no longer pending.' }
  if (principal && change.proposer === principal) {
    return { ok: false, reason: 'You proposed this — a different admin must approve (no self-approval).' }
  }
  if (principal && signoffs.some((s) => s.actor === principal)) {
    return { ok: false, reason: 'You have already signed off on this change.' }
  }
  return { ok: true }
}

// canDeny: a single veto stops a pending change (fail-closed). The proposer may deny to
// withdraw, so there is no self-restriction here — only the permission + pending state.
export function canDeny(change: Pick<Change, 'state'>, hasPerm: boolean): boolean {
  return hasPerm && change.state === 'pending'
}

// A lone admin can propose but can never reach quorum (self-approval is blocked) — the
// console should say so rather than show a dead Approve button.
export function isSelfApprovalDeadend(
  change: Pick<Change, 'state' | 'proposer'>,
  principal: string,
  hasPerm: boolean,
): boolean {
  return hasPerm && change.state === 'pending' && !!principal && change.proposer === principal
}
