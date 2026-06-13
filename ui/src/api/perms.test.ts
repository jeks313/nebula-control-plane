import { describe, it, expect } from 'vitest'
import { rolesHavePerm } from './perms'

describe('rolesHavePerm (mirror of internal/adminapi/rbac.go)', () => {
  it('admin is a superuser', () => {
    expect(rolesHavePerm(['admin'], 'policy:propose')).toBe(true)
    expect(rolesHavePerm(['admin'], 'joinkey:manage')).toBe(true)
    expect(rolesHavePerm(['admin'], 'approval:decide')).toBe(true)
  })

  it('operator has the ops perms but not policy/approval authority', () => {
    expect(rolesHavePerm(['operator'], 'joinkey:manage')).toBe(true)
    expect(rolesHavePerm(['operator'], 'enroll:decide')).toBe(true)
    expect(rolesHavePerm(['operator'], 'rollout:control')).toBe(true)
    expect(rolesHavePerm(['operator'], 'policy:propose')).toBe(false)
    expect(rolesHavePerm(['operator'], 'approval:decide')).toBe(false)
  })

  it('viewer carries no permissions', () => {
    expect(rolesHavePerm(['viewer'], 'enroll:decide')).toBe(false)
    expect(rolesHavePerm(['viewer'], 'joinkey:manage')).toBe(false)
  })

  it('break-glass carries no standalone permission', () => {
    expect(rolesHavePerm(['break-glass'], 'enroll:decide')).toBe(false)
    expect(rolesHavePerm(['break-glass'], 'approval:decide')).toBe(false)
  })

  it('unknown and empty roles deny', () => {
    expect(rolesHavePerm(['wat'], 'enroll:decide')).toBe(false)
    expect(rolesHavePerm([], 'enroll:decide')).toBe(false)
  })

  it('ORs across multiple roles', () => {
    expect(rolesHavePerm(['viewer', 'operator'], 'joinkey:manage')).toBe(true)
  })
})
