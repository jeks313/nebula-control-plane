import { describe, expect, it } from 'vitest'
import { buildInstallCommand } from './InstallCommand'

const BASE = 'https://ncp-artifacts-123456789012.s3.ca-central-1.amazonaws.com'

describe('buildInstallCommand', () => {
  it('builds a run-as-root one-liner per method', () => {
    expect(buildInstallCommand('sso', BASE)).toBe(`curl -fsSL ${BASE}/install-sso.sh | sudo bash`)
    expect(buildInstallCommand('cloud', BASE)).toBe(`curl -fsSL ${BASE}/install-cloud.sh | sudo bash`)
    expect(buildInstallCommand('joinkey', BASE)).toBe(`curl -fsSL ${BASE}/install-joinkey.sh | sudo bash`)
  })

  it('inlines env (e.g. a just-minted join key) before bash', () => {
    expect(buildInstallCommand('joinkey', BASE, { NCP_JOIN_KEY: 'njk_abc123' })).toBe(
      `curl -fsSL ${BASE}/install-joinkey.sh | sudo NCP_JOIN_KEY=njk_abc123 bash`,
    )
  })

  it('shell-quotes an env value that contains shell metacharacters', () => {
    expect(buildInstallCommand('joinkey', BASE, { NCP_JOIN_KEY: "a b';id" })).toBe(
      `curl -fsSL ${BASE}/install-joinkey.sh | sudo NCP_JOIN_KEY='a b'\\'';id' bash`,
    )
  })
})
