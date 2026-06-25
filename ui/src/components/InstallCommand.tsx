import { installerBaseURL } from '../api/config'
import { useToast } from './Toast'
import { Button, Card } from './ui'

// InstallCommand renders the one-line node installer for an enrollment method as a
// copyable command. The per-method scripts (install-{joinkey,sso,cloud}.sh) already bake
// in THIS harbor's gateway/core URLs at release time, so the operator only runs one line
// — no address to supply. They're meant to be RUN with sudo (no internal sudo, so they
// never re-prompt for the password), hence `| sudo bash`.
//
// `env` inlines `KEY=value` before `bash` (e.g. NCP_JOIN_KEY for a just-minted join key).
// When the installer base URL isn't configured on the server, we fall back to a hint
// rather than emitting a broken command.
export type InstallMethod = 'joinkey' | 'sso' | 'cloud'

const SUBTITLE: Record<InstallMethod, string> = {
  joinkey: 'Run this on the node (it prompts for the join key, unless one is inlined below):',
  sso: 'Run this on the node — it opens your browser to sign in; an admin then approves the enrollment:',
  cloud: 'Run this on the cloud instance — it self-detects the cloud and attests via the instance IAM role:',
}

export function buildInstallCommand(method: InstallMethod, base: string, env?: Record<string, string>): string {
  const prefix = Object.entries(env ?? {})
    .map(([k, v]) => `${k}=${shellQuote(v)} `)
    .join('')
  return `curl -fsSL ${base}/install-${method}.sh | sudo ${prefix}bash`
}

export function InstallCommand({
  method,
  env,
  title = 'Install command',
}: {
  method: InstallMethod
  env?: Record<string, string>
  title?: string
}) {
  const toast = useToast()
  const base = installerBaseURL()

  if (!base) {
    return (
      <Card className="px-4 py-3 text-[12px] text-ink-faint">
        <div className="mb-1 text-[11px] uppercase tracking-wide">{title}</div>
        Set <code className="text-ink-dim">-installer-base-url</code> on harbor to show a ready-to-run command
        here. Until then, download <code className="text-ink-dim">install-{method}.sh</code> from your artifact
        bucket and run it as root (<code className="text-ink-dim">sudo bash install-{method}.sh</code>).
      </Card>
    )
  }

  const cmd = buildInstallCommand(method, base, env)
  return (
    <Card className="px-4 py-3">
      <div className="mb-1 text-[11px] uppercase tracking-wide text-ink-faint">{title}</div>
      <p className="mb-2 text-[12px] text-ink-dim">{SUBTITLE[method]}</p>
      <div className="flex items-center gap-2">
        <code className="flex-1 overflow-x-auto rounded-[6px] border border-edge bg-mesh-2 px-2 py-1.5 font-mono text-[12px] text-ink">
          {cmd}
        </code>
        <Button
          onClick={() => {
            void navigator.clipboard?.writeText(cmd)
            toast.notify('Install command copied to clipboard', 'success')
          }}
        >
          Copy
        </Button>
      </div>
    </Card>
  )
}

// shellQuote single-quotes a value for inline `KEY=value` use, escaping embedded single
// quotes the POSIX way ('\''). Join-key secrets are njk_… tokens (no quotes), but the
// editor never trusts that.
function shellQuote(v: string): string {
  if (/^[A-Za-z0-9_./:-]+$/.test(v)) return v
  return `'${v.replace(/'/g, `'\\''`)}'`
}
