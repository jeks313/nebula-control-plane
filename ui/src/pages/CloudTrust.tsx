import { useCloudTrust } from '../api/hooks'
import { Card, Page, StateBlock, ErrorState, Chip } from '../components/ui'

// Cloud Trust — the dual-control-published cloud-attestation config: which cloud
// principals (AWS accounts/roles today) may attest into the mesh, and the groups +
// auto-issue posture each is granted. Read-only here; publishing is a dual-control
// change (the propose/approve UI is a later increment).
export function CloudTrust() {
  const q = useCloudTrust()
  const cfg = q.data

  return (
    <Page
      title="Cloud Trust"
      subtitle="Which cloud accounts may attest into the mesh — and the groups they're granted"
    >
      {q.isPending && <StateBlock kind="loading" message="Loading cloud-trust config…" />}
      {q.isError && <ErrorState error={q.error} fallback="Couldn't load the cloud-trust config." />}
      {cfg &&
        (!cfg.published ? (
          <StateBlock kind="empty" message="No cloud-trust config published yet. Publishing is a dual-control change." />
        ) : (
          <div className="flex flex-col gap-4">
            <Card className="px-4 py-3 text-[13px] text-ink-dim">
              Published as change <span className="nums text-ink">#{cfg.change_id}</span>. Default groups granted to every
              attested host:{' '}
              <span className="ml-1 inline-flex flex-wrap gap-1 align-middle">
                {(cfg.default_groups ?? []).length === 0 ? (
                  <span className="text-ink-faint">none</span>
                ) : (
                  (cfg.default_groups ?? []).map((g) => <Chip key={g} tone="permit">{g}</Chip>)
                )}
              </span>
            </Card>

            <Card className="overflow-hidden">
              <div className="border-b border-edge px-4 py-2 text-[12px] text-ink-faint">Trusted AWS accounts</div>
              <table className="w-full text-left">
                <thead className="border-b border-edge text-[11px] uppercase tracking-wide text-ink-faint">
                  <tr>
                    {['Account', 'Allowed roles (ARN)', 'Groups', 'Admission'].map((h) => (
                      <th key={h} className="px-4 py-2 font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-edge">
                  {(cfg.aws ?? []).map((a) => (
                    <tr key={a.account} className="align-top hover:bg-mesh-2">
                      <td className="nums px-4 py-2 font-mono text-[12px] text-ink">{a.account}</td>
                      <td className="px-4 py-2 font-mono text-[11px] text-ink-dim">
                        {(a.arn_patterns ?? []).length === 0 ? (
                          <span className="text-ink-faint">any role in the account</span>
                        ) : (
                          <span className="flex flex-col gap-0.5">
                            {(a.arn_patterns ?? []).map((p) => <span key={p}>{p}</span>)}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2">
                        <span className="flex flex-wrap gap-1">
                          {(a.groups ?? []).length === 0 ? <span className="text-ink-faint">—</span> : (a.groups ?? []).map((g) => <Chip key={g}>{g}</Chip>)}
                        </span>
                      </td>
                      <td className="px-4 py-2">
                        {a.auto_issue ? <Chip tone="warn">auto-issue</Chip> : <span className="text-ink-dim">manual approval</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          </div>
        ))}
    </Page>
  )
}
