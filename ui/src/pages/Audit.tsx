import { useAudit } from '../api/hooks'
import { Card, Page, StateBlock, ErrorState } from '../components/ui'

export function Audit() {
  const q = useAudit()
  return (
    <Page title="Audit" subtitle="Hash-chained, append-only — newest first">
      {q.isLoading && <StateBlock kind="loading" message="Loading audit log…" />}
      {q.isError && <ErrorState error={q.error} fallback="Couldn't load the audit log." />}
      {q.data && (q.data.entries.length === 0
        ? <StateBlock kind="empty" message="No audit entries." />
        : (
          <Card className="overflow-hidden">
            <table className="w-full text-left">
              <thead className="border-b border-edge text-[11px] uppercase tracking-wide text-ink-faint">
                <tr>
                  {['Seq', 'Time', 'Actor', 'Action', 'Target', 'Details'].map((h) => (
                    <th key={h} className="px-4 py-2 font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-edge">
                {q.data.entries.map((e) => (
                  <tr key={e.seq} className="align-top hover:bg-mesh-2">
                    <td className="nums px-4 py-2 text-ink-faint">{e.seq}</td>
                    <td className="nums px-4 py-2 text-ink-dim">{new Date(e.ts).toLocaleString()}</td>
                    <td className="px-4 py-2 text-ink">{e.actor}</td>
                    <td className="px-4 py-2 font-mono text-[12px] text-permit">{e.action}</td>
                    <td className="px-4 py-2 text-ink-dim">{e.target ?? '—'}</td>
                    <td className="px-4 py-2 text-ink-faint">{e.details ?? ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        ))}
    </Page>
  )
}
