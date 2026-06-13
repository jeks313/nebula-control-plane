import { useDevices } from '../api/hooks'
import { Card, Page, StateBlock, cx } from '../components/ui'

export function Devices() {
  const q = useDevices()
  return (
    <Page title="Devices" subtitle="Hosts reporting in over the mesh">
      {q.isLoading && <StateBlock kind="loading" message="Loading devices…" />}
      {q.isError && <StateBlock kind="error" message="Couldn't load devices." />}
      {q.data && (q.data.devices.length === 0
        ? <StateBlock kind="empty" message="No devices yet." />
        : (
          <Card className="overflow-hidden">
            <table className="w-full text-left">
              <thead className="border-b border-edge text-[11px] uppercase tracking-wide text-ink-faint">
                <tr>
                  {['Overlay IP', 'Name', 'Pilot', 'Nebula', 'Cert expires', 'Health', 'Last seen'].map((h) => (
                    <th key={h} className="px-4 py-2 font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-edge">
                {q.data.devices.map((d) => (
                  <tr key={d.overlay_ip} className="hover:bg-mesh-2">
                    <td className="nums px-4 py-2 text-ink">{d.overlay_ip}</td>
                    <td className="px-4 py-2 text-ink">{d.name}</td>
                    <td className="nums px-4 py-2 text-ink-dim">{d.pilot_version ?? '—'}</td>
                    <td className="nums px-4 py-2 text-ink-dim">{d.nebula_version ?? '—'}</td>
                    <td className="nums px-4 py-2 text-ink-dim">{fmtDate(d.cert_not_after)}</td>
                    <td className={cx('px-4 py-2', healthTone(d.health))}>{d.health ?? '—'}</td>
                    <td className="nums px-4 py-2 text-ink-faint">{fmtDate(d.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        ))}
    </Page>
  )
}

function healthTone(h?: string): string {
  if (h === 'ok' || h === 'healthy') return 'text-permit'
  if (h === 'stale' || h === 'degraded') return 'text-warn'
  if (h) return 'text-danger'
  return 'text-ink-faint'
}

function fmtDate(iso?: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString()
}
