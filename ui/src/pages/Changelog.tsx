import { useVersion, type ChangelogDay } from '../api/hooks'
import { Card, Page, StateBlock, ErrorState, Chip } from '../components/ui'

// CalVer (2026.06.28) -> the committer-date form used in the changelog (2026-06-28), so we can
// highlight the day this build was cut.
function calverToDate(version: string): string {
  return version.replaceAll('.', '-')
}

function fmtBuild(iso: string): string {
  if (!iso || iso === 'unknown') return 'unknown'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

export function Changelog() {
  const q = useVersion()
  return (
    <Page title="Changelog" subtitle="What's deployed to this Harbor, and the commit history behind it">
      {q.isPending && <StateBlock kind="loading" message="Loading version…" />}
      {q.isError && <ErrorState error={q.error} fallback="Couldn't load version." />}
      {q.data && (
        <>
          <Card className="mb-4 p-4">
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <span className="text-[15px] font-semibold text-ink">Deployed</span>
              <span className="nums font-mono text-[14px] text-ink">{q.data.version}</span>
              {q.data.commit && q.data.commit !== 'none' && (
                <span className="nums font-mono text-[13px] text-ink-dim">· {q.data.commit}</span>
              )}
              {q.data.version === 'dev' && <Chip tone="warn">unstamped dev build</Chip>}
            </div>
            <p className="mt-1 text-[12px] text-ink-faint">Built {fmtBuild(q.data.build_time)}</p>
          </Card>

          {q.data.days.length === 0 ? (
            <StateBlock kind="empty" message="No changelog embedded in this build." />
          ) : (
            <div className="flex flex-col gap-4">
              {q.data.days.map((d) => (
                <DayBlock key={d.date} day={d} deployedDate={calverToDate(q.data!.version)} />
              ))}
            </div>
          )}
        </>
      )}
    </Page>
  )
}

function DayBlock({ day, deployedDate }: { day: ChangelogDay; deployedDate: string }) {
  const isDeployedDay = day.date === deployedDate
  return (
    <div>
      <div className="mb-1.5 flex items-center gap-2">
        <h2 className="text-[13px] font-semibold text-ink">{day.date}</h2>
        {isDeployedDay && <Chip tone="permit">deployed</Chip>}
      </div>
      <Card className="divide-y divide-edge overflow-hidden">
        {day.commits.map((c) => (
          <div key={c.hash} className="flex items-baseline gap-3 px-4 py-2">
            <span className="nums shrink-0 font-mono text-[11px] text-ink-faint">{c.hash}</span>
            <span className="text-[13px] text-ink">{c.subject}</span>
          </div>
        ))}
      </Card>
    </div>
  )
}
