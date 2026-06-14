import { useState } from 'react'
import {
  useActivePolicy,
  useCompilePolicy,
  useProposePolicy,
  useReachability,
  usePolicyMatrix,
  useRunPolicyTests,
  useFlowDiff,
  type CompileResult,
  type Decision,
  type ReachabilityMatrix,
  type PolicyDiff,
} from '../api/hooks'
import { usePermissions } from '../api/perms'
import { isApiError, isCentrallyHandled } from '../api/errors'
import { useToast } from '../components/Toast'
import { Card, Page, StateBlock, ErrorState, Button, Chip, cx } from '../components/ui'

export function Policy() {
  const { can } = usePermissions()
  const mayPropose = can('policy:propose')
  // The draft DSL is shared by the editor (compile/propose) and the A1 analysis rail.
  const [draft, setDraft] = useState('allow group:laptops -> group:servers tcp 22\n')

  return (
    <Page title="Policy" subtitle="The published firewall policy, with draft preview, analysis + dual-control publish">
      <div className="flex flex-col gap-5">
        <ActivePolicyCard />
        <DraftEditor draft={draft} setDraft={setDraft} mayPropose={mayPropose} />
        <AnalysisRail draft={draft} />
      </div>
    </Page>
  )
}

function ActivePolicyCard() {
  const q = useActivePolicy()
  const p = q.data
  return (
    <Card className="overflow-hidden">
      <div className="flex items-baseline justify-between border-b border-edge px-4 py-2">
        <span className="text-[12px] font-medium text-ink">Active policy</span>
        {p?.published && (
          <span className="text-[11px] text-ink-faint">
            change <span className="nums">#{p.change_id}</span> · {(p.hash ?? '').slice(0, 12)}…
          </span>
        )}
      </div>
      <div className="px-4 py-3">
        {q.isPending && <StateBlock kind="loading" message="Loading active policy…" />}
        {q.isError && <ErrorState error={q.error} fallback="Couldn't load the active policy." />}
        {p &&
          (!p.published ? (
            <StateBlock kind="empty" message="No policy published yet — default-deny. Draft one below and propose it." />
          ) : (p.rules ?? []).length === 0 ? (
            <div className="text-[13px] text-ink-dim">Published, but it defines no explicit rules (baseline only).</div>
          ) : (
            <RuleTable rules={p.rules ?? []} />
          ))}
      </div>
    </Card>
  )
}

function RuleTable({ rules }: { rules: { from: string; to: string; proto: string; port: string }[] }) {
  return (
    <table className="w-full text-left text-[12px]">
      <thead className="text-[11px] uppercase tracking-wide text-ink-faint">
        <tr>
          {['From', 'To', 'Proto', 'Port'].map((h) => (
            <th key={h} className="py-1 pr-4 font-medium">{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rules.map((r, i) => (
          <tr key={i} className="text-ink">
            <td className="py-1 pr-4"><Chip>{r.from}</Chip></td>
            <td className="py-1 pr-4"><Chip tone="permit">{r.to}</Chip></td>
            <td className="py-1 pr-4 font-mono text-ink-dim">{r.proto}</td>
            <td className="nums py-1 pr-4 text-ink-dim">{r.port}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

const FIELD = 'w-full rounded-[6px] border border-edge bg-mesh-2 px-2 py-1.5 text-[13px] text-ink placeholder:text-ink-faint'

function DraftEditor({ draft, setDraft, mayPropose }: { draft: string; setDraft: (s: string) => void; mayPropose: boolean }) {
  const toast = useToast()
  const compile = useCompilePolicy()
  const propose = useProposePolicy()
  const [groups, setGroups] = useState('servers')
  const [description, setDescription] = useState('')
  const result = compile.data

  function onCompile() {
    compile.mutate(
      { policy: draft, groups: splitGroups(groups) },
      { onError: (err) => toast.notify(isApiError(err) ? err.detail || err.title : 'Compile failed.', 'error') },
    )
  }

  function onPropose() {
    if (!draft.trim()) {
      toast.notify('Draft a policy first.', 'error')
      return
    }
    propose.mutate(
      { policy: draft, description: description.trim() },
      {
        onSuccess: (c) => toast.notify(`Opened change #${c.id} — review it in Approvals.`, 'success'),
        onError: (err) => {
          if (isCentrallyHandled(err)) return // step-up re-auth handled centrally
          toast.notify(isApiError(err) ? err.detail || err.title : 'Propose failed.', 'error')
        },
      },
    )
  }

  return (
    <Card className="overflow-hidden">
      <div className="border-b border-edge px-4 py-2 text-[12px] font-medium text-ink">Draft &amp; preview</div>
      <div className="flex flex-col gap-3 px-4 py-3">
        <label className="block">
          <span className="mb-1 block text-[11px] uppercase tracking-wide text-ink-faint">Policy (DSL)</span>
          <textarea
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            rows={5}
            spellCheck={false}
            className={cx(FIELD, 'font-mono text-[12px]')}
            placeholder="allow group:a -> group:b tcp 443"
          />
        </label>

        <div className="flex items-end gap-2">
          <label className="flex-1">
            <span className="mb-1 block text-[11px] uppercase tracking-wide text-ink-faint">Preview for groups (comma-separated)</span>
            <input value={groups} onChange={(e) => setGroups(e.target.value)} placeholder="servers, db" className={FIELD} />
          </label>
          <Button onClick={onCompile} disabled={compile.isPending}>
            {compile.isPending ? 'Compiling…' : 'Compile preview'}
          </Button>
        </div>

        {result && <CompileView result={result} />}

        {mayPropose && (
          <div className="mt-1 flex items-end gap-2 border-t border-edge pt-3">
            <label className="flex-1">
              <span className="mb-1 block text-[11px] uppercase tracking-wide text-ink-faint">Description (optional)</span>
              <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="why this change" className={FIELD} />
            </label>
            <Button variant="primary" onClick={onPropose} disabled={propose.isPending}>
              {propose.isPending ? 'Proposing…' : 'Propose for approval'}
            </Button>
          </div>
        )}
      </div>
    </Card>
  )
}

// AnalysisRail — the §4 analysis rail (server-computed, A1): reachability query (with
// "why"), the test-authoring loop, and the all-pairs reachability matrix. All run against
// the current draft DSL.
function AnalysisRail({ draft }: { draft: string }) {
  return (
    <Card className="overflow-hidden">
      <div className="border-b border-edge px-4 py-2 text-[12px] font-medium text-ink">
        Analysis <span className="text-ink-faint">(server-computed)</span>
      </div>
      <div className="flex flex-col gap-5 px-4 py-3">
        <FlowDiffView draft={draft} />
        <ReachabilityQuery draft={draft} />
        <PolicyTests draft={draft} />
        <MatrixView draft={draft} />
      </div>
    </Card>
  )
}

// FlowDiffView — the §4.4 "what does this change do" panel: the flows this draft adds
// (accent) / removes (amber) vs the active published policy, and the blast radius (how
// many real hosts whose firewall would change). Server-computed.
function FlowDiffView({ draft }: { draft: string }) {
  const toast = useToast()
  const diff = useFlowDiff()
  return (
    <div>
      <div className="mb-2 flex items-center gap-2">
        <span className="text-[11px] uppercase tracking-wide text-ink-faint">Changes vs active</span>
        <Button
          onClick={() =>
            diff.mutate({ policy: draft }, { onError: (e) => toast.notify(isApiError(e) ? e.detail || e.title : 'Diff failed.', 'error') })
          }
          disabled={diff.isPending}
        >
          {diff.isPending ? '…' : 'Diff'}
        </Button>
      </div>
      {diff.data && <FlowDiffResult d={diff.data} />}
    </div>
  )
}

function FlowDiffResult({ d }: { d: PolicyDiff }) {
  const added = d.added ?? []
  const removed = d.removed ?? []
  const b = d.blast
  const warning = d.warning ? (
    <div className="rounded-[6px] border border-warn/40 bg-warn/10 px-3 py-2 text-[12px] text-warn">
      Won&rsquo;t publish: {d.warning}
    </div>
  ) : null
  if (added.length === 0 && removed.length === 0) {
    return (
      <div className="flex flex-col gap-2">
        {warning}
        <div className="text-[12px] text-ink-faint">No reachability change vs the active policy.</div>
      </div>
    )
  }
  return (
    <div className="flex flex-col gap-2">
      {warning}
      {b && (
        <div className="text-[12px] text-ink-dim">
          Blast radius: up to <span className="nums text-ink">{b.count}</span> of <span className="nums">{b.total}</span>{' '}
          hosts affected <span className="text-ink-faint" title="members of the changed rules' groups — a conservative superset">(?)</span>
          {b.hosts && b.hosts.length > 0 && (
            <span className="ml-1 font-mono text-[11px] text-ink-faint">
              {b.hosts.slice(0, 8).join(', ')}
              {b.truncated || b.hosts.length > 8 ? ' …' : ''}
            </span>
          )}
        </div>
      )}
      <ul className="flex flex-col gap-0.5 font-mono text-[11px]">
        {removed.map((f, i) => (
          <li key={`r${i}`} className="text-warn">− allow {f.from} -&gt; {f.to} {f.flow.proto} {f.flow.port}</li>
        ))}
        {added.map((f, i) => (
          <li key={`a${i}`} className="text-permit">+ allow {f.from} -&gt; {f.to} {f.flow.proto} {f.flow.port}</li>
        ))}
      </ul>
    </div>
  )
}

const SMALL = 'w-24 rounded-[6px] border border-edge bg-mesh-2 px-2 py-1 text-[13px] text-ink'

function ReachabilityQuery({ draft }: { draft: string }) {
  const toast = useToast()
  const q = useReachability()
  const [from, setFrom] = useState('laptops')
  const [to, setTo] = useState('servers')
  const [proto, setProto] = useState('tcp')
  const [port, setPort] = useState('22')

  function check() {
    q.mutate(
      { policy: draft, from, to, proto, port },
      { onError: (e) => toast.notify(isApiError(e) ? e.detail || e.title : 'Query failed.', 'error') },
    )
  }

  return (
    <div>
      <div className="mb-2 text-[11px] uppercase tracking-wide text-ink-faint">Reachability query</div>
      <div className="flex flex-wrap items-center gap-2">
        <input value={from} onChange={(e) => setFrom(e.target.value)} className={SMALL} placeholder="from" />
        <span className="text-ink-faint">→</span>
        <input value={to} onChange={(e) => setTo(e.target.value)} className={SMALL} placeholder="to" />
        <input value={proto} onChange={(e) => setProto(e.target.value)} className={cx(SMALL, 'w-16')} placeholder="proto" />
        <input value={port} onChange={(e) => setPort(e.target.value)} className={cx(SMALL, 'w-20')} placeholder="port" />
        <Button onClick={check} disabled={q.isPending}>{q.isPending ? '…' : 'Check'}</Button>
      </div>
      {q.data && <ReachResult d={q.data} from={from} to={to} proto={proto} port={port} />}
    </div>
  )
}

function ReachResult({ d, from, to, proto, port }: { d: Decision; from: string; to: string; proto: string; port: string }) {
  const flow = `${from} → ${to} ${proto}/${port}`
  if (d.allowed) {
    const why =
      d.reason === 'rule' && d.rule
        ? `granted by: allow ${d.rule.from} -> ${d.rule.to} ${d.rule.proto} ${d.rule.port}`
        : `granted by ${d.reason}`
    return (
      <div className="mt-2 rounded-[6px] border border-permit/40 bg-permit/10 px-3 py-2 text-[12px] text-permit">
        ALLOWED — {flow}
        <span className="ml-1 text-ink-dim">· {why}</span>
      </div>
    )
  }
  return (
    <div className="mt-2 rounded-[6px] border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">
      DENIED — {flow}
      <span className="ml-1 text-ink-dim">
        ·{' '}
        {d.nearest
          ? `nearest miss: allow ${d.nearest.from} -> ${d.nearest.to} ${d.nearest.proto} ${d.nearest.port} (wrong proto/port)`
          : 'default-deny — no matching rule'}
      </span>
    </div>
  )
}

function PolicyTests({ draft }: { draft: string }) {
  const toast = useToast()
  const run = useRunPolicyTests()
  const [tests, setTests] = useState('assert allow laptops -> servers tcp 22\nassert deny laptops -> servers tcp 3306\n')
  const r = run.data

  function onRun() {
    run.mutate(
      { policy: draft, tests },
      { onError: (e) => toast.notify(isApiError(e) ? e.detail || e.title : 'Tests failed.', 'error') },
    )
  }

  return (
    <div>
      <div className="mb-2 flex items-center gap-2">
        <span className="text-[11px] uppercase tracking-wide text-ink-faint">Tests</span>
        {r && (
          <span className={cx('text-[11px]', r.ok ? 'text-permit' : 'text-danger')}>
            {r.passed}/{r.results.length} passing
          </span>
        )}
      </div>
      <textarea
        value={tests}
        onChange={(e) => setTests(e.target.value)}
        rows={3}
        spellCheck={false}
        className={cx(FIELD, 'font-mono text-[12px]')}
        placeholder="assert allow|deny <from> -> <to> <proto> <port>"
      />
      <div className="mt-2"><Button onClick={onRun} disabled={run.isPending}>{run.isPending ? 'Running…' : 'Run tests'}</Button></div>
      {r && r.results.length > 0 && (
        <ul className="mt-2 flex flex-col gap-0.5 font-mono text-[11px]">
          {r.results.map((t, i) => (
            <li key={i} className={t.pass ? 'text-permit' : 'text-danger'}>
              {t.pass ? 'PASS' : 'FAIL'} assert {t.assertion.expect ? 'allow' : 'deny'} {t.assertion.from} {'->'}{' '}
              {t.assertion.to} {t.assertion.proto} {t.assertion.port}
              {!t.pass && <span className="text-ink-dim"> (got {t.got ? 'allow' : 'deny'})</span>}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function MatrixView({ draft }: { draft: string }) {
  const m = usePolicyMatrix()
  return (
    <div>
      <div className="mb-2 flex items-center gap-2">
        <span className="text-[11px] uppercase tracking-wide text-ink-faint">Reachability matrix</span>
        <Button onClick={() => m.mutate({ policy: draft })} disabled={m.isPending}>
          {m.isPending ? '…' : 'Build'}
        </Button>
      </div>
      {m.data && <MatrixGrid m={m.data} />}
    </div>
  )
}

function MatrixGrid({ m }: { m: ReachabilityMatrix }) {
  if (m.groups.length === 0) {
    return <div className="text-[12px] text-ink-faint">No concrete groups in the policy to chart.</div>
  }
  const byPair = new Map(m.cells.map((c) => [`${c.from} ${c.to}`, c]))
  return (
    <div className="overflow-x-auto">
      <table className="text-[11px]">
        <thead>
          <tr>
            <th className="px-2 py-1 text-left text-ink-faint">from ＼ to</th>
            {m.groups.map((g) => (
              <th key={g} className="px-2 py-1 font-mono text-ink-dim">{g}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {m.groups.map((from) => (
            <tr key={from}>
              <td className="px-2 py-1 font-mono text-ink-dim">{from}</td>
              {m.groups.map((to) => {
                const c = byPair.get(`${from} ${to}`)
                const n = c?.flows.length ?? 0
                const title = n > 0 ? c!.flows.map((f) => `${f.proto}/${f.port}`).join(', ') : c?.baseline ? 'baseline only' : 'default-deny'
                return (
                  <td key={to} className="px-2 py-1 text-center" title={title}>
                    {n > 0 ? <span className="nums text-permit">{n}</span> : c?.baseline ? <span className="text-ink-faint">·</span> : <span className="text-ink-faint">—</span>}
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function CompileView({ result }: { result: CompileResult }) {
  if (!result.valid) {
    return (
      <div className="rounded-[6px] border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">
        Invalid: {result.error || 'parse error'}
      </div>
    )
  }
  const inbound = result.compiled?.inbound ?? []
  const outbound = result.compiled?.outbound ?? []
  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-2 text-[12px]">
        <Chip tone="permit">valid</Chip>
        {result.invariants_ok ? (
          <Chip tone="permit">invariants ok</Chip>
        ) : (
          <Chip tone="danger">invariants violated</Chip>
        )}
        <span className="text-ink-faint">compiled firewall for a host with those groups (incl. non-removable baseline)</span>
      </div>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <RuleList title="Inbound (who may reach it)" rules={inbound} />
        <RuleList title="Outbound (where it may go)" rules={outbound} />
      </div>
    </div>
  )
}

function RuleList({ title, rules }: { title: string; rules: { proto: string; port: string; host?: string; group?: string }[] }) {
  return (
    <div>
      <div className="mb-1 text-[11px] uppercase tracking-wide text-ink-faint">{title}</div>
      {rules.length === 0 ? (
        <div className="text-[12px] text-ink-faint">—</div>
      ) : (
        <ul className="flex flex-col gap-0.5 font-mono text-[11px] text-ink-dim">
          {rules.map((r, i) => (
            <li key={i}>
              {r.proto}/{r.port} {r.group ? `group:${r.group}` : r.host || 'any'}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function splitGroups(s: string): string[] {
  return s.split(',').map((g) => g.trim()).filter(Boolean)
}
