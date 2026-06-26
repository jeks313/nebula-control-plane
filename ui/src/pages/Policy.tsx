import { useEffect, useState, type ReactNode } from 'react'
import {
  useActivePolicy,
  useCompilePolicy,
  usePutPolicy,
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
import { isApiError, isCentrallyHandled, isForbidden } from '../api/errors'
import { useToast } from '../components/Toast'
import { Card, Page, StateBlock, ErrorState, Button, Chip, cx } from '../components/ui'
import { Dialog } from '../components/Dialog'

// A draft rule, edited via modal forms (Add / Edit) and removed locally; the draft is
// composed, analyzed (compile / diff / tests / matrix), then applied as one config. from/to
// are bare group names ("any" allowed); the DSL accepts bare groups so serialization round-
// trips the parsed rules exactly.
type Rule = { from: string; to: string; proto: string; port: string }
const PROTOS = ['tcp', 'udp', 'icmp', 'any']

function rulesToDsl(rules: Rule[]): string {
  return rules.map((r) => `allow ${r.from} -> ${r.to} ${r.proto} ${r.port}`).join('\n')
}

export function Policy() {
  const { can } = usePermissions()
  const mayManage = can('policy:manage')
  const active = useActivePolicy()
  // The draft is seeded once from the active policy (edit the current policy, not a blank
  // slate) and thereafter owned by the user; null until the active policy has loaded.
  const [draft, setDraft] = useState<Rule[] | null>(null)
  useEffect(() => {
    if (draft === null && active.data) {
      setDraft((active.data.rules ?? []).map((r) => ({ from: r.from, to: r.to, proto: r.proto, port: r.port })))
    }
  }, [active.data, draft])

  return (
    <Page title="Policy" subtitle="The active firewall policy, with a draft you compose, analyze, then apply.">
      <div className="flex flex-col gap-5">
        <ActivePolicyCard />
        {draft === null ? (
          <Card className="px-4 py-3"><StateBlock kind="loading" message="Loading policy…" /></Card>
        ) : (
          <>
            <DraftRulesCard draft={draft} setDraft={setDraft} mayManage={mayManage} active={active.data?.rules ?? []} />
            <AnalysisRail draft={rulesToDsl(draft)} />
          </>
        )}
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
            v<span className="nums">{p.version}</span> · {(p.hash ?? '').slice(0, 12)}…
          </span>
        )}
      </div>
      <div className="px-4 py-3">
        {q.isPending && <StateBlock kind="loading" message="Loading active policy…" />}
        {q.isError && <ErrorState error={q.error} fallback="Couldn't load the active policy." />}
        {p &&
          (!p.published ? (
            <StateBlock kind="empty" message="No policy published yet — default-deny. Draft one below and apply it." />
          ) : (p.rules ?? []).length === 0 ? (
            <div className="text-[13px] text-ink-dim">Published, but it defines no explicit rules (baseline only).</div>
          ) : (
            <RuleTable rules={p.rules ?? []} />
          ))}
      </div>
    </Card>
  )
}

function RuleTable({ rules }: { rules: Rule[] }) {
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

// DraftRulesCard — compose the draft as a list of rules (Add / Edit via modal, Remove
// locally), preview the compiled firewall, and apply. "Apply" serializes the draft to the
// DSL and PUTs /config/policy: a valid policy is never privileged, so it lands as 200 →
// applied; the 202 branch is kept for the uniform PUT contract.
function DraftRulesCard({
  draft,
  setDraft,
  mayManage,
  active,
}: {
  draft: Rule[]
  setDraft: (r: Rule[]) => void
  mayManage: boolean
  active: Rule[]
}) {
  const toast = useToast()
  const compile = useCompilePolicy()
  const put = usePutPolicy()
  const [groups, setGroups] = useState('servers')
  const [saveError, setSaveError] = useState<string | null>(null)
  const [addOpen, setAddOpen] = useState(false)
  const [editAt, setEditAt] = useState<number | null>(null)
  const result = compile.data
  const dsl = rulesToDsl(draft)

  function onCompile() {
    compile.mutate(
      { policy: dsl, groups: splitGroups(groups) },
      { onError: (err) => toast.notify(isApiError(err) ? err.detail || err.title : 'Compile failed.', 'error') },
    )
  }

  function onApply() {
    setSaveError(null)
    put.mutate(dsl, {
      onSuccess: (r) => {
        if (r.applied) {
          toast.notify(`Policy applied (v${r.row.version}).`, 'success')
        } else {
          toast.notify(
            `This change grants privileged access and needs a second approver — submitted as change #${r.change.id}; approve it from Approvals.`,
            'info',
          )
        }
      },
      onError: (err) => {
        if (isCentrallyHandled(err)) return // 401 / step-up re-auth handled centrally
        if (isForbidden(err)) {
          setSaveError('You lack the policy:manage permission.')
          return
        }
        // 400 (and any other) — surface the exact server validator message inline.
        setSaveError(isApiError(err) ? err.detail || err.title : 'Apply failed.')
      },
    })
  }

  const dirty = rulesToDsl(active) !== dsl

  return (
    <Card className="overflow-hidden">
      <div className="flex items-center justify-between border-b border-edge px-4 py-2">
        <span className="text-[12px] font-medium text-ink">Draft &amp; preview</span>
        <div className="flex items-center gap-2">
          {dirty && <span className="text-[11px] text-warn">unsaved draft</span>}
          <Button onClick={() => setDraft(active.map((r) => ({ ...r })))} disabled={!dirty} title="Discard draft edits and reload the active policy">
            Revert to active
          </Button>
          <Button variant="primary" onClick={() => setAddOpen(true)}>Add rule</Button>
        </div>
      </div>
      <div className="flex flex-col gap-3 px-4 py-3">
        {draft.length === 0 ? (
          <div className="rounded-[6px] border border-edge px-3 py-4 text-center text-[13px] text-ink-faint">
            No rules — this draft is default-deny (every flow blocked). Add a rule to allow traffic.
          </div>
        ) : (
          <table className="w-full text-left text-[12px]">
            <thead className="text-[11px] uppercase tracking-wide text-ink-faint">
              <tr>
                {['From', 'To', 'Proto', 'Port'].map((h) => (
                  <th key={h} className="py-1 pr-4 font-medium">{h}</th>
                ))}
                <th className="py-1 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-edge">
              {draft.map((r, i) => (
                <tr key={i} className="text-ink hover:bg-mesh-2">
                  <td className="py-1.5 pr-4"><Chip>{r.from}</Chip></td>
                  <td className="py-1.5 pr-4"><Chip tone="permit">{r.to}</Chip></td>
                  <td className="py-1.5 pr-4 font-mono text-ink-dim">{r.proto}</td>
                  <td className="nums py-1.5 pr-4 text-ink-dim">{r.port}</td>
                  <td className="py-1.5">
                    <div className="flex justify-end gap-2">
                      <Button onClick={() => setEditAt(i)}>Edit</Button>
                      <Button variant="danger" onClick={() => setDraft(draft.filter((_, j) => j !== i))}>Remove</Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div className="flex items-end gap-2 border-t border-edge pt-3">
          <label className="flex-1">
            <span className="mb-1 block text-[11px] uppercase tracking-wide text-ink-faint">Preview for groups (comma-separated)</span>
            <input value={groups} onChange={(e) => setGroups(e.target.value)} placeholder="servers, db" className={FIELD} />
          </label>
          <Button onClick={onCompile} disabled={compile.isPending}>
            {compile.isPending ? 'Compiling…' : 'Compile preview'}
          </Button>
        </div>

        {result && <CompileView result={result} />}

        {mayManage && (
          <div className="mt-1 flex flex-col gap-2 border-t border-edge pt-3">
            {saveError && (
              <div className="rounded-[6px] border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">
                {saveError}
              </div>
            )}
            <div className="flex items-center justify-between gap-2">
              <span className="text-[11px] text-ink-faint">
                Apply publishes the draft directly. (A change granting privileged access would route to a second approver.)
              </span>
              <Button variant="primary" onClick={onApply} disabled={put.isPending || !dirty}>
                {put.isPending ? 'Applying…' : 'Apply config'}
              </Button>
            </div>
          </div>
        )}
      </div>

      {addOpen && <RuleDialog onSubmit={(r) => { setDraft([...draft, r]); setAddOpen(false) }} onClose={() => setAddOpen(false)} />}
      {editAt !== null && (
        <RuleDialog
          rule={draft[editAt]}
          onSubmit={(r) => { setDraft(draft.map((d, j) => (j === editAt ? r : d))); setEditAt(null) }}
          onClose={() => setEditAt(null)}
        />
      )}
    </Card>
  )
}

// RuleDialog — the per-rule modal form (Add / Edit). Returns the rule to the caller, which
// folds it into the local draft; nothing is published until Apply.
function RuleDialog({ rule, onSubmit, onClose }: { rule?: Rule; onSubmit: (r: Rule) => void; onClose: () => void }) {
  const edit = !!rule
  const [f, setF] = useState<Rule>(rule ?? { from: '', to: '', proto: 'tcp', port: '' })
  const [error, setError] = useState<string | null>(null)

  function submit() {
    setError(null)
    const from = f.from.trim()
    const to = f.to.trim()
    const port = f.port.trim() || 'any'
    if (!from || !to) {
      setError('From and To are required (a group name, or “any”).')
      return
    }
    onSubmit({ from, to, proto: f.proto, port })
  }

  return (
    <Dialog
      open
      onClose={onClose}
      title={edit ? 'Edit rule' : 'Add rule'}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit}>{edit ? 'Save rule' : 'Add rule'}</Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        {error && <div className="rounded-[6px] border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">{error}</div>}
        <p className="text-[12px] text-ink-faint">
          Allow members of <span className="font-mono">From</span> to reach members of <span className="font-mono">To</span> on the given protocol/port. Use <span className="font-mono">any</span> for any source or port.
        </p>
        <div className="grid grid-cols-2 gap-2">
          <Labeled label="From (source group)">
            <input autoFocus value={f.from} onChange={(e) => setF({ ...f, from: e.target.value })} placeholder="laptops" className={cx(FIELD, 'font-mono')} />
          </Labeled>
          <Labeled label="To (destination group)">
            <input value={f.to} onChange={(e) => setF({ ...f, to: e.target.value })} placeholder="servers" className={cx(FIELD, 'font-mono')} />
          </Labeled>
          <Labeled label="Protocol">
            <select value={f.proto} onChange={(e) => setF({ ...f, proto: e.target.value })} className={cx(FIELD, 'font-mono')}>
              {PROTOS.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </Labeled>
          <Labeled label="Port (N, N-M, or any)">
            <input value={f.port} onChange={(e) => setF({ ...f, port: e.target.value })} placeholder="443" className={cx(FIELD, 'font-mono')} />
          </Labeled>
        </div>
      </div>
    </Dialog>
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
  const byPair = new Map(m.cells.map((c) => [`${c.from} ${c.to}`, c]))
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
                const c = byPair.get(`${from} ${to}`)
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

function Labeled({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-[11px] uppercase tracking-wide text-ink-faint">{label}</span>
      {children}
    </label>
  )
}

function splitGroups(s: string): string[] {
  return s.split(',').map((g) => g.trim()).filter(Boolean)
}
