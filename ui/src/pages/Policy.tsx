import { useState } from 'react'
import {
  useActivePolicy,
  useCompilePolicy,
  useProposePolicy,
  type CompileResult,
} from '../api/hooks'
import { usePermissions } from '../api/perms'
import { isApiError, isCentrallyHandled } from '../api/errors'
import { useToast } from '../components/Toast'
import { Card, Page, StateBlock, ErrorState, Button, Chip, cx } from '../components/ui'

export function Policy() {
  const { can } = usePermissions()
  const mayPropose = can('policy:propose')

  return (
    <Page title="Policy" subtitle="The published firewall policy, with draft preview + dual-control publish">
      <div className="flex flex-col gap-5">
        <ActivePolicyCard />
        <DraftEditor mayPropose={mayPropose} />
        <p className="text-[12px] text-ink-faint">
          The reachability matrix, test suite, blast-radius and visual diff (§4 analysis rail) land with the A1
          policy-analysis engine.
        </p>
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

function DraftEditor({ mayPropose }: { mayPropose: boolean }) {
  const toast = useToast()
  const compile = useCompilePolicy()
  const propose = useProposePolicy()
  const [draft, setDraft] = useState('allow group:laptops -> group:servers tcp 22\n')
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
