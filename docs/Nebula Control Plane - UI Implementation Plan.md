---
created: 2026-06-13
updated: 2026-06-13
source: claude-chat
status: draft
project: nebula-control-plane
tags: [networking, nebula, security, ui, frontend, design, firewall]
---

# Nebula Control Plane — UI Implementation Plan

Companion to [[Nebula Control Plane - Admin UI Plan]] (the *what* — information
architecture, all 14 screens, settings, security posture) and the
[[Nebula Control Plane - Design Plan]] / [[Nebula Control Plane - Implementation Plan]].

This doc is the **how**: the visual design language, the front-end architecture,
and — at the center — the **group-tag / firewall visual designer**. It also does a
**competitive scan** to find gaps. The Admin UI Plan's screen catalog is assumed;
here we extend it, not repeat it.

> Convention: *(impl X)* = implementation-plan step; *(§X)* = design-plan section.
> "Console" = the Harbor web admin UI.

> **v2 (2026-06-13) — folded in a multi-perspective critique.** Headline changes:
> (1) a **backend track (A0 Admin API → A1 policy-analysis engine → A2 SSE
> emitter)** is now an explicit *predecessor* of the UI — none of those exist yet,
> and the front end is useless without them; (2) the policy designer's default view
> **flips from graph canvas to the reachability matrix** (the canvas becomes the
> comprehension/onboarding/demo view); (3) a **single-admin / configurable-quorum
> mode** (dual-control deadlocks a 1–2-admin org otherwise); (4) a committed
> **visual signature** (the §5 recipe was the generic shadcn template); (5) a
> first-class **fleet identity + health-rollup** model; and (6) honesty fixes
> (audit "chain-verified" overstated, CSP can't be a baked nonce, secret-shown-once
> on reload, JS supply chain). Superseded recommendations are marked **[v1→v2]**.

---

## 0. Reality check — what's built, and the backend the UI actually needs

The UI must not get ahead of the backend, and the v1 plan badly did: it described a
console against an admin API, a policy-analysis engine, an event stream, and an
authenticated human identity **that do not exist**. Today the only HTTP surfaces are
the public gateway (`/v1/enroll`) and the mesh-only `core-api` (`/v1/certs/renew`,
`/v1/heartbeat`) — authed by **source overlay IP** (a *device*, not a human). All
admin logic lives behind `harbor` **CLI verbs** that call Go packages + the DB
directly. The "actor" on a dual-control sign-off is a **CLI-supplied string**.

So the UI has two hard predecessors, tracked as a **backend track** that runs
*before/with* the UI track (see §11):

- **A0 — Admin HTTP API.** Lift the `harbor` command bodies into versioned
  `/admin/v1` handlers, write the OpenAPI, and **refactor the CLI to consume the
  API** so "CLI-parity / no UI backdoor" is *tested*, not asserted. Read endpoints
  (devices/fleet/audit) first. CI contract test: the OpenAPI is the only admin
  surface and the CLI's calls are a strict subset.
- **A1 — Policy analysis engine.** `internal/policy` today has only `Validate` /
  `CheckInvariants` / compile-per-host. The designer's whole value — **reachability
  query, flow-diff/blast-radius, and test assertions** — is net-new server code,
  not "cheap on the existing engine." Staged: (1) reachability query (compile both
  groups, intersect — powers the simulator *and* the matrix), (2) flow-diff across
  the host set (blast-radius), (3) assertion DSL + storage + publish gate.
- **A2 — Change/event emitter.** A fan-out (heartbeat upserts, rollout transitions,
  approval state) behind one multiplexed SSE endpoint. Until it exists, the rollout
  monitor polls.

Backed by **real data today** (after A0 exposes it): fleet/heartbeats
(`internal/fleet`, `coreapi`), enrollment + join keys + approval (`enrollment`,
`joinkey`), policy compile + invariants + dual-control (`policy`, `dualcontrol`),
lighthouse fleet (`lighthouse`), canary rollout (`rollout`), IPAM (`ipam`), audit
chain (`store.VerifyAudit`), AWS attestation evidence (`awsattest`), drift (`drift`).

**Gated on unbuilt backend** (screen ships when its data does): **A0/A1/A2** above;
**SSO/MFA + RBAC roles** (2.11 — the auth shell blocks on this; the dev-auth seam in
§8 unblocks dogfooding); immutable-fact **group map** (5.5); **revocation** (M7);
**CA/key rotation** (M8); **detections + reconciliation + WORM audit** (M9); device
**posture**; overlay **DNS**; subnet-router **routes** (DSL gap, §4).

---

## 1. Goals & principles

1. **Modern and sharp.** Dense, fast, dark-first ops tooling that looks like a 2026
   product, not an enterprise portal. The §5 design *signature* is a first-class
   deliverable, gated in UI-0 — not a recipe to be filled in later.
2. **Thin client, zero authority** (Admin-UI P-UI-1). The SPA holds no signing power
   and no business rules; every decision (RBAC, dual-control, invariants, tests,
   diff, blast-radius, **fleet health**) is **server-computed**. A compromised UI
   tier cannot sign a cert, bypass two-person approval, or lie about safety. UI
   stays out of the §2.1 TCB.
3. **API-first / CLI-parity.** Everything the console does goes through the *same*
   `/admin/v1` the CLI uses (A0). Enforced by a CI contract test, not a promise.
4. **Preview before commit.** Compile, invariants, reachability tests, blast-radius,
   and diffs precede every mutation — and the test results + diff are **snapshotted
   into the dual-control approval** (§4.4) so the approver evaluates exactly what
   the proposer ran (no TOCTOU).
5. **Provenance by default.** Every fact shows *why* (which group-map rule, which
   policy version, which attestation evidence, which approver).
6. **Accessible + keyboard-first.** ⌘K command palette; **the matrix is the
   keyboard/screen-reader primary**; the canvas is a comprehension view, not the
   only authoring path.

---

## 2. Competitive scan — gaps, deduped, with honest scoping

Surveyed: **Tailscale**, **Defined Networking (defined.net)** (commercial
managed-Nebula, our closest analog), **Headscale**, **ZeroTier Central**,
**Twingate**, **NetBird**, **Netmaker**, **Teleport**, **Cloudflare Zero Trust**,
and the micro-segmentation tools (**Illumio / Cisco Tetration / Guardicore**) whose
dependency-map→policy workflow is the gold standard for the firewall designer.

Action column is now three-valued: **Now** (backend exists or A0/A1 covers it) ·
**Later** (backend gap named) · **Out** (deliberately not us, with the reason).

| Capability | Best-in-class | Status | Action |
|---|---|---|---|
| Machines list + device detail | Tailscale, defined.net | ✅ | Now |
| Policy editor w/ inline **tests** that gate publish | Tailscale | ❌ (A1) | **Now** |
| **Reachability matrix** authoring (from×to grid) | *nobody ships cleanly* | ❌ (A1) | **Now — differentiator + hero (§4/§5)** |
| Reachability/"why-reachable" query + **nearest-miss** | AWS VPC Reachability Analyzer | ❌ (A1) | **Now** |
| `internet` / egress pseudo-target ("who may reach the internet") | Tailscale autogroup:internet | ❌ (DSL) | **Now — cheapest high-value rule** |
| Device approval queue + enroll keys | Tailscale, defined.net | ✅ | Now |
| Live **topology map** (comprehension) | NetBird, ZeroTier, Tetration | ❌ | **Now (policy-permitted) / Later (live)** |
| Tag/group **delegation** (who may assign a tag) | Tailscale `tagOwners` | partial | Later |
| **Subnet routers / `unsafe_routes`** (reach a non-mesh CIDR via a node) | Tailscale, NetBird, Netmaker | ❌ (DSL needs a CIDR destination) | **Later — most-used feature after admit (§4)** |
| Flow-**diff** / blast-radius on change | (weakly: Tailscale text diff) | ❌ (A1) | **Now — the highest-stakes screen** |
| Observed-flows → propose-allow ("ghost layer") | Illumio / Tetration | ❌ | Later (rides the live-tunnel overlay) |
| Key/CA expiry + rotation UX | Tailscale, defined.net | planned | Later (M8) |
| Audit / activity log + **tamper-evidence** | all (weaker) | ✅ chain; WORM ❌ | Now (honest label, §8) / Later (WORM = the lead) |
| JIT **time-boxed group** via approval | Teleport | dual-control adjacent | Later (named feature, reuses dual-control) |
| API tokens / service accounts | Tailscale | ❌ | Later |
| Webhooks / SIEM / integrations | Tailscale, Cloudflare | settings-only | Later |
| Overlay **DNS** | Tailscale, NetBird | deferred (lighthouse.dns) | Later |
| Device **posture** gating | Twingate, Cloudflare | facts only | Later (cross-platform = M10) |
| Guided first-run onboarding | defined.net, NetBird | ❌ | Now (console onboarding; genesis stays CLI) |
| "Is A reachable from B **right now**?" live probe | NetBird | ❌ (no backend can cash it) | **Out — reframed (below)** |
| Central flow logs / access analytics | Cloudflare, Twingate | ❌ by design (P3) | **Out (reason below)** |

**[v1→v2] Cut the live connectivity probe** from the differentiation story — the
Pilot reports heartbeats to Core, not peer reachability, so no endpoint can answer
it without net-new agent work. Lead with the **policy reachability query** and label
it honestly: **"will-it-be-permitted"**, not "is-it-reachable-now."

**Deliberately out of scope (and why):** SSH-user ACLs + session recording (we're
L3, not an SSH proxy); resource/app-centric access (we're a network firewall, not an
app gateway); central flow capture (design P3 — control plane off the data path).
The one portable idea from that neighborhood worth keeping is Teleport's **JIT
time-boxed access**, recast as "request a group membership that expires" on top of
dual-control.

---

## 3. Product surface, the Dashboard, and the Fleet model

Keep the Admin UI Plan's 14-area IA. The user named three things explicitly — a
fleet **overview dashboard**, the fleet **description**, and its **status** — and v1
under-served all three. Here they are, defined.

### 3.1 "Fleet description" = a first-class Fleet Identity object
The noun the rest of the console describes. Make it inventory **and** identity **and**
topology:
- **Masthead** (top of dashboard): network name + **environment chip** (prod/staging
  tint) · overlay CIDR + utilization · lighthouse count ("3 lighthouses, all
  reporting") · active CA fingerprint(s) + config-signing key · active policy version
  + publish date/approvers · node/group totals. The Tailscale "tailnet header"
  analog; every field exists (IPAM + lighthouse registry + keys + policy-active + env).
- **A dedicated Fleet/Network description page** (split from the dashboard): the
  slower-changing identity + full inventory snapshot (nodes by state/platform/cloud/
  group, lighthouse topology, CIDR/pool layout, CA/trust posture, current policy +
  approvers) — an **exportable "here is what this mesh IS"** sheet for onboarding an
  operator or an audit handover. Masthead = teaser; this page = full sheet.

### 3.2 "Fleet status" = one server-computed health rollup (not a wall of gauges)
The client must not decide health (thin-client). One endpoint:
`GET /admin/v1/fleet/health → {status: critical|degraded|healthy, reasons:[{code,
severity, count, link}]}`, status = max severity. Reason codes map 1:1 to backend facts:
- **CRITICAL:** `AUDIT_CHAIN_BROKEN` · `LIGHTHOUSE_UNREACHABLE` (any drop — discovery
  SPOF) · `CERTS_EXPIRED` · `ROLLOUT_ROLLEDBACK` (auto-frozen) · `IPAM_EXHAUSTED`.
- **DEGRADED:** `CERTS_EXPIRING` (cliff) · `HOSTS_STALE` · `CLOCK_SKEWED` ·
  `DRIFT_SPIKE` · `ROLLOUT_IN_PROGRESS` · `APPROVALS_AGING`.

The same definition feeds the dashboard verdict, `harbor fleet -alert` (already
exits non-zero), and webhooks/SIEM — no drift between surfaces. **Audit-chain failure
and drift spikes are part of the rollup math**, not isolated tiles — integrity *is*
fleet health.

### 3.3 Dashboard layout (replaces the v1 stat-grid)
Verdict-first, single scannable column:
1. **Fleet Identity masthead** (§3.1), led by a plain-language sentence — *"142 hosts
   across 4 regions, all healthy, policy v37 fully rolled out, audit chain verified"* —
   a human line with inline status dots beats a grid of numbers.
2. **Health verdict** — one big Healthy/Degraded/Critical chip + severity-ordered
   reason chips (§3.2). The 3-second answer.
3. **Active operations strip** — lights up only when something's happening: live
   "rollout wave X/Y converging," a red "ROLLOUT AUTO-ROLLED-BACK — frozen" banner
   with jump-to, pending approvals as *actionable rows* ("Policy v42 — awaiting 2nd
   approver, 3h"). Collapses when idle.
4. **Full-width topology map hero** — the literal picture of the mesh (lighthouses
   highlighted, **policy-permitted** edges — labeled as *permitted reachability*, a
   static compile, so the §5 motion never implies live flow).
5. **Three focused cards:**
   - **Renewal cliff** — a 30-day expiry **timeline that flags clustering** (a cohort
     all expiring one Tuesday = renewal-storm / mass age-out; cert lifetime is "the
     outage budget"), + top-5 soonest with one-click force-renew; lighthouse/control-
     plane certs called out louder.
   - **Lighthouse availability** — always-visible, **separate from device counts**:
     "3/3 reachable" + per-lighthouse last-heartbeat + cert-expiry. Escalates to
     CRITICAL the moment reachable count drops or any lighthouse cert hits the cliff
     (closest thing to a global outage; the never-zero *registry* invariant does NOT
     tell you a lighthouse is *down right now*). *(Data flows once lighthouses
     heartbeat.)*
   - **Trust integrity** — audit chain status (honestly labeled, §8), drift 24h
     sparkline, genesis intact. Calm always; loud-red only when broken.
6. **Fleet convergence gauge** — "% of fleet on policy v42, Y lagging" from
   `applied_bundle_version`. A mesh-health signal competitors structurally can't show.
7. Recent audit highlights + enrollment funnel at the bottom.

### 3.4 Other surface deltas
- **Policy** → the **Policy & Group-Tag Designer** (§4), default = matrix.
- **Groups** merge into the designer's Tags rail (taxonomy, zones, colors,
  provenance, delegation) — groups and their rules edited in one place.
- **Devices** gains attestation evidence + heartbeat facts (posture-gating is Later).
- New: **Automation** (API tokens/webhooks — Later) and **Onboarding** (console
  empty-states + a "get started" checklist; genesis stays a CLI/offline ceremony).
- Everything else per the Admin UI Plan, with §5's design language and §8's
  dual-control/preview patterns applied uniformly.

---

## 4. The Policy & Group-Tag Designer (the centerpiece)

*"Design a group tag layout for firewall design."* One workspace, **three
synchronized views of one model**, plus a live analysis rail (all analysis is
server-side, A1). **Backend predecessor: A1.**

### 4.1 The model — and the DSL gap to close first **[v1→v2]**
- **Groups (tags)** — the unit of policy; membership from the group map (5.5) or
  manual. The designer edits *rules between groups*.
- **Allow rules, default-deny.** Today the DSL is `allow <from> -> <to> <proto>
  <port>` — **one proto + one port per rule**, no ranges, no `any`, no port-lists;
  ICMP is baseline-only. v1 promised stacked port chips the language can't store.
  **Decision: extend the DSL to a port-set/ranges per rule** (`allow web -> db tcp
  5432,8000-8099` and `tcp any`) — Nebula's firewall supports this natively, so one
  edge with N chips = **one rule**, and the matrix cell, diff, and tests all operate
  on the same unit. Steal Tailscale's port syntax (`80,443,8000-8999,*`). `any` and
  "ICMP is baseline-only, not authorable" are defined in the UI; the port picker
  offers only what the DSL can encode.
- **Reserved/baseline** — control-plane + lighthouse reachability + ICMP are a
  mandatory baseline; rendered **locked** (dashed, undeletable) as a teaching surface.
- Output: compiled per-host firewall → signed bundle → dual-control publish → canary
  rollout → drift-revert.

### 4.2 Default view = the Reachability Matrix **[v1→v2: was the graph canvas]**
A groups × groups **from→to grid**, dense and monospaced — the daily authoring
surface, the keyboard/a11y primary, and the **hero screen** (§5). Why this, not the
graph: a directed group→group graph hairballs past ~12–15 groups, and its edge labels
(the ports) *are* the policy content — they collide exactly where it matters. "Design
a tag layout" is a grouping/zoning task the matrix expresses honestly. Illumio/
Tetration learned this: the *map* is for comprehension; real authoring is tabular.

- **Authoring feel:** arrow to a cell → Enter → type `5432` → allow. Drag-fill a row
  or column; shift-select cell ranges; set/clear ports across a selection; **copy one
  group's ruleset and paste onto others** ("make these behave like web").
- **Legible default-deny:** allowed cells **accent-tinted** (shade by port-count);
  denied cells carry a faint **diagonal hatch** so empty reads as *actively denied*,
  not unconfigured. Sticky group headers with color bars; hover cross-hair lights the
  full row + column.
- **State the semantics in-UI:** a cell = "A may **initiate** to B on these ports;
  return traffic is automatic" (stateful / SG-like, **not** NACL-like). When someone
  adds both A→B and B→A, surface "you already allow web→db; this adds db→web (db
  initiating) — return traffic is automatic, did you mean that?" + a one-click "make
  bidirectional" for genuine peer cases. (The exact footgun Illumio/Tetration spend
  UX on.)

### 4.3 The Tag Canvas — comprehension / onboarding / demo (secondary)
Still gorgeous, still the dashboard topology showpiece — but not the default editor.
Two jobs it's genuinely good at:
- **From-scratch zone layout** (onboarding gesture): drop groups into zones (*DMZ /
  App / Data / Mgmt*), express tiers. **Empty state shows only the locked baseline**,
  annotated *"Everything else is denied. Draw an edge to allow."* — so the first
  concept a newcomer meets is default-deny + guaranteed reachability, made visible.
  Offer templates (3-tier, hub-spoke, flat) or import from the group map.
- **"Show me everything that can reach `db`"** — select a node → ego-graph highlight.

Above ~15 groups the canvas defaults to a **zone-level view** (4–6 zone super-nodes,
aggregated edges "App→Data: 3 rules"), drill in to expand — the Tetration pattern.
Not for typing `5432` into edge labels.

### 4.4 Live analysis rail + the publish pipeline (server-computed, A1)
- **Invariant checklist** (6.3): control-plane reachable, lighthouse discovery
  intact, no reserved-group refs. **Publish blocked on red.**
- **Compiled preview** (6.2): pick a host/group → its exact inbound/outbound (baseline
  injected).
- **Reachability query = test-authoring loop:** the query bar and the test suite are
  one surface. "laptops → db:5432 = **DENIED** (no rule)" → **"+ Save as test"** →
  `assert deny laptops -> db tcp 5432`. Steal AWS Reachability Analyzer's **"why"**:
  on YES show the granting rule; on NO show default-deny **and the nearest-miss**
  ("there's web→db on tcp/443 but not tcp/5432") → a binary answer becomes a one-edit
  fix. Tests run on every edit and **gate publish**; a flipped-red test scroll-to
  highlights both the assertion and the rule that changed it. Seed a test from the
  baseline invariants so newcomers see one for free.
- **The diff is the highest-stakes screen in the product** (a human approving a
  firewall change) — a first-class visual artifact, not a rail tile. Overlay matrix:
  added cells glow accent; **removed cells glow amber-warning** (losing reach =
  potential outage, louder than adding); changed ports show old→new chips; affected-
  host count on hover; click a removed cell → "removes db access for 14 hosts in zone
  App." Canvas mode: new edges animate in, removed strike through red. Far beyond
  Tailscale's plain-text HuJSON diff — a real differentiator.

**Publish path:** `Draft → validate (invariants + tests green) → request publish
(dual-control 6.5) → reviewer sees the matrix/canvas diff + blast-radius + test
results → approve (distinct admin, or single-admin mode §8) → canary rollout (6.6)
monitor → auto-rollback armed`. **Snapshot `{draft hash, test results, flow-diff,
affected-host list}` into the approval record** so the approver evaluates exactly what
the proposer ran (closes the TOCTOU gap if the active policy moves underneath).
Version history with one-click rollback; drift panel (6.7).

### 4.5 Scale, zones-as-aggregation, and granularity gaps
- **Zones are a first-class authoring primitive**, not cosmetic swimlanes:
  `allow web -> zone:Data tcp 5432` expands to one allow per group in the zone, shown
  as one fat edge / merged cell-block with a disclosure to see/override the
  expansion. "All of Data except secrets" = author the zone rule, delete the one
  expanded edge → UI shows "zone:Data minus secrets-store." This gives exception
  ergonomics **without** putting deny-rules or ordering into the signed policy (keep
  it pure-allow + default-deny — deny-exceptions fight the clean model and the
  invariant checker).
- **Cheap high-value targets:** an **`internet`/egress pseudo-target** (the most
  common first firewall question — elegant as a matrix column: "web may reach the
  internet, db may not"), and a **`self`/same-group** shorthand. For single-host
  exceptions, a **host-as-ad-hoc-target** affordance rather than forcing one-member
  groups (the Tailscale anti-pattern that bloats the taxonomy).
- **Subnet routers / `unsafe_routes`** *(Later — DSL gap)*: the most-used overlay
  feature after device admit, and our group→group DSL can't express `allow web ->
  10.0.5.0/24`. Plan: a CIDR destination form (a "route target" pseudo-group) +
  route advertisement & admin approval in enrollment (mirror Tailscale's
  "approve advertised routes"). Render an advertised route as a special node so edges
  into it are authorable. Flagged now so the model leaves room for it.
- **Observed → proposed ("ghost layer"), design for it now** *(Later)*: when the
  opt-in host-reported live-tunnel overlay (Decision #5) lands, render observed-but-
  not-allowed flows as faint dotted edges with "+ allow," allowed-and-observed with a
  "seen in 24h" check, and allowed-but-never-observed as removal candidates — the
  Illumio/Tetration closed loop, without violating P3 (opt-in summary, not central
  flow capture).

### 4.6 Implementation notes
- Matrix (default + hero): virtualized grid (**TanStack Table/Virtual**), zone-grouped
  collapsible rows/cols; maps 1:1 to the rule model (no graph-layout problem) — build
  this first to de-risk the model + A1 analysis.
- Canvas (secondary): **xyflow / React Flow** with custom nodes + orthogonal edge
  routing (§5). *Note:* xyflow is fine for the bounded policy canvas; the **fleet
  topology map uses a WebGL renderer (Sigma.js / Cytoscape)**, not xyflow, at
  hundreds of nodes.
- DSL view: **CodeMirror 6** + custom mode; lint via debounced `POST /admin/v1/
  policy/compile?dry_run` (server is the single source of validity).
- **Undo/redo on the canonical policy model** (one command stack shared by all three
  views; ⌘Z everywhere); distinguish model edits (undoable, recompile) from layout
  edits (undoable, cheap). "Lossless round-trip across views" is an explicit Vitest
  target. Local state in **Zustand**; layout/zone/color in a sidecar that never
  enters the signed policy.

---

## 5. Visual design language — committed signature **[v1→v2: was a generic recipe]**

The v1 recipe (dark + one accent + Inter + 6–8px radius + Lucide + subtle shadows)
is *verbatim* the shadcn default — follow it and you ship an anonymous Cal.com/Dub
clone, failing the #1 goal on the exact axis the user cares about. Commitments:

- **Accent = meaning, picked now.** A single **Nebula-blue** that *means*
  "permitted / allowed / healthy reachability" everywhere — permitted edges on both
  canvases, allowed matrix cells, the topology map, the rollout bar. Brand color
  bound to the product's core concept (an allow-list firewall). Stop saying
  "indigo/cyan."
- **Custom 11-step neutral ramp**, slightly **blue-cool** (not stock zinc/slate), on
  a true near-black (~#0A0B0D). Tokens named for the domain (`surface` / `mesh` /
  `edge`), not `card`/`popover`.
- **ONE signature motif:** a single **"propagation" motion language** — directional
  dashes / a traveling pulse — shared across the three places things flow through the
  fleet over time: **canary rollout waves, lighthouse/blocklist propagation %,**
  and (future) **live handshakes**. Same easing, same accent; permitted edges use a
  slow version at rest. Grounded in heartbeat events we already emit. This is what
  makes it instantly *ours* (cf. Stripe's gradient, Linear's cycle animation). A
  faint **mesh-grid texture** on hero/empty surfaces so even empty looks branded.
- **Type:** **Geist + Geist Mono** (more engineered than Inter, and distances us from
  the Inter-everywhere crowd). Compact scale (12/13/14/16/20/24/32, **body 13px**,
  metadata 11–12px), `tabular-nums` on all numerics, header tracking −0.01…−0.02em.
- **Borders-first elevation, not shadows:** e0 base; e1 = +3% lightness + 1px
  hairline; e2 = +6% + border; shadows **only** for true overlays (popover, ⌘K).
  Radius 6px (4px on inputs/chips). ~32px default row height. First Storybook page.
- **Charts:** **drop Tremor** (rounded pastel bars read as a template) — a thin
  in-house **visx** layer: 1px line strokes, no/low fills, dotted neutral gridlines,
  mono tabular axis labels, series muted to ~40% until hover, no rounded bar caps, no
  drop-shadows. A real **histogram** for cert-expiry; a **custom stepped/waterfall**
  rollout-wave monitor (not a progress bar); inline sparklines in the Devices table.
- **Canvas/matrix look like circuit diagrams, not default React Flow:** group nodes =
  compact dark chips with a left color-bar + mono member-count + provenance glyph +
  hatched-border lock for reserved groups; **orthogonal (manhattan) edge routing**
  (the single biggest "we did custom work" tell); port chips as tiny mono pills;
  zones as subtle domain-tinted swimlanes. The topology map reuses the same node/edge
  language so the two feel like one system.
- **The ONE hero screen:** the **Reachability Matrix** — a tight monospaced heatmap
  from×to grid (a firewall crossed with a GitHub contribution graph). Novel in this
  space, screenshot-able, and already on the build path. Topology hero is a close
  second.
- **Design gate (UI-0):** before any feature screen, produce 3 hi-fi comps (dashboard
  hero, Tag Canvas at ~12 groups, reachability matrix), placed beside real
  screenshots of Tailscale / defined.net / NetBird / a Linear board. Proceed only if
  Harbor's comps are distinguishable from a stock shadcn template **and** hold up next
  to Linear. Cheaper than discovering at UI-4 that the centerpiece looks like a
  template.

A **Storybook** holds tokens + components + the chart kit + canvas/matrix as the
living style guide and visual-regression surface.

---

## 6. Front-end architecture

**Stack:** **React SPA** (Vite + TS), **Tailwind + shadcn/ui (Radix)**, **TanStack
Query / Table / Virtual**, **CodeMirror 6** (DSL), **xyflow** (policy canvas),
**Sigma.js or Cytoscape** (fleet topology map at scale), **visx** (charts — single
lib, no Tremor), **Zustand** (editor state), **Playwright + Vitest**.

*Why a real SPA (reversing the Admin UI Plan's HTMX lean):* the matrix authoring,
live analysis rail, topology map, and rollout monitor are genuinely rich-client. We
keep the posture by making the SPA a **strict dumb client** (no authority, all
decisions server-side, strict CSP, no secrets in JS) — richness *and* out of the TCB.

- **State:** TanStack Query for server data (optimistic only for *non-privileged*
  actions); Zustand for ephemeral editor state; URL holds filters/selection.
- **Routing:** typed routes; deep links to any object (device, policy version, audit
  row) for incident sharing.
- **Real-time (A2):** **one multiplexed SSE endpoint** `GET /admin/v1/stream?topics=
  heartbeats,rollouts,approvals` on a single connection (avoids the ~6-conn HTTP/1.1
  cap — confirm HTTP/2 on the embedded server), authed by the **session cookie**,
  envelopes carry topic + monotonic id for `Last-Event-ID` resume. Mutations stay on
  fetch+CSRF; SSE is read-only (that's *why* WebSocket is deferred). On session
  expiry, hard-close and re-auth — **never paint stale heartbeats**. Every live tile
  shows "updated Ns ago / stream stale," and a degraded banner ("Console can't reach
  Core — the mesh may be down; use the break-glass runbook"). The rollout monitor can
  simply poll `status` every 1–2s until A2 lands.
- **Data scale:** dashboard aggregates + table pages are computed **server-side**
  (cursor pagination, server filter/sort); virtualize what we render. The `/fleet/
  health` rollup (§3.2) is one server call, not 10k rows.
- **Code-split** by area; canvas/topology/charts lazy-load.

---

## 7. API & data contract (A0)

- **One versioned admin API** `/admin/v1/...`, the same the CLI uses. Resource-
  oriented: `devices`, `enrollments`, `joinkeys`, `groups`, `policies` (+ `/compile`,
  `/tests`, `/diff`, `/reachability`), `rollouts`, `lighthouses`, `ipam`, `keys`,
  `approvals`, `audit`, `settings`, `tokens`, plus `me` and `fleet/health`.
- `GET /me → {principal, roles, mfa_satisfied_at}` and `GET /fleet/health` (§3.2) are
  load-bearing; sign-offs bind to the **authenticated principal**, never a free-text
  actor.
- **OpenAPI-first**, generate the typed TS client → client/server drift is a compile
  error. **CI contract test:** the OpenAPI is the only admin surface; the CLI is a
  strict subset (enforces "no UI backdoor").
- **Conventions:** cursor pagination, filtering, field selection, `ETag`/`If-Match`
  (optimistic concurrency on policy/settings), `Idempotency-Key` on mutations,
  problem+json errors rendered inline.
- **Dual-control + analysis as data:** an approval is a first-class resource carrying
  the **snapshotted diff/tests** (§4.4). `compile` / `diff` / `reachability` /
  `tests` / `fleet/health` are **server endpoints**; the client renders, never
  recomputes safety (A1).

---

## 8. Security implementation

- **Auth (blocks on 2.11; dev-seam unblocks dogfooding):** OIDC **Auth-Code + PKCE**;
  session in an **httpOnly, Secure, SameSite** cookie (no tokens in JS); short TTL;
  silent refresh; **step-up auth** for privileged actions. **Dev-auth seam:** one
  server-side `AdminIdentity` interface with two impls — real OIDC, and an
  env-gated, CI-blocked **`X-Harbor-Dev-Actor`** header — so the running app exercises
  RBAC + dual-control (which needs two *distinct* actors) against a seeded Harbor long
  before 2.11. Until OIDC lands, the only honestly-shippable app is mesh-only behind
  the dev seam.
- **RBAC:** server-enforced on every endpoint; client also hides what the role can't
  do (defense in depth, not the control). Read-only default.
- **Dual-control UX + single-admin mode [v1→v2]:** privileged actions create a
  request a *distinct* admin approves; self-approve impossible (server-enforced); one
  **Approvals inbox** aggregates all pending two-person actions, each showing the
  snapshotted diff. **But two-person control deadlocks a 1–2-admin org** (your own
  AWS demo is one operator). So quorum is a **configurable site setting** with a
  documented **single-admin mode**: default two-person ON, **loud audit + persistent
  env-tint banner when OFF**, plus a designated **break-glass approver** / the CLI
  break-glass path as a valid second sign-off when the IdP/mesh is down. The approval
  screen detects "you are the only admin" and explains it instead of showing a dead
  Approve button.
- **Hardening:** **hash-based CSP** (sha256 of bundled scripts, computed at build —
  a baked nonce can't live in a static `go:embed`'d `index.html`; nonces would force
  per-request templating), no inline/eval, audit Radix/CodeMirror/xyflow for inline-
  style needs up front (avoid `style-src 'unsafe-inline'`); SRI; CSRF tokens on
  mutations; no secrets client-side; framing denied. **JS supply chain is TCB-
  adjacent** (a compromised dep runs in the admin's authenticated session): frozen
  lockfile, npm provenance/SLSA verified in CI, a **blocking** SCA gate, and **fold
  the embedded UI bundle into the Core release signature/SBOM** — turning `go:embed`
  from convenience into a security property.
- **Secrets shown once (reload-safe):** join-key secrets + API tokens live only in
  transient React state (never the query cache, never the URL); the create-result
  modal is **non-routable** (reload = gone, by design) with an "I've saved it" gate +
  download-as-file + one-click **regenerate** (revoke+reissue) from the orphaned key's
  row; afterward only last-4/fingerprint is shown.
- **Audit affordance (honest) [v1→v2]:** mutations state "this will be logged as …"
  and link the audit row. **Until WORM (2.13) ships, label audit "chain
  self-consistent (in-DB) — does not detect tail truncation"** (the server returns
  the verification result + which anchor it checked); the trust-integrity tile shows
  WORM anchoring as "not configured." A confident green check we can't back is worse
  than nothing.

---

## 9. Non-functional

- **Accessibility:** WCAG 2.2 AA; **the matrix is the keyboard/screen-reader primary**
  (the canvas is a comprehension view, so a11y doesn't hinge on a graph); full
  keyboard paths; ARIA live regions for rollout/approvals/health; axe in CI.
- **Performance:** initial shell < ~200KB gz (canvas/topology/charts lazy); table
  interactions < 50ms; dashboard first data < 1s; virtualize large lists.
- **Resilience:** never present stale data as live (§6 stale indicator + degraded
  banner) — this is an incident tool.
- **Testing:** Vitest + Testing Library; **Playwright E2E** against a seeded Harbor
  (enroll→approve, **policy author→test→dual-control publish→canary**, single-admin
  publish, lighthouse swap, bulk-revoke guardrails, lossless view round-trip); visual
  regression; axe; **OpenAPI contract tests**.
- **i18n-ready; theming** (dark/light + env tint, tokens drive all); **observability**
  (scrubbed client errors, UX telemetry on high-stakes flows, feature flags).

---

## 10. Build & delivery

- **Location:** `ui/` (pnpm + Vite). Built assets **embedded in the Core binary via
  `go:embed`**, served by a static handler over the mesh — single artifact, lockstep
  UI↔API versioning, minimal footprint. Confirm **HTTP/2** on the embedded server
  (SSE multiplexing) and **hash-based CSP** at build time (§8).
- **CI:** lint/typecheck/test/build; SCA blocking gate + provenance; Playwright on an
  ephemeral seeded Harbor; Storybook + visual-regression; bundle-size gate; UI bundle
  folded into the Core SBOM/signature.
- **Versioning:** UI pinned to its Core build; API is the N/N-1 compatibility contract.

---

## 11. Phasing — two parallel tracks **[v1→v2: was UI-only UI-0…UI-6]**

The v1 UI-0…UI-6 pretended the backend was done. Reframe as a **backend track** and a
**UI track** with explicit handoffs.

**Backend track (predecessor):**
- **A0 — Admin API + dev-auth seam** (gates everything): `/admin/v1` read endpoints,
  OpenAPI, CLI refactor + contract test, `AdminIdentity` seam, `me`, `fleet/health`.
  - ✅ **A0.1 (2026-06-13)** — `internal/adminapi` + `harbor admin-api` (mesh-only):
    the **dev-auth seam** (`IdentityProvider` / `DevHeaderProvider`, env-gated),
    read endpoints `me` · `fleet/health` · `devices` · `audit`(+`/verify`) ·
    `lighthouses`, the **server-computed health rollup** `fleet.Rollup` (§3.2,
    healthy/degraded/critical + reason codes), keyset pagination, problem+json.
    Adversarially reviewed (14-agent workflow): fixed audit "couldn't-check" vs
    "tampered" conflation (new `store.ErrAuditTampered`), error-string leakage,
    `reasons: null`, `/devices` cursor, 401-not-503, role-null. Tested + live-smoked.
  - ✅ **A0.2 (2026-06-13)** — **OpenAPI 3.0 spec** for the A0.1 endpoints
    (`internal/adminapi/openapi.yaml`, embedded + served unauthenticated at
    `GET /admin/v1/openapi.yaml`), routes made **data-driven** (`Server.Routes()`),
    and a **contract test** (kin-openapi, test-only dep) that fails on drift:
    the spec validates, documented operations **exactly equal** the served routes
    (both directions), and **every live 200 body is validated against its schema**.
  - ⬜ **A0.3+** — generate the **TS client** (once `ui/` exists); **mutating
    endpoints** (approvals/policy/joinkeys/lighthouse/rollout); refactor the
    `harbor` CLI onto the API; CI test that the **CLI ⊆ the OpenAPI surface**.
- **A1 — Policy analysis engine** (gates UI-4): reachability query → flow-diff/blast-
  radius → assertions + publish gate, snapshotted into approvals.
- **A2 — SSE change emitter** (upgrades UI-2+ live views; polling until then).
- (Independently: **2.11** SSO/MFA/RBAC upgrades the dev seam to real auth.)

**UI track (each phase front-to-back, no screen before its data):**
- **UI-0 — Foundation + design gate** *(needs A0):* design system + Storybook + the
  3-comp design gate (§5); app shell (nav, ⌘K, env tint); generated API client; the
  dual-control/preview/destructive-action primitives. Ship **read-only Dashboard
  (with the §3 fleet identity + health rollup) + Devices + Audit on the dev-auth
  seam** — a *running, data-backed* demo, not just Storybook. Real OIDC/MFA = **UI-0b**
  when 2.11 lands.
- **UI-1 — Enrollment** *(M3):* approval queue, join keys (auto-issue warned),
  conflict/admit inbox, funnel, quotas; console onboarding checklist + empty-states.
- **UI-2 — Fleet health** *(M4):* expiry/cliff + lighthouse-availability + trust-
  integrity cards, version landscape, heartbeat detail, **topology map v1**
  (policy-permitted). Live via A2 or polling.
- **UI-3 — Identity facts** *(M5):* group-map editor + cloud-trust settings;
  attestation evidence on device detail.
- **UI-4 — Policy & Group-Tag Designer** *(M6 + A1) — the headline:* matrix-default
  + canvas + DSL, the analysis rail (reachability/tests/diff/blast-radius),
  single-admin-aware dual-control publish, canary monitor, drift panel; Network/IPAM.
- **UI-5 — Trust ops** *(M7–M8):* revocation/blocklist + propagation SLO; CA/key
  rotation wizards; lighthouse fleet management.
- **UI-6 — Enterprise** *(M9):* detections + reconciliation, full Settings, Access/
  RBAC admin, System/ops, Automation (tokens/webhooks), break-glass log, overlay-DNS
  placeholder, JIT time-boxed group.

---

## 12. Risks

- **Backend-not-built (P0/P1):** the UI is worthless without A0/A1; they're multi-
  milestone and invisible in v1. Mitigate: the A-track is now an explicit predecessor
  with the API read endpoints + reachability query sequenced first.
- **Auth dependency (P2):** the console blocks on 2.11. Mitigate: the **dev-auth
  seam** gives a running, data-backed app early; OIDC is a clean swap behind one
  interface.
- **Single-admin deadlock (P6):** without single-admin mode the product bricks for
  its first cohort. Mitigated by the configurable quorum (§8).
- **Generic look:** the §5 recipe was a template; mitigated by the committed
  signature + the UI-0 design gate.
- **Canvas at scale:** mitigated by matrix-as-default + zone aggregation + a WebGL
  topology renderer.
- **Stale-as-live during incidents:** mitigated by the SSE stale/degraded indicators.

---

## 13. Decisions

### Reaffirmed (2026-06-13, first review)
1 Rich SPA (React+Vite) · 2 shadcn/ui+Tailwind · 5 topology policy-permitted-now/
live-later · 6 "groups" naming · 7 embed via `go:embed` · 8 read-only role + signed
exports · 9 posture backlogged · 10 break-glass CLI-only · 11 genesis CLI + console
onboarding · 12 SSE + polling fallback.

### Revised / added by the critique **[v1→v2]**
| # | Decision | Now | Why |
|---|---|---|---|
| 3 | Designer default view | **Reachability Matrix** (canvas → comprehension/demo) | Graph hairballs past ~15 groups + port labels collide; matrix is the authoring + a11y + hero surface. |
| 4 | Policy tests | Gate publish + **snapshot tests/diff into the approval** | Closes the TOCTOU gap; reachability query first (powers matrix too). |
| 13a | **Single-admin mode** | Configurable quorum, default two-person ON, loud when OFF | Dual-control otherwise deadlocks a 1–2-admin org (our own demo). |
| 13b | **DSL port-sets/ranges** | Extend DSL (`tcp 5432,8000-8099`, `tcp any`) | Nebula supports it; makes one edge = one rule for chips/diff/tests. |
| 13c | **Charts = visx only** | Drop Tremor | Tremor reads as a template; visx + thin in-house kit. |
| 13d | **Topology renderer** | Sigma.js/Cytoscape (WebGL), not xyflow | xyflow for the bounded policy canvas only; WebGL for fleet-scale graphs. |
| 13e | **Visual signature** | Accent=permitted, propagation motif, Geist, borders-first, matrix hero, UI-0 design gate | The §5 recipe was the generic shadcn default. |
| 13f | **Backend A-track** | A0 API → A1 analysis → A2 SSE as predecessors | The UI assumed servers that don't exist. |
| 13g | **Dev-auth seam** | `AdminIdentity` interface; dev header impl | Dogfood RBAC + dual-control before 2.11. |
| 13h | **Live connectivity probe** | **Cut**; use "will-it-be-permitted" query | No backend can answer "reachable right now." |
| 13i | **Audit badge** | "chain self-consistent (in-DB)" until WORM | Don't claim tamper-evidence we can't back. |

### Still open (decide during build)
- Collaborative multi-operator canvas editing → would flip Decision 12 to WebSocket.
- Subnet-router DSL form (CIDR destination) — needs a backend DSL extension; scope at M7-ish.
- Whether the onboarding checklist is dismissible/persistent per-org.

## Sources / references
- [[Nebula Control Plane - Admin UI Plan]] — IA, screen catalog, settings, UI security posture.
- [[Nebula Control Plane - Design Plan]] / [[Nebula Control Plane - Implementation Plan]] — backend surface the UI consumes.
- Competitive/design: Tailscale (ACL tests, tagOwners, autogroup:internet, key expiry), defined.net (managed-Nebula roles, enrollment), NetBird (topology, routes, posture), ZeroTier (flow rules), Twingate/Cloudflare (posture), Teleport (JIT access requests), Illumio/Cisco Tetration/Guardicore (dependency-map→policy, micro-segmentation maps), AWS VPC Reachability Analyzer (the "why"), Linear/Vercel/Grafana (visual bar).
