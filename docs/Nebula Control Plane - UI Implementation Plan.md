---
created: 2026-06-13
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
**competitive scan** to find features we've missed, and fills functional gaps. The
Admin UI Plan's screen catalog is assumed; here we extend it, not repeat it.

> Convention: *(impl X)* = implementation-plan step; *(§X)* = design-plan section.
> "Console" = the Harbor web admin UI.

---

## 0. What's actually built (the data the UI can show today)

The UI must not get ahead of the backend. As of M0–M6 done + M5 started, the
console can be backed by real APIs for:

- **Fleet/Devices/Heartbeats** — `internal/fleet`, `coreapi` heartbeats (last-seen, versions, applied bundle version, cert expiry, clock skew, health).
- **Enrollment + join keys + manual approval** — `internal/enrollment`, `joinkey`, gateway (PENDING queue, approve/deny, scoped/capped/revocable keys, quotas).
- **Firewall policy + dual-control publish** — `internal/policy` (group allow-DSL, compile-per-host, invariants), `internal/dualcontrol` (two-person approvals).
- **Lighthouse fleet** — `internal/lighthouse` (add/replace/remove, never-zero invariant).
- **Canary rollout** — `internal/rollout` (waves, convergence, auto-rollback, status).
- **IPAM** — `internal/ipam` (pools, sub-ranges, allocations, quarantine).
- **Audit** — `internal/store` hash-chained log + `VerifyAudit`.
- **AWS attestation** — `internal/awsattest` (evidence for device detail).
- **Drift** — `internal/drift` (per-host revert events).

**Gated on unbuilt backend** (screen ships when the API does): SSO/MFA + RBAC roles
(2.11 — *the auth shell blocks on this*), immutable-fact **group map** (5.5),
**revocation/blocklist** (M7), **CA/key rotation** (M8), **detections + reconciliation
+ WORM audit** (M9), device **posture** facts, overlay **DNS**. The plan calls these
out per screen so we build front-to-back, never a screen with no data.

---

## 1. Goals & principles

1. **Modern and sharp.** Dense, fast, dark-first ops tooling that looks like a 2026
   product, not an enterprise portal. Information design over decoration; motion is
   fast and purposeful; the firewall designer is a *showpiece*.
2. **Thin client, zero authority** (carry over Admin-UI P-UI-1). The SPA holds no
   signing power and no business rules; every decision (RBAC, dual-control,
   invariants, blast-radius) is **server-enforced**. A fully compromised UI tier
   cannot sign a cert or bypass two-person approval. UI stays out of the §2.1 TCB.
3. **API-first / CLI-parity.** Everything the console does is the *same* versioned
   admin API the CLI uses — no privileged UI backdoor; everything is scriptable.
4. **Preview before commit, everywhere.** Compile, invariant checks, reachability
   tests, blast-radius, and diffs precede every mutation (P-UI-5).
5. **Provenance by default.** Every fact shows *why* (which group-map rule granted a
   group, which policy version, which attestation evidence, which approver).
6. **Accessible + keyboard-first.** Power-user ⌘K command palette; the visual canvas
   has a full keyboard path and an accessible matrix equivalent (not mouse-only).

---

## 2. Competitive scan — what equivalent products do, and what we're missing

Surveyed: **Tailscale** admin console, **Defined Networking (defined.net)** — the
commercial managed-Nebula and our closest analog, **Headscale** + community UIs,
**ZeroTier Central**, **Twingate**, **NetBird**, **Netmaker**, **Teleport**,
**Cloudflare Zero Trust**.

| Capability | Who does it well | Have we got it? | Action |
|---|---|---|---|
| Machines list + device detail | Tailscale, defined.net | ✅ (Admin UI 4.2) | keep |
| **ACL/policy editor with inline _tests_** (assert "X can/can't reach Y", run on publish) | **Tailscale** (killer feature) | ❌ | **ADD — policy tests as first-class (see §4)** |
| **Roles = group-based firewall** ("roles" UX) | defined.net | ✅ our groups+policy | align naming/UX with "roles/groups" |
| Visual reachability matrix / graph | *nobody does this well* | ❌ | **ADD — our differentiator (§4)** |
| **Live network/topology map** | NetBird, ZeroTier | ❌ | **ADD — dashboard map (§3, §5)** |
| Device approval queue + pre-auth/enroll keys | Tailscale, ZeroTier, defined.net | ✅ (4.3) | keep; match defined.net "enrollment code" UX |
| **Tag ownership / who-can-assign-a-tag** | Tailscale (`tagOwners`) | partial (group map is fact-based) | **ADD delegation model for manual groups** |
| **Device posture checks** (OS, disk-enc, patch, agent ver → gate access) | Twingate, Cloudflare | partial (we have heartbeat facts) | **ADD posture facts + posture-gated groups (backlog)** |
| Key/CA expiry + rotation UX | Tailscale (key expiry), defined.net | planned (4.8) | keep (gated on M8) |
| **Tailnet lock / node-key signing** (no single server can add a node) | Tailscale | analogous to our genesis dual-control + attestation | document parity; surface "trust integrity" |
| Audit / activity log | all | ✅ (4.11) + our **chain-verify** is stronger | keep; lean into tamper-evidence as a feature |
| API tokens / service accounts | Tailscale | ❌ | **ADD — automation tokens screen** |
| Webhooks / SIEM / integrations | Tailscale, Cloudflare | settings-only (6.8) | **ADD integrations UI surface** |
| **Overlay DNS / MagicDNS** | Tailscale, NetBird | deferred (lighthouse.dns) | **ADD placeholder screen + backlog** |
| Just-in-time access requests / approvals | Teleport | our dual-control is adjacent | reuse dual-control for "request elevated group, time-boxed" |
| Guided **first-run onboarding** (set up network, first node) | defined.net, NetBird | ❌ (we have a CLI runbook) | **ADD genesis/onboarding wizard** |
| Connectivity / peer health test ("can A reach B right now") | NetBird | ❌ (we have simulator over *policy*) | **ADD live connectivity probe (host-assisted)** |
| Flow logs / access analytics | Cloudflare, Twingate | ❌ by design (P3: control plane off data path) | **acknowledge gap** — only host-reported summaries possible; treat as opt-in posture telemetry, not central flow capture |

**Net new features to fold in (beyond the Admin UI Plan):** policy *tests*,
reachability **matrix + graph** designer, **live topology map**, manual-group
**delegation**, **device posture** (backlog), **API tokens**, **integrations** UI,
**overlay DNS** (backlog), **onboarding wizard**, **live connectivity probe**.

---

## 3. Product surface (delta over the Admin UI Plan)

Keep the Admin UI Plan's 14-area IA. Additions/changes:

- **Dashboard** gains a **live topology map** (mesh graph: nodes by group/zone,
  lighthouses highlighted, edges = currently-permitted reachability, optional
  host-reported active tunnels) and a **"trust integrity" tile** (audit chain
  verified ✓, genesis intact, CA posture).
- **Policy** is replaced/expanded by the **Policy & Group-Tag Designer** (§4) — the
  headline. Subsumes the old "editor + compile preview + simulator + drift" into one
  cohesive workspace with **matrix / graph / DSL** views + **tests**.
- **Groups** merges into the designer's "Tags" rail (group taxonomy, zones, colors,
  membership provenance, delegation) — groups and the rules that use them are
  edited in one place, which is how operators actually think.
- New top-level: **Automation** (API tokens, webhooks, integrations) and
  **Onboarding** (first-run wizard; later hidden once set up).
- New within Devices: **live connectivity probe** and **posture** tab (backlog).

Everything else (Enrollment, Network/IPAM, Lighthouses, Keys & CA, Revocation,
Detections, Audit, Access, System, Settings) per the Admin UI Plan, with the design
language (§5) and the dual-control/preview patterns (§8) applied uniformly.

---

## 4. The Policy & Group-Tag Designer (the centerpiece)

This is the screen the request is really about: *"design group tag layout for
firewall design."* It must make a group-based, default-deny, allow-list firewall
**legible and safe to author** for a fleet of hundreds of hosts. It is one workspace
with **three synchronized views of one model**, plus a live analysis rail.

### 4.1 The model it edits (already in `internal/policy`)
- **Groups (tags)** — the unit of policy. Membership comes from the immutable-fact
  **group map** (5.5) or manual assignment; the designer edits *rules between
  groups*, not host-by-host.
- **Allow rules** — `allow <from-group> -> <to-group> <proto> <port>` (default-deny;
  no rule = no reach).
- **Reserved/baseline** — `control-plane` + `lighthouse` reachability and ICMP are a
  mandatory baseline that **cannot** be removed or shaped (invariant); the designer
  renders these as **locked** elements.
- Output: compiled per-host firewall, signed into the bundle, dual-control-published,
  canary-rolled-out, drift-reverted.

### 4.2 Three views, one source of truth

**(A) Tag Canvas — "the group tag layout"** *(primary, the headline)*
A directed graph on an infinite canvas (think the cleanest possible version of a
network diagram), built for *designing the tag topology*:
- **Group nodes**: name, color, member count, a **provenance badge** (fact-derived
  vs manual), and a **reserved/lock badge** for `control-plane`/`lighthouse`.
- **Zones / swimlanes**: cosmetic containers (e.g. *DMZ*, *App*, *Data*, *Mgmt*) you
  drag groups into to express tiers; purely organizational, persisted as layout
  metadata (not part of the signed policy).
- **Edges = allow rules**: drag from group A to group B to create a rule; the edge
  carries **proto/port chips** (`tcp/443`, `tcp/5432`, `any`). Multiple ports = stacked
  chips on one edge. Direction is explicit (arrowhead).
- **Default-deny is visible**: no edge = denied; hovering a non-edge offers "+ allow".
- **Baseline edges**: control-plane/ICMP shown as dashed **locked** edges so people
  *see* what's guaranteed and can't delete it.
- Auto-layout (tier/hierarchical from edge direction), minimap, multi-select, align,
  search-to-focus a group, "highlight everything that can reach X / that X reaches."
- **Keyboard-first + accessible**: every canvas action is doable from the keyboard,
  and the Matrix view (B) is the screen-reader-equivalent of the same model.

**(B) Reachability Matrix** *(dense editing)*
Groups as rows (from) × columns (to); each cell shows the allowed proto/ports (chips)
or empty (denied). Click a cell → port/proto editor. Best for: bulk authoring,
auditing "what can reach the `db` column," and large taxonomies where a graph gets
busy. Filter/scope by zone or group. This view is our differentiator — no competitor
offers a clean allow-matrix.

**(C) DSL / Text** *(source view, power users + diffs + git-ability)*
The raw `allow …` policy in a CodeMirror editor with our language mode, **server-side
lint** (parse + `Validate` + `CheckInvariants` on the fly), and inline error
squiggles. Round-trips losslessly with A and B (the layout/zone/color metadata lives
in a sidecar, never in the signed policy). This is the export/import + review-diff
format.

All three edit the *same* in-memory policy object; switching views never loses work.

### 4.3 The live analysis rail (right side, always visible)
Updates on every edit, computed **server-side** (the client never decides safety):
- **Invariant checklist** (impl 6.3): green/red — control-plane reachable, lighthouse
  discovery intact, no reserved-group references. **Publish blocked on red.**
- **Compiled preview** (impl 6.2): pick a host or group → see its exact inbound/outbound
  firewall section (the baseline auto-injected), so authors see what a host *actually* gets.
- **Policy tests** *(new, Tailscale-inspired)*: named assertions stored *with* the
  policy — `assert allow web -> db tcp 5432`, `assert deny laptops -> db`. Run on every
  edit and **gate publish**; they're regression tests for your firewall. Surfaced as a
  pass/fail list; failures point at the offending rule.
- **Blast radius / diff vs published**: "compared to the live policy, this draft **adds
  N flows / removes M flows**, affecting **K hosts** (list)." Removing a flow is
  flagged louder than adding (potential outage).
- **Reachability query**: "can `group A` reach `group B` on port N?" answered from the
  draft (the simulator, now interactive).

### 4.4 The publish pipeline (UX of the safe path)
`Draft → Validate (invariants + tests must pass) → Request publish (dual-control,
impl 6.5) → Reviewer sees the canvas diff + matrix diff + blast radius + tests →
Approve (distinct admin) → Canary rollout (impl 6.6) with the live wave monitor →
Auto-rollback armed`. The initiator can never self-approve (P-UI-4). Version history
with **one-click rollback** to any prior signed version, and a **drift panel**
(impl 6.7) listing hosts whose local edits were reverted.

### 4.5 Group-tag management (the "tag layout" lifecycle)
Inline in the designer's **Tags rail**: create/rename/describe a group; set
zone/color; see **membership + provenance** (which group-map rule, or manual list);
**delegation** — who may assign a manual group (Tailscale `tagOwners` analog, RBAC);
reserved groups are read-only. Renames are guarded (they ripple into rules + the
group map) with a blast-radius preview.

### 4.6 Implementation notes for the designer
- Canvas: **xyflow / React Flow** (mature, themeable, keyboard support, custom nodes/
  edges) — group nodes and labeled multi-port edges are custom components.
- Matrix: virtualized grid (TanStack Table/Virtual) to stay smooth at dozens×dozens.
- DSL: **CodeMirror 6** + a small custom language mode; lint via a debounced call to a
  server `POST /policy/compile?dry_run` (single source of truth for validity).
- Local editor state: **Zustand** (canvas positions, selection, undo/redo history);
  the *policy* (rules) is the serialized model, layout metadata is the sidecar.
- All "is this safe?" answers come from the server compile/invariant/test/diff
  endpoints; the client only renders them.

---

## 5. Visual design language ("modern and sharp")

A small, opinionated design system — defined once, applied everywhere.

- **Mode:** **dark-first**, with a light theme. The **environment label** (prod vs
  staging) tints the top bar to prevent cross-env mistakes.
- **Palette:** near-black layered surfaces (3–4 elevation steps), a single **accent**
  (electric indigo/cyan), and disciplined **semantic colors** — green=healthy,
  amber=warning/expiring, red=critical/denied/destructive, blue=info/pending. Color is
  never the *only* signal (a11y).
- **Type:** **Inter** (or Geist) for UI; **JetBrains Mono / Geist Mono** for IPs,
  fingerprints, ARNs, and the policy DSL — anything copy-pasteable is monospace.
- **Spacing/shape:** 4px base grid; subtle radii (6–8px) for a sharp-not-soft feel;
  hairline 1px borders for density; restrained shadows (elevation via surface color,
  not heavy drop-shadows).
- **Density:** compact default, comfortable toggle; data tables are the workhorse —
  sortable, column-configurable, virtualized, with **saved views**.
- **Motion:** 120–200ms, ease-out; used for state transitions, rollout/propagation
  progress, and canvas interactions — never gratuitous.
- **Showpieces:** the **topology map** (animated handshake/health pulses) and the
  **Tag Canvas** are where the product gets to look genuinely modern.
- **Iconography:** one set (Lucide), consistent weights.
- **Components:** **shadcn/ui** (Radix primitives) as the base kit — accessible,
  unstyled-then-themed, sharp; we own the tokens so it looks like *ours*, not stock.

A **Storybook** holds the design system (tokens, components, the canvas/matrix/charts)
as the living style guide and visual-regression surface.

---

## 6. Front-end architecture

**Stack (recommended):** a focused **React SPA** built with **Vite + TypeScript**,
**Tailwind CSS + shadcn/ui (Radix)**, **TanStack Query** (server state) +
**TanStack Table/Virtual**, **xyflow** (policy canvas + topology map),
**CodeMirror 6** (DSL), **Tremor or visx** (dashboard charts), **Zustand** (local
editor state), **Playwright + Vitest** (test).

*Why a real SPA and not the server-rendered (HTMX/Templ) lean of the Admin UI Plan:*
the headline features — the **drag-to-author policy canvas**, the **live analysis
rail**, the **topology map**, and **real-time rollout/propagation** — are genuinely
rich-client interactions that HTMX would fight. We keep the security posture by making
the SPA a **strict dumb client** (no authority, all decisions server-side, strict CSP,
no secrets in JS) — i.e. we get richness *and* keep the UI out of the TCB. (This is an
explicit reversal of the Admin UI Plan's HTMX lean — **decided** in §13-#1; the
strict-dumb-client rules are the condition that makes it acceptable.)

- **State:** TanStack Query for all server data (cache, refetch, optimistic only for
  *non-privileged* actions); Zustand only for ephemeral editor/canvas state; URL holds
  filters/selection (shareable, back-button-correct).
- **Routing:** typed routes; deep links to any object (device, policy version, audit
  row) for incident sharing.
- **Real-time:** **SSE** channels over the mesh for fleet heartbeats, rollout/
  propagation progress, the approval queue, and the detections feed; reconnect with
  backoff; fall back to polling.
- **Data scale:** never ship 10k rows to the client — dashboard aggregates and table
  pages are computed **server-side** (cursor pagination, server filter/sort);
  virtualize what we do render.
- **Code-split** by area; the canvas/charts libs lazy-load so the shell stays light.

---

## 7. API & data contract

- **One versioned admin API** (`/admin/v1/...`), the same the CLI uses (P-UI-1).
  Resource-oriented: `devices`, `enrollments`, `joinkeys`, `groups`, `policies`
  (+ `/compile`, `/tests`, `/diff`), `rollouts`, `lighthouses`, `ipam`, `keys`,
  `approvals`, `audit`, `detections`, `settings`, `tokens`.
- **Describe it in OpenAPI**, generate the typed TS client → the front end never
  hand-writes request types; drift between server and client is a compile error.
- **Conventions:** cursor pagination, rich filtering, field selection, `ETag`/
  `If-Match` for optimistic-concurrency on policy/settings edits, `Idempotency-Key`
  on mutations, problem+json errors that the UI renders inline.
- **Dual-control as data:** an approval is a first-class resource (`/approvals`) the UI
  lists, diffs, and acts on — the same `internal/dualcontrol` records the CLI uses.
- **Server owns truth:** `/policy/compile` (invariants), `/policy/tests`,
  `/policy/diff`, blast-radius, IPAM projections, reachability queries are **server
  endpoints**; the client renders results, never recomputes safety.

---

## 8. Security implementation (the UI's own posture, made concrete)

- **Auth:** OIDC **Authorization Code + PKCE** to the IdP; session in an **httpOnly,
  Secure, SameSite** cookie (no tokens in JS); short TTL; silent refresh; **step-up
  auth** (re-prompt/MFA) for privileged actions (publish, rotate, bulk revoke). *Blocks
  on impl 2.11 (SSO/MFA/RBAC).*
- **RBAC:** server enforces on every endpoint; the client **also** hides what the role
  can't do (defense in depth, not the control). Read-only is the default role.
- **Dual-control UX** (P-UI-4): privileged actions create a request → a *distinct*
  admin approves; initiator-self-approve is impossible (server-enforced); the UI shows
  who must sign, the diff, and the pending state; one **Approvals** inbox aggregates
  all pending two-person actions.
- **Hardening:** strict **CSP** (nonce-based, no inline/eval), SRI on assets, CSRF
  tokens on mutations, no secrets client-side, framing denied, dependency pinning +
  SCA in CI. The SPA is served as static assets by Core over the mesh (mesh-only +
  IdP), with the **break-glass** path (impl 9.2) defined as CLI-only when the mesh is
  down.
- **Secrets shown once:** join-key secrets, API tokens — displayed exactly once on
  creation, copy-to-clipboard, never re-retrievable.
- **Audit affordance:** every mutation screen states "this will be logged as …" and
  links the resulting audit row; the audit view shows **chain-verified ✓** against the
  WORM copy (impl 2.13) with a loud banner if it breaks.

---

## 9. Non-functional

- **Accessibility:** WCAG 2.2 AA; full keyboard paths (incl. the canvas); visible
  focus; ARIA for live regions (rollout/approvals); the **Matrix view is the
  accessible equivalent of the Tag Canvas**; axe checks in CI.
- **Performance budgets:** initial shell < ~200KB gz (canvas/charts lazy); table
  interactions < 50ms; dashboard first data < 1s on a warm API; virtualize all large
  lists.
- **Testing:** Vitest + Testing Library (components), **Playwright E2E** against a
  seeded Harbor (critical flows: enroll→approve, **policy author→test→dual-control
  publish→canary**, lighthouse swap, bulk revoke guardrails), visual regression on the
  design system + canvas, axe a11y, contract tests against the OpenAPI.
- **i18n-ready:** all strings externalized (English first); locale-aware dates/numbers.
- **Theming:** dark/light + the env tint; tokens drive everything.
- **Observability:** client error reporting (scrubbed, mesh-internal), UX telemetry for
  the high-stakes flows (where do publishes get abandoned?), feature flags.

---

## 10. Build & delivery

- **Location:** `ui/` in the repo (pnpm + Vite). Built static assets are **embedded
  into the Core binary via `go:embed`** and served by a tiny static handler over the
  mesh → the console ships as part of the single Harbor artifact (no separate deploy,
  consistent versioning, smallest moving-parts footprint). **Decided** (§13-#7); a
  sidecar static server was the considered alternative.
- **CI:** lint/typecheck/test/build the UI; inject the CSP nonce mechanism; SCA;
  Playwright against an ephemeral seeded Harbor; Storybook + visual-regression; bundle-
  size gate.
- **Versioning:** UI version pinned to the Harbor build it ships in; the API is the
  compatibility contract (N/N-1).

---

## 11. Phasing (engineering-oriented; maps onto the Admin UI Plan UI-0…UI-6)

- **UI-0 — Foundation** *(needs 2.11 auth + impl 2.8 admin API):* design system +
  Storybook, app shell (nav, ⌘K, env tint, notifications), OIDC/MFA/RBAC auth,
  TanStack Query + generated API client, SSE plumbing, the **dual-control + preview +
  destructive-action** primitives (built once, reused). Ship **read-only Dashboard +
  Devices + Audit** to prove the thin-client model.
- **UI-1 — Enrollment** *(impl M3):* approval queue, join keys (auto-issue warned),
  conflict inbox, enrollment funnel, quotas.
- **UI-2 — Fleet health** *(impl M4):* expiry/health dashboards, version landscape,
  heartbeat detail, **topology map v1**, live connectivity probe.
- **UI-3 — Identity facts** *(impl M5):* immutable-fact **group map** editor +
  cloud-trust settings (approved accounts/subscriptions, auto-assign), attestation
  evidence on device detail.
- **UI-4 — Policy & Group-Tag Designer** *(impl M6) — the headline:* the
  canvas + matrix + DSL workspace, the live analysis rail (invariants/compile/**tests**/
  blast-radius), dual-control publish, **canary rollout monitor**, drift panel, +
  Network/IPAM screens.
- **UI-5 — Trust ops** *(impl M7–M8):* revocation/blocklist with propagation SLO,
  **CA/key rotation wizards**, lighthouse fleet management.
- **UI-6 — Enterprise** *(impl M9):* detections + reconciliation, full Settings,
  Access/RBAC admin, System/ops (deploys, backups, self-update), Automation (API
  tokens/webhooks/integrations), break-glass log, onboarding wizard, overlay-DNS
  placeholder.

Each phase is **front-to-back**: no screen ships before its API has real data.

---

## 12. Risks

- **Auth dependency:** the whole console blocks on 2.11 (SSO/MFA/RBAC). Mitigate:
  build UI-0's *non-auth* pieces (design system, components, canvas in Storybook)
  in parallel; gate the running app on 2.11.
- **SPA vs thin-client tension:** richer client = bigger attack surface. Mitigate with
  the strict-dumb-client rules (§8) and keeping *all* authority server-side.
- **Canvas at scale:** hundreds of groups would clutter the graph. Mitigate: zones,
  focus/filter, and the matrix as the dense fallback; lazy-render off-screen nodes.
- **Real-time over the mesh:** SSE across Nebula must tolerate reconnects; always have
  a polling fallback.
- **Two front-end stacks:** if we ever also want server-rendered break-glass, that's a
  second toolchain — keep break-glass CLI-only to avoid it.

---

## 13. Decisions (resolved 2026-06-13)

All twelve open questions were reviewed and decided (every choice took the
recommended option):

| # | Decision | Chosen | Rationale (1-line) |
|---|---|---|---|
| 1 | Rendering model | **Rich SPA** (React + Vite + TS) | The policy canvas + live dashboards need a rich client; keep it a strict dumb client to preserve the TCB boundary. |
| 2 | Component kit | **shadcn/ui + Tailwind** (Radix) | Own the components (sharp, ours) + Radix a11y + Tailwind velocity; heavy widgets from TanStack/xyflow/CodeMirror. |
| 3 | Designer default view | **Tag Canvas** (graph) | Directly serves "design group tag layout"; best for comprehension/onboarding/demos. Matrix one click away; app remembers last view. |
| 4 | Policy tests | **Gate publish + dual-control override** | Regression-tests the firewall; cheap on the existing compile engine; override keeps it from ever being a hard lock. |
| 5 | Topology map | **Policy-permitted now → opt-in live overlay later** | Free + P3-clean now; design for a host-reported live-tunnel overlay once peer telemetry is justified. |
| 6 | Vocabulary | **"groups"** (+ "tag layout" framing) | Matches Nebula's cert field + our code; avoids the admin-RBAC "roles" collision; canvas nicknamed the tag/group layout. |
| 7 | Serving | **Embed in Core (`go:embed`)** | Single artifact, guaranteed UI↔API version match, mesh-served, minimal footprint; Signer stays isolated. |
| 8 | Auditor access | **Read-only RBAC role + signed exports** | Reuse the read-only role; serve external compliance via signed chain-verified exports; keeps mesh-only intact. |
| 9 | Device posture | **Backlog** (show existing heartbeat facts) | Posture done right is cross-platform (M10) + ties into group-map; avoid a Linux-only half-feature during the core UI build. |
| 10 | Break-glass | **CLI-only + drilled runbook** | Out-of-band recovery should be dependency-light + auditable; no off-mesh web surface for a rare event. |
| 11 | Onboarding | **Genesis CLI/offline + console onboarding for the rest** | Genesis mints trust roots → must stay out of the UI (P-UI-1); build empty-states + a "get started" checklist for everyday flows. |
| 12 | Real-time transport | **SSE + polling fallback** | One-way status streams fit SSE exactly; lower surface than WebSocket; reserve WebSocket for future collaborative canvas editing. |

### Consequent commitments baked into the plan
- The SPA is a **strict dumb client** (§8): zero authority, all decisions server-side, strict CSP, no secrets in JS — this is the condition that made the SPA choice acceptable.
- **Policy tests** become a first-class part of the designer's analysis rail and the publish pipeline (§4.3/§4.4).
- The topology map (§3/§5) is **architected for a later live-tunnel overlay** without rework.
- Genesis remains a **CLI/offline ceremony**; the console gets **empty-states + a guided checklist** (§11/UI-1).

### Still open (smaller, can decide during build)
- Collaborative multi-operator canvas editing → would flip Decision 12 toward WebSocket; revisit only if we want live co-editing.
- Exact charting lib (Tremor vs visx) — defer to UI-0 prototyping.
- Whether the "get started" checklist is dismissible/persistent per-org.

## Sources / references
- [[Nebula Control Plane - Admin UI Plan]] — IA, screen catalog, settings, UI security posture.
- [[Nebula Control Plane - Design Plan]] / [[Nebula Control Plane - Implementation Plan]] — backend surface the UI consumes.
- Competitive: Tailscale (ACL editor + tests, tagOwners, key expiry), defined.net (managed Nebula "roles", enrollment codes), ZeroTier Central (flow rules), Twingate/Cloudflare (posture), NetBird (topology map, connectivity), Teleport (access requests), Headscale (OSS control server).
