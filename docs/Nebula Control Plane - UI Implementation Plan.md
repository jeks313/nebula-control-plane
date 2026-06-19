---
created: 2026-06-13
updated: 2026-06-18
source: claude-chat
status: draft
project: nebula-control-plane
tags: [networking, nebula, security, ui, frontend, design, firewall]
---

# Nebula Control Plane — UI Implementation Plan

> **Status (2026-06-18):** SHIPPED & LIVE on the poc. The React console
> (`ui/`, embedded in Core via `go:embed` behind `-tags ui`, served on :443) is
> deployed and running, with real session auth (OIDC/SAML/GitHub + dev mock-idp
> for login), RBAC, and step-up MFA. Live screens: Dashboard (health rollup +
> recent-reaps panel), Enrollments, Devices, Join Keys, Cloud Trust, **User Trust
> (SSO)**, **IPAM**, Policy (compile + the A1 analysis rail: flow-diff/blast-radius,
> reachability query, test runner, matrix grid), **Releases**, Approvals, Audit.
> Still genuinely deferred: the reachability **matrix as the default authoring
> view** + the **Tag Canvas** (no xyflow/WebGL dep yet), the **topology map**,
> the live **SSE** stream (A2 — polling stands in), and the trust-ops wizards
> (CA/key rotation, revocation/blocklist UI). The phase/status callouts below are
> kept for history; the 2026-06-13 ✅ markers and §11 phasing under-report what has
> since landed (IPAM, SSO/User-Trust, the device reaper, Releases) — see the
> inline (superseded 2026-06-18: …) annotations.

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
  - ✅ **A1.1 reachability / matrix / tests (2026-06-13).** New `internal/policy/
    analysis.go` — pure, server-computed answers defined as a faithful mirror of what
    `CompileHost` enforces (a single `allow A->B` rule is compiled into both endpoints,
    so one matching rule grants reachability; the non-removable baseline — control-plane
    + ICMP — is layered on). **`Reachable`** (allowed + why: granting rule, or
    default-deny with the nearest miss), **`Matrix`** (all-pairs group×group permitted
    flows; baseline flagged), and a **test DSL** (`assert allow|deny <from> -> <to>
    <proto> <port>`) → pass/fail. New read-only endpoints
    `POST /admin/v1/policy/{reachability,matrix,tests}` (dry-runs, no perm/step-up like
    compile). UI **analysis rail** on the Policy page: a reachability query bar with the
    "why", an inline test runner, and a reachability-matrix grid. Adversarially reviewed
    (7-agent, cross-checked against `CompileHost`): **5 confirmed, all fixed** — incl. a
    **critical false-allow** (a wildcard query dimension dropped the other concrete
    dimension → "reachable" when enforcement blocks; now each dimension is evaluated
    independently, with regression tests), a control-plane-sender baseline false-allow,
    a matrix O(n²) DoS (group cap), and query input validation.
  - ✅ **A1.2a flow-diff + blast-radius (2026-06-13).** Added to `internal/policy/
    analysis.go` (pure, reusing the A1.1 primitives): **`FlowDiff(active, draft)`** — the
    user-rule flows **added/removed** vs the active policy, diffed per *literal* group pair
    (so an `any` rule shows as itself, not fanned out), deduped per (proto,port) with
    `N-N`→`N` port canonicalization, directional, baseline excluded; and
    **`BlastRadius(diff, groupHosts, allHosts)`** — the real hosts a change touches (a
    changed `A->B` flow affects group A ∪ group B, since `CompileHost` writes both
    endpoints; an `any` side ⇒ the whole fleet). The host-membership source (the A1.2
    blocker) is now `fleetGroupMap` — fleet-wide group→hosts from each host's **latest
    issued enrollment** groups (the just-landed provenance data; reserved groups excluded
    as keys, those hosts still in the `any` denominator). New read-only endpoint
    `POST /admin/v1/policy/diff` (flow-diff + blast in one call; draft-rule cap; an
    unpublishable draft is previewed with a non-fatal `warning`). UI: a **"Changes vs
    active"** panel on the Policy page (added/removed flows + "up to N of M hosts
    affected"). Adversarially reviewed (5-agent + verify): **11 confirmed of 31, all
    LOW/MEDIUM** — fixed the draft-rule **DoS cap**, the reserved-group **warning**,
    honest **superset** wording for blast radius, port-range churn, and added
    fleet-group-map / truncation / conformance tests.
  - **Deferred to A1.2b (the dual-control integration):** assertion **storage +
    publish-gate** (bundle policy+tests in the `policy.publish` payload as a versioned
    JSON envelope — one `PayloadHash` binds them, the no-TOCTOU §4.4 snapshot for free;
    gate at propose **and** in the commit committer) + surfacing the test-results/diff
    snapshot to the approver, and richer per-rule invariant diagnostics.
- **A2 — Change/event emitter.** A fan-out (heartbeat upserts, rollout transitions,
  approval state) behind one multiplexed SSE endpoint. Until it exists, the rollout
  monitor polls.

Backed by **real data today** (after A0 exposes it): fleet/heartbeats
(`internal/fleet`, `coreapi`), enrollment + join keys + approval (`enrollment`,
`joinkey`), policy compile + invariants + dual-control (`policy`, `dualcontrol`),
lighthouse fleet (`lighthouse`), canary rollout (`rollout`), IPAM (`ipam`), audit
chain (`store.VerifyAudit`), AWS attestation evidence (`awsattest`), drift (`drift`).

**Gated on unbuilt backend** (screen ships when its data does): **A0/A1/A2** above;
~~**SSO/MFA + RBAC roles** (2.11 — the auth shell blocks on this; the dev-auth seam in
§8 unblocks dogfooding)~~ *(superseded 2026-06-18: 2.11 SSO + RBAC + step-up MFA
SHIPPED & LIVE — OIDC/SAML/GitHub + dev mock-idp; the auth shell ships in UI-0b)*;
immutable-fact **group map** (5.5); **revocation** (M7);
**CA/key rotation** (M8); **detections + reconciliation + WORM audit** (M9); device
**posture**; overlay **DNS**; subnet-router **routes** (DSL gap, §4).

> *(superseded 2026-06-18)* Since this section was written, the backend track is
> largely DONE and several "gated" screens have shipped & gone live on the poc:
> **A0** (admin API, OpenAPI + contract test, admin tokens), **A1.1/A1.2a** (the
> reachability/matrix/tests + flow-diff/blast-radius analysis rail), **2.11** (SSO
> + RBAC + step-up MFA). Net-new since: **IPAM** (ADR 0010 — named netblocks, full
> console editor, API, Prometheus gauges, dashboard tile — SHIPPED & LIVE),
> **SSO user enrollment + User-Trust admin UI** (ADR 0004/0009 — CODE-COMPLETE,
> off by default / not rolled out), the **device reaper** + **ephemeral hosts**
> (SHIPPED & LIVE; dashboard recent-reaps panel), and the **Releases** console
> (#39 — binary registries + per-lane fleet upgrades). A2 (SSE) is still unbuilt
> (polling stands in).

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
| Policy editor w/ inline **tests** that gate publish | Tailscale | ✅ test runner (A1.1); publish-gate = A1.2b | **Now** |
| **Reachability matrix** authoring (from×to grid) | *nobody ships cleanly* | ✅ matrix grid (A1.1, read-only rail); authoring = UI-4b | **Now — differentiator + hero (§4/§5)** |
| Reachability/"why-reachable" query + **nearest-miss** | AWS VPC Reachability Analyzer | ✅ (A1.1) | **Now** |
| `internet` / egress pseudo-target ("who may reach the internet") | Tailscale autogroup:internet | ❌ (DSL) | **Now — cheapest high-value rule** |
| Device approval queue + enroll keys | Tailscale, defined.net | ✅ | Now |
| Live **topology map** (comprehension) | NetBird, ZeroTier, Tetration | ❌ | **Now (policy-permitted) / Later (live)** |
| Tag/group **delegation** (who may assign a tag) | Tailscale `tagOwners` | partial | Later |
| **Subnet routers / `unsafe_routes`** (reach a non-mesh CIDR via a node) | Tailscale, NetBird, Netmaker | ❌ (DSL needs a CIDR destination) | **Later — most-used feature after admit (§4)** |
| Flow-**diff** / blast-radius on change | (weakly: Tailscale text diff) | ✅ (A1.2a; visual matrix-overlay diff = UI-4b) | **Now — the highest-stakes screen** |
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

> ✅ **Delivered (2026-06-13) — device provenance + scope filters.** Shipped as a
> backend predecessor + the riding UI. `GET /admin/v1/devices` now joins each
> heartbeat to its **authoritative enrollment** (the latest *issued* row for that
> `overlay_ip`, mirroring `coreapi.device()`) via a batched lookup (no SQL JOIN — the
> codebase has none), surfacing `attest_provider/account/principal/region` for attested
> hosts, `join_key_name` for token hosts (resolved through `join_keys`, including
> revoked keys), and the issued `groups`. New scope filters `?provider=` /
> `?attest_account=` / `?join_key=` resolve an authoritative-enrollment allow-set, and
> the handler **keyset-fills** the page against it in Go (bounded bind-params, correct
> `next_after` at any fleet size). Migration 000012 adds `enrollments(overlay_ip,
> status)` for the per-page lookup. UI: a **"Joined via"** column + groups, with each
> provenance value clickable to filter, and removable active-filter chips. (Original
> request below.)
>
> The **Devices list** should show, per host, **how it joined the mesh** — its
> *enrollment provenance*:
> - **Cloud-attested hosts:** the attesting **site** = provider + account (e.g. `AWS ·
>   111122223333`, `Azure · <subscription>`), optionally with region. (Provider-agnostic,
>   per the M5.3 evidence shape: `attest_provider` / `attest_account` /
>   `attest_principal` / `attest_region`.)
> - **Token-enrolled hosts:** the **join-key name** they enrolled with (the join key's
>   name *is* its description — there is no separate description field today).
>
> And the list must be **filterable down to those scopes** — narrow Devices to a single
> attestation provider/account, or to a single join key (e.g. "show every host that came
> in via `laptops-2026`", or "every host attested from AWS account 1111…").
>
> **Backend dependency (the real work):** the Devices list is *heartbeat-sourced* and
> carries **no provenance today** — no groups, no join-key link, no attestation fields.
> The provenance lives on the **enrollment record** (M5.3: the evidence columns +
> `join_key_id` + `groups`). So this needs either (a) a **device→enrollment join** keyed
> on `overlay_ip` (issued enrollments carry the allocated IP) — or `pubkey_hash` — that
> surfaces provenance on the `Device` view, plus join-key **name** via `join_keys`
> (the row only has `join_key_id`); or (b) an **extended `GET /admin/v1/devices`** that
> returns the provenance fields and accepts filter params (e.g. `?provider=`,
> `?attest_account=`, `?join_key=`). Caveat: a device can outlive/re-enroll, so define
> which enrollment is authoritative (latest issued for that overlay IP). Until this lands
> the column/filter have no data — A0/A1-style backend predecessor first, then the UI.

> ✅ **Delivered (2026-06-13) — editable join keys.** New `PATCH /admin/v1/joinkeys/{name}`
> (`joinkey:manage`, audited `joinkey-update`, **active-only**, **config-columns-only**).
> `joinkey.Update` writes a `map[string]any` of only the set fields (pointer request struct
> → `auto_issue=false`/`max_uses=0` persist, omitted = unchanged) via a column-scoped
> `Updates` that **never touches `used_count`/`secret`/`name`/`state`** (the concurrent
> enroll counter is safe); a revoked/unknown key 404s. No step-up (matches create/revoke —
> not an authority-granting dual-control action). UI: an **Edit** dialog per active key,
> pre-filled, reusing a shared `JoinKeyFields` form (name read-only; TTL blank = keep,
> 0 = never); the auto-issue ⚠ warning mirrors the create form. Tests: `joinkey.Update`
> (false/0 persist, `used_count` preserved, revoked → ErrNotFound) + HTTP PATCH 200 /
> 404 / revoked-404 / viewer-403. (Original request below.)
>
> The **Join Keys screen** needs an **Edit** action (today it is create + revoke only).
> An "Edit" on each *active* key opens a dialog **pre-filled** with the current values and
> lets an admin change: **groups** (add/remove), **max uses**, **TTL / expiry**,
> **rate/hour quota**, **auto-issue**, **ephemeral**, **sub-range**.
> - **Immutable (never editable):** the **secret** (it is hashed + shown once — editing
>   it is "regenerate", a separate revoke-and-reissue) and the **name** (the key's
>   identity / unique handle — renaming = a new key).
> - **Semantics to get right:** toggling **auto-issue** is *authority-affecting* (it
>   skips per-device approval) — keep the create-form warning on the edit form and audit
>   the change loudly. Lowering **max_uses below the current used_count** simply exhausts
>   the key — a useful *soft stop* short of full revoke; allow it. The edit must update
>   only the config columns and **never clobber `used_count`** (the enroll path mutates
>   it concurrently), so the write is a targeted column update, not a row replace; and
>   it applies to **active keys only** (a revoked key is terminal).
>
> **Backend dependency:** there is **no update endpoint** today — only
> `POST /admin/v1/joinkeys` (create, secret-once) and `POST /admin/v1/joinkeys/{name}/revoke`.
> This needs a new `PUT`/`PATCH /admin/v1/joinkeys/{name}` (perm `joinkey:manage`,
> audited, active-only, config-columns-only) before the UI Edit dialog can ship.

> ✅ **Delivered (2026-06-13) — editable Cloud Trust (UI-only).** The Cloud Trust screen
> gains an **Add accounts / Propose change** editor (gated on `cloudtrust:propose`): a
> dynamic form (AWS account rows — account / ARN globs / groups / auto-issue — + default
> groups) seeded from the active config, that **republishes the whole config** via the
> existing `POST /admin/v1/cloudtrust/propose` (dual-control + step-up, reviewed in
> Approvals). No backend change. Client pre-validates ≥1 account + unique ids (mirrors the
> server's `ErrEmpty`/`ErrDupAccount`); a prominent high-stakes warning ("controls who may
> attest"; whole-config republish — keep every account) + a per-row auto-issue+any-role
> warning. Approvals now **pretty-prints** JSON payloads so the cloud-trust change reads
> well (policy DSL falls through to raw). The full-config round-trip + central step-up
> handling mirror the policy-propose twin. (Original request below.)
>
> The **Cloud Trust screen** is read-only today — no way to **add** a trusted account or
> **edit** an existing one (e.g. change the groups granted). It needs add + edit.
> - **Model — whole-config republish (not per-entry PATCH):** the active config is one
>   document (`default_groups` + `aws[]`); "add/edit" = propose a *new version* of the
>   whole config (the latest committed becomes active — same shape as policy publish).
>   The form pre-fills from the active config, the admin changes it, and **Propose** opens
>   a dual-control change reviewed in **Approvals**.
> - **Backend already exists (this is UI-only):** unlike the two notes above,
>   `POST /admin/v1/cloudtrust/propose` is built (M5.3) — dual-control (`cloudtrust:propose`,
>   admin-only) + **step-up MFA**, committed via the generic `/approvals` flow with the
>   committer re-validating. So the UI just needs the propose/edit form (gate the controls
>   on `can('cloudtrust:propose')`); no new endpoint.
> - **Open decision (up in the air):** whether the form lets you edit the **scope** (which
>   accounts / ARN patterns may attest) and **admission** (`auto_issue`), or restricts the
>   easy path to **groups-only** and treats scope/admission as more deliberate. Note: by
>   construction *any* change to this config — groups, scope, or admission — already goes
>   through **two-person approval + step-up** (it is a `cloudtrust.publish` change), so the
>   safety is enforced regardless; the question is purely how much the form exposes vs.
>   how loudly it warns. Changing scope/admission widens who can join the mesh — treat it
>   as the highest-stakes edit (extra confirmation + a prominent diff in the approval).
> - **Resolved:** the form exposes **full editing** (scope + admission) — "add account"
>   inherently needs scope, and dual-control + step-up enforce safety regardless — with a
>   high-stakes warning and a per-row auto-issue+any-role warning rather than hiding fields.

> ✅ **Delivered (2026-06-13) — join-key name on Enrollments + shared "Joined via" cell.**
> `EnrollmentView` now carries `join_key_name`, resolved server-side from `join_key_id` via the shared
> id→name map (revoked keys still resolve; falls back to `token` if the key is gone).
> The Enrollments "Method" column is now a **"Joined via"** column rendered by a **shared
> `JoinedVia` component** (`ui/src/components/provenance.tsx`) used by both Devices
> (click-to-filter) and Enrollments (static, `fallback=method`) — so the provider/key
> chip is identical on both screens. `seed-demo` was fixed so **pending** token
> enrollments carry a `join_key_id` (they previously rendered a bare `token`) and a
> **denied** example was added, so the Pending/Approved/Denied tabs are now consistent and
> all populated. (Original request below.)
>
> On the **Enrollments screen**, a token-method enrollment shows just `token` in the
> Method column — show the **name of the join key** it used instead (e.g. `token ·
> laptops-2026`), mirroring how attested rows already show `AWS · <account>`.
> - **Backend dependency (small):** `EnrollmentView` carries `join_key_id` (a number) but
>   **not the name**, and the join-keys list doesn't expose its `id` either — so the
>   client can't map id→name today. Cheapest fix: add **`join_key_name`** to
>   `EnrollmentView` (server-side join `enrollments.join_key_id → join_keys.name`).
>   Revoked keys keep their row so the name still resolves; fall back to `token` (or
>   `token (#id)`) if the key is gone.
> - **Shares the device-provenance note above:** that `enrollment → join_key` linkage is
>   the same one the Devices-list join-key column needs — build it once and reuse it.

> ✅ **Delivered (2026-06-13) — dashboard "Why" drill-downs.** `fleet.Rollup` now
> server-populates the existing `Reason.link` for the five device-condition codes
> (`CERTS_EXPIRED`→`/devices?condition=expired`, `CERTS_EXPIRING`→`expiring`,
> `HOSTS_STALE`→`stale`, `CLOCK_SKEWED`→`clock_skewed`, `HOSTS_UNHEALTHY`→`unhealthy`);
> audit/rollout reasons get no `/devices` link. `GET /admin/v1/devices` accepts the
> matching `?condition=` filter, whose SQL predicate (`fleet.ConditionSQL`) is the twin
> of the `fleet.classify` Go logic that drives the verdict — a test asserts the
> `?condition=X` count equals the `/fleet/health` total, so the drill-down can't drift
> from the "why". The dashboard renders each linked reason as a `react-router` link; the
> Devices page reads `?condition=` from the URL. (Original request below.)
>
> Each **"Why" reason** on the Fleet dashboard should be a **link to the relevant detail,
> pre-filtered to that condition** — e.g. "2 certs expiring within 168h" → the **Devices**
> view showing exactly those expiring hosts. Reason-code → destination:
> - `CERTS_EXPIRING` / `CERTS_EXPIRED` / `HOSTS_STALE` / `CLOCK_SKEWED` / `HOSTS_UNHEALTHY`
>   → **Devices**, filtered to the matching hosts.
> - `AUDIT_CHAIN_BROKEN` / `AUDIT_CHECK_UNAVAILABLE` → **Audit** / trust-integrity tile.
> - `ROLLOUT_ROLLEDBACK` / `ROLLOUT_IN_PROGRESS` → the rollout / active-ops view (no
>   dedicated rollout page yet — links there when it exists).
> - **Backend dependency:** the `Reason` schema already has an optional **`link`** field —
>   recommend the **server populate it** with the deep-link (server-driven; the client
>   just renders an anchor, no client-side code→route map). Crucially, the **Devices
>   endpoint has no filter params today** (only `limit`/`after`); it needs a server-side
>   filter (e.g. `?condition=expiring|expired|stale|clock_skewed|unhealthy`) computed with
>   the **same fleet thresholds** the health rollup uses — the client does **not** know
>   those thresholds (`-expiry-within`/`-stale-after`/`-clock-skew-ms` are server config),
>   so client-side filtering would drift from the verdict. Server-computed keeps the
>   drill-down consistent with the "Why" (P-UI-1).
> - **Devices page** then honors the filter (a filter chip + a clear-filter affordance).
> - **Same Devices-filter surface as the provenance note above:** the provenance scope
>   filters (provider/account/join-key) and these health-condition filters are one general
>   **Devices filtering** mechanism — design the `/devices` filter params + the UI filter
>   bar to cover both.

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
  before 2.11. ~~Until OIDC lands, the only honestly-shippable app is mesh-only behind
  the dev seam.~~ *(superseded 2026-06-18: 2.11 landed — generic OIDC, SAML 2.0, and
  GitHub OAuth all ship, with step-up MFA. The poc runs the dev **mock-idp** for
  console login; a real IdP (Entra) for the console is a separate prod item.)*
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
  `go:embed`** (behind a `ui` build tag — `go build -tags ui`; a plain build ships a
  "not built" stub so CI needs no Node), served by a static handler — single artifact,
  lockstep UI↔API versioning, minimal footprint. Confirm **HTTP/2** on the embedded
  server (SSE multiplexing) and **hash-based CSP** at build time (§8). *(superseded
  2026-06-18: SHIPPED & LIVE — the poc builds harbor `-tags ui` and serves the full
  console on **:443** at `poc-harbor.<domain>` over the ACME edge TLS, not only over
  the mesh; HTTPS/CSP/HSTS hardening landed in UI-0.)*
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
  - ✅ **A0.3 (2026-06-13)** — first **mutating endpoints**, the dual-control
    publish showcase: `POST /policy/propose`, `POST /policy/compile` (read-only
    live analysis), `GET /policy/active`, `GET /approvals`, `GET /approvals/{id}`,
    `POST /approvals/{id}/approve`, `POST /approvals/{id}/deny`. Mutations **bind to
    the authenticated principal** (never a body field) and require the admin role
    (the RBAC seam); dual-control sentinels mapped to HTTP (409 self-approve /
    duplicate / not-pending, 422 commit-rejected, 404). OpenAPI + contract test
    extended; proven over HTTP (propose → self-approve 409 → distinct approver
    commits → active). Adversarially reviewed (14-agent): **hardened the
    `internal/dualcontrol` engine with a compare-and-set commit claim** so the
    committer runs exactly once even with concurrent distinct approvers
    (Postgres double-commit race; SQLite was masking it) — with a `-race`
    regression test; plus `ErrCommit`→422, empty-body tolerance, `rules`/contract
    `[]`-not-null, compile un-gated for viewers, and 400-doc fixes.
  - ✅ **A0.4 (2026-06-13)** — fleet-management mutations (pure-DB): **lighthouse**
    `POST/PUT {ip}/DELETE {ip}` (+ existing GET), **rollout** `GET current / POST
    start / POST current/step / POST current/abort`, **join keys** `GET / POST
    (secret once) / POST {name}/revoke`. All require the admin role, bind to the
    authenticated principal (audited), and reuse the existing engines. OpenAPI +
    contract test extended; proven over HTTP (lighthouse swap incl. last-active
    block; rollout start/step/abort/restart; join-key create/list/revoke/dup-409;
    viewer-403 on every mutation). Adversarially reviewed (10-agent): fixed a real
    **`active:true` lie** for finished rollouts (derive from state), removed the
    undocumented 501 path (engines now default in `New`), added step-audit
    attribution, fixed the unreachable `aborted` enum, and stopped a spurious
    audit row on idempotent lighthouse-remove.
  - ✅ **A0.5 (2026-06-13)** — enrollment **approval queue**: `GET /enrollments`
    (keyset-paginated, default `pending`), `POST {id}/approve`, `POST {id}/deny`.
    Approve is gated on **issuance mode** — `harbor admin-api -ca-cert …` builds the
    full enrollment consumer (`CanIssue`); started read-only, approve returns a
    deliberate **501** ("issuance not configured") instead of a broken signer.
    Deny works on a Store-only consumer. All mutations require the admin role,
    bind to the authenticated principal (audited), and the views never return the
    host pubkey/cert bytes (fingerprint only). OpenAPI + contract test extended;
    HTTP tests (list, deny 200/409, approve-501 read-only, viewer-403, unauth-401).
    Adversarially reviewed (14-agent; 8 confirmed → 3 distinct): **hardened
    `enrollment.Approve`/`Deny` with a status-gated compare-and-set** — a concurrent
    approve+deny on the same pending row could otherwise mint a cert for a host
    recorded **denied** (the A0.3 TOCTOU class); the losing approve now releases its
    IP and never delivers the cert, with a `-race` regression test; added **keyset
    pagination** to the enrollment list (was unbounded — the one join-key-holder-
    influenced surface); and, per Chris's call, **dropped `500` from the OpenAPI
    contract spec-wide** — a 500 is abnormal operation (the server failed), not a
    documented result, so it is no longer enumerated per-operation (4xx + the
    deliberate 501/503 signals remain), locked by a `TestNo500Enumerated` guard.
  - ✅ **A0.6 (2026-06-13)** — **CLI ⊆ OpenAPI surface** guardrail (principle 3
    "no UI backdoor", *tested* not asserted). A CI contract test (`cmd/harbor/
    cli_surface_test.go`) reconstructs the harbor command tree from `main.go` by
    AST and checks every command against a `cliSurface` catalog: each **operator**
    command must map to a real OpenAPI `operationId`; each **break-glass/local** one
    (`genesis`, `ca-init`, `issue-cert`, `migrate`, `ipam`, the `worker` daemon,
    `audit add` — audit-row injection is deliberately off-API for integrity, server
    launchers, meta) must carry a justification. A new/removed command forces a
    classification decision (bidirectional check). Scope chosen: parity test only —
    the HTTP-client refactor (needs 2.11 auth) and TS client (needs `ui/`) stay
    deferred (A0.7+). Adversarially reviewed (16-agent; 6 confirmed → 1 root cause):
    the extractor **failed *open*** on un-modeled dispatch shapes (const/ident case
    labels, `default:`-clause logic, pre-switch `if`-guards, if/else chains, non-
    `cmd*` handlers, dispatch outside `main`'s switch) — a backdoor could ship green.
    Rewrote it to **fail *closed*** (errors on any shape it can't read; resolves
    handlers by any in-file function, not a name prefix) and added a
    `TestExtractorFailsClosed` self-test that proves each dangerous shape is now
    rejected — so the guardrail's own integrity is itself tested.
  - ✅ **A0.7 CLI logging + polish (2026-06-13).** New `internal/clilog`: a `slog`
    setup that is **human-readable text on a TTY and JSON when run as a service**
    (`-log-format auto|text|json`, `-log-level`), installed as `slog.Default()` so the
    daemon libraries (`supervisor`/`renew`/`heartbeat`/`drift`/`adminapi`/`adminauth`)
    inherit the format with no threading. The long-running daemons — harbor `core-api`
    / `admin-api` / `enroll worker`, `pilot supervise`, `gateway` — now emit **structured
    lifecycle + background-task logs** (start/listening/shutdown/stopped, mode + auth
    diagnostics, worker batch progress, SIGHUP reloads, build version) instead of raw
    `printf`. Interactive command **results stay clean stdout** (logs → stderr) so
    pipelines/`jq` are unaffected. Adversarially reviewed (4-agent; 1 confirmed + fixed):
    the pilot SIGHUP reload handler still used raw `fmt`, breaking the JSON stream — now
    routed through the logger. No secret leakage; stdout/stderr discipline verified.
  - ✅ **A0.8 admin API tokens (2026-06-13).** Non-interactive machine auth for
    `/admin/v1` (the human path is an IdP session; automation/CI/curl/the future TS
    client present `Authorization: Bearer`). `internal/adminauth/token.go`:
    `harbor_`-prefixed tokens (32 random bytes, scanner-friendly), **stored only as a
    SHA-256** (a DB read yields no usable credential), with scoped roles + expiry +
    revocation; `TokenProvider` resolves the bearer header on the existing
    `Identify(r)` seam, and an `adminapi.ChainProvider` runs it **before** the
    session/dev provider so tokens and human sessions coexist. **Security rule:** a
    token's `mfa_satisfied_at` is always nil, so a token can run operator ops but is
    refused the **step-up-gated** dual-control actions (approve / policy publish) —
    machine approval of two-person control is impossible by construction. `harbor
    admin-token create|list|revoke` (LOCAL bootstrap — they create the auth, so can't
    require it; audited; token printed once, never logged); classified break-glass in
    the A0.6 catalog (whose extractor now parses the whole package, not just main.go).
    Migration `000010`. Adversarially reviewed (3-agent): **no findings**.
  - ⬜ **A0.8b — runtime CLI⊆API parity:** refactor the operator `harbor` commands to
    consume `/admin/v1` over HTTP (using a token), upgrading the A0.6 static-subset
    guardrail into runtime parity. Generate the **TS client** once `ui/` exists.
- **A1 — Policy analysis engine** (gates UI-4): reachability query → flow-diff/blast-
  radius → assertions + publish gate, snapshotted into approvals.
- **A2 — SSE change emitter** (upgrades UI-2+ live views; polling until then).
- ✅ **2.11 admin SSO + RBAC — foundation (2026-06-13).** New `internal/adminauth`:
  a **server-side session layer** (opaque cookie, SHA-256 at rest, httpOnly + SameSite,
  absolute TTL + revocation, **session-bound** double-submit CSRF) behind a
  **protocol-agnostic `Authenticator` seam** (bring-your-own-IdP — the session is
  Harbor's, so the protocol only matters at login). Three providers ship: generic
  **OIDC** (Auth-Code + PKCE, `go-oidc`, ID-token + nonce verified), **GitHub OAuth**
  (identity via the API, roles from org/team membership, verified-primary email only),
  and an **in-process mock OIDC IdP** (`harbor admin-api -mock-idp`) that exercises the
  real OIDC path for dev/CI. RBAC moved from binary-admin to a server-side
  **role→permission matrix** (`admin` superuser · `operator` day-2 fleet ops, no
  policy/CA · `viewer` read-only/default · `break-glass` capability). `GET /me` now
  carries the real `{principal, roles, mfa_satisfied_at}`; sign-offs/audit bind to it.
  Wired into `harbor admin-api` (`-oidc-*` / `-github-*` / `-mock-idp` / `-role-map`;
  real auth precedes the `-dev-auth` seam; `-mock-idp` is fail-closed mutually
  exclusive with real auth). Migration `000009_sessions`. Full OIDC browser flow +
  RBAC + CSRF + session lifecycle tested. Adversarially reviewed (11-agent; 3 confirmed
  + 1 fixed): **open-redirect** `\`-bypass in `return_to`, **mock-idp** not mutually
  exclusive with real auth, GitHub **unverified-email** as audit principal, and
  CSRF **bound to the session** (not a bare cookie). This unblocks **UI-0b**.
  - ✅ **2.11 SAML 2.0 (2026-06-13).** The enterprise AD path, added behind the same
    `FlowAuthenticator` seam (SAML is not OAuth-shaped — a signed XML assertion by
    HTTP-POST to an ACS, not a `?code=` callback). `internal/adminauth/saml.go`:
    SP-initiated AuthnRequest → IdP → ACS validation via `crewjam/saml` + `goxmldsig`
    (signature against the IdP metadata cert, audience == SP entity id, conditions,
    **InResponseTo bound to our AuthnRequest**), NameID → principal, attribute →
    groups → the shared `RoleMapper`; an SP-metadata endpoint; AD FS/Entra MFA via
    AuthnContextClassRef. Standard lib only (no hand-rolled XML-dsig); `golang-jwt`/
    `samlsp` kept OUT of the shipped binary. Tested end-to-end against a **full
    in-process mock SAML IdP** (`internal/adminauth/samlmock`, test-only) that signs
    real assertions, plus replay/forgery rejection. Wired into `harbor admin-api`
    (`-saml-idp-metadata-url/-file`, `-saml-sp-cert/-key`, `-saml-groups-attr`);
    `-mock-idp` is fail-closed mutually exclusive with it. Adversarially reviewed
    (9-agent; 1 confirmed + fixed): the login-state cookie was forgeable — an empty
    `InResponseTo` would have admitted unsolicited/IdP-initiated assertions, and a
    chosen one enabled replay — so login-state cookies (SAML **and** OIDC) are now
    **HMAC-signed** (tamper-evident), the ACS rejects an empty request id, and
    `AllowIDPInitiated` is explicitly off.
  - ✅ **2.11 step-up MFA enforcement (2026-06-13).** The authority-GRANTING dual-control
    actions (`approve`, policy `propose`) now require RECENT MFA: `requireStepUp` checks
    the session's `mfa_satisfied_at` against `MFAFreshness` (default **15m**, 0 disables);
    stale/absent → a distinguishable **403 `step_up_required`** so the console can force a
    re-auth and retry. **Deny is deliberately NOT gated** — vetoing is the fail-closed
    direction; a bad change must always be stoppable. The re-auth path is `?step_up=1` →
    OIDC `prompt=login&max_age=0`, SAML `ForceAuthn` → a fresh login mints a new session
    with a fresh `mfa_satisfied_at`. GitHub surfaces no MFA, so a GitHub session can never
    satisfy step-up (by design). Wired into `harbor admin-api -mfa-freshness`; the dev seam
    asserts MFA so local dogfooding still works. Adversarially reviewed (15-agent; 2
    confirmed + fixed): a **future-dated** `mfa_satisfied_at` defeated freshness (one-sided
    check, never expired) → symmetric bound with a small clock-skew tolerance (mirrors
    `internal/nonce`); and `mfaFromClaims` **fell back to the token `iat`** when `auth_time`
    was absent, making a cached MFA look fresh → now requires `auth_time` (fail closed).
  - ⬜ **2.11+ deferred:** SAML **SLO** (single logout) + **encrypted assertions**; the
    **CLI→HTTP refactor (A0.8b)** can now proceed (admin tokens landed in A0.8).

**UI track (each phase front-to-back, no screen before its data):**
- **UI-0 — Foundation + design gate** *(needs A0):* design system + Storybook + the
  3-comp design gate (§5); app shell (nav, ⌘K, env tint); generated API client; the
  dual-control/preview/destructive-action primitives. Ship **read-only Dashboard
  (with the §3 fleet identity + health rollup) + Devices + Audit on the dev-auth
  seam** — a *running, data-backed* demo, not just Storybook. Real OIDC/MFA = **UI-0b**
  when 2.11 lands.
  - ✅ **UI-0 foundation (2026-06-13).** The SPA skeleton + the running, data-backed
    demo. New `ui/` (Vite 8 + React 19 + TS 5.9; Tailwind v4 CSS-first `@theme` with the
    §5 domain tokens — mesh/surface/edge/ink, accent=permitted, Geist; TanStack Query;
    react-router 7). **Generated, typed API client** (`openapi-typescript` →
    `openapi-fetch` against `internal/adminapi/openapi.yaml`; the generator stays
    build/test-only — `go list -deps` confirms it is in **no** shipped binary). App shell
    (sidebar nav + topbar identity/sign-out + env banner) over three read-only screens:
    **Dashboard** (§3 health rollup + reasons + metrics), **Devices**, **Audit** — all on
    the bearer-token / dev-auth seam. **Served by Core**, not a separate origin: new
    `internal/adminui` embeds the built bundle via `go:embed` behind a `ui` build tag (a
    plain `go build` ships a "not built" stub, so CI never needs Node) → one artifact,
    lockstep UI↔API versioning. **Zero authority (P-UI-1):** the client makes no authz
    decision; **environment posture is server-injected** into `index.html` (operator-set
    `-environment`, sanitized to a benign token) and read **fail-closed** (anything but
    `production` ⇒ non-prod banner) — never inferred from the URL.
  - ✅ **UI-0 HTTPS/TLS + console hardening (2026-06-13).** TLS across all three servers
    via new `internal/httpserve` (`ListenAndServeTLS` when `-tls-cert`/`-tls-key` are set
    — TLS 1.2+ floor, HTTP/2; else plain) + a `Scheme()` helper for logs. **Fail-closed
    transport posture (P8):** the public **gateway** refuses plaintext unless `-insecure`
    (upstream-TLS opt-out), and a partial cert/key pair is a hard error; **admin-api**
    treats `-environment=production` as the prod signal — refusing to start without Secure
    cookies and hard-blocking `-dev-auth`. Console security headers (`internal/adminui`):
    a strict **CSP** that pins the inline runtime-config script by its **sha256** (so
    scripts never need `'unsafe-inline'`), `X-Frame-Options: DENY`, `nosniff`,
    `Referrer-Policy: no-referrer`, and **HSTS over TLS**; hashed assets `immutable`,
    index `no-store`. Adversarially reviewed (9-agent): 4 low findings, all fixed +
    regression-tested.
  - **Deferred to later UI-0 increments:** Storybook + the 3-comp **design gate** (§5),
    the **⌘K** command palette, visx charts, the Tag Canvas / reachability **matrix**
    hero (§4.2–4.3), the dual-control/preview/destructive-action component primitives,
    and build-time **style-src** hash tightening.
  - ✅ **UI-0b auth shell (2026-06-13).** Real session auth wired into the SPA,
    replacing the dev-auth seam (frontend-only — the 2.11 backend already shipped).
    **AuthGate**: the console renders the authed chrome ONLY for a live session, driven
    entirely by `/me` (the server is the source of truth; never inferred from the URL) —
    killing the redirect-flash. New **Login** screen discovers methods from
    `/admin/v1/auth/providers` and starts the server's OIDC/SAML/GitHub flow with a
    sanitized same-origin `return_to`. **Typed problem+json error model** (`errors.ts`:
    `ApiError` + `isUnauthenticated`/`isStepUpRequired`/`isForbidden`) so the three 403s
    (step-up vs RBAC vs CSRF) are distinguishable and pages render the server's
    `title`/`detail` instead of hardcoded copy. **Session lifecycle:** a mid-use 401 on
    any query *removes* cached `/me` so the gate flips to login immediately — never paints
    stale data behind a dead session. **CSRF:** an openapi-fetch middleware auto-attaches
    `X-CSRF-Token` (from the JS-readable `harbor_csrf` cookie) to every mutation, so
    future typed writes are CSRF-correct by construction. **Step-up MFA primitive:**
    `redirectToStepUp` + the `step_up_required` classifier — the re-auth/retry hook UI-1
    plugs into. **Zero authority (P-UI-1)** preserved: no tokens in JS; every authz
    decision stays server-enforced. Added **Vitest** with 18 unit tests over the
    security-critical pure logic (problem parsing, `return_to` sanitization, CSRF/login
    URL building). Adversarially reviewed (6-agent): 2 low findings, both fixed +
    regression-tested.
  - **Deferred to UI-1:** client-side RBAC control-hiding (defense-in-depth; there is no
    privileged control to hide yet), the step-up prompt/modal UX, and surfacing MFA
    freshness in the header — all land with the first privileged action.
- **UI-1 — Enrollment** *(M3):* approval queue, join keys (auto-issue warned),
  conflict/admit inbox, funnel, quotas; console onboarding checklist + empty-states.
  - ✅ **UI-1 enrollment + join keys (2026-06-13).** The first **mutating** screens, and
    the first real consumers of the UI-0b CSRF middleware + RBAC seam. **Enrollments**
    (`pages/Enrollments.tsx`): the approval queue with Pending/Approved/Denied tabs,
    **keyset pagination** (real `next_after` paging — no silent cap), and **approve /
    deny** actions. Approve is a one-click issue (server allocates the IP, shown back);
    deny opens a dialog for an optional reason surfaced to the rejected host. **Join
    Keys** (`pages/JoinKeys.tsx`): list (groups, auto-issue/ephemeral mode, used/max,
    rate/hr, expiry, state) + **create** + **revoke**. Create warns loudly when
    **auto-issue** is on (skips per-device approval), and the **one-time secret** is
    shown in a **non-routable, ack-gated modal** (copy + download-as-file; the secret
    lives only in transient mutation state — never the query cache/URL/logs — and
    `reset()` discards it on close, per §8 secret-once). **RBAC defense-in-depth
    (first consumer):** new `api/perms.ts` mirrors the server matrix
    (admin=*, operator, viewer, break-glass) and hides actions a role can't use —
    the server still enforces (P-UI-1). New primitives: `Button`/`Chip`, a minimal
    `Dialog`, a dependency-free `Toast`, and a `MutationCache` that centrally handles
    auth/step-up on every write. Mutations are CSRF-correct (UI-0b middleware), disable
    in-flight, and `onSettled`-refetch so a **409 "not pending"** / **404 "already
    revoked"** / **501 "read-only"** reconcile cleanly. Vitest now 28 tests (added the
    RBAC matrix + formatters). Verified end-to-end against a live binary (secret-once
    shape, dup→409, revoke→404, approve-read-only→501). Adversarially reviewed
    (7-agent): 2 low findings, both fixed (no error toast over the login redirect;
    friendly RBAC-403 copy).
  - **Deferred (no backend data yet — confirmed absent):** the enrollment **funnel**
    (no aggregate/stats endpoint; `count` is page-size only), the **quota-usage**
    dashboard (`quota_per_hour`/`max_uses` are config, no usage endpoint), and the
    **conflict/admit inbox** (no such status — only the pending queue + a transient 409
    race). Also deferred: the formal **onboarding checklist** (strong empty-states
    shipped), bulk approve/deny, server-side search/total-count, and Radix-izing the
    Dialog. These need new backend endpoints before a screen.
- **UI-2 — Fleet health** *(M4):* expiry/cliff + lighthouse-availability + trust-
  integrity cards, version landscape, heartbeat detail, **topology map v1**
  (policy-permitted). Live via A2 or polling.
  - ✅ **UI-2 fleet dashboard (2026-06-13) — demo-able unit.** Rebuilt the Dashboard
    into the §3.3 verdict-first layout, every tile backed by REAL data (no dataless
    tiles): a plain-language **masthead** (authoritative `FleetHealth.totals.total`,
    status, audit, active policy — no region count, that field doesn't exist); the
    **health verdict** + severity-ordered reasons; an **active-operations strip**
    (`rollouts/current` + pending `approvals`, polled, collapses when idle, auto-
    rollback called out); and six focused cards — **convergence gauge**, **renewal
    cliff** (expiry buckets + soonest, read-only — no force-renew endpoint), **version
    landscape**, **trust integrity** (`audit/verify`, honestly distinguishing
    verified / tampered / unavailable), **lighthouse registry** (labeled — liveness
    pending), **recent activity**. The convergence/cliff/landscape tiles are computed
    **client-side** from the devices page (all fields confirmed on `Device`); a "first
    200 hosts" hint shows whenever the page is truncated (no silent fleet-wide claim).
    New `lib/fleet.ts` aggregations are pure + unit-tested (Vitest now 37). Polling
    stands in for live until A2/SSE.
  - ✅ **Synthetic demo harness (2026-06-13).** New `harbor seed-demo` (DEV-ONLY,
    classified in the no-UI-backdoor guard) writes a believable ~14-host fleet straight
    into the store — heartbeats (version/cert/bundle spread, one each of expiring/stale/
    skewed/unhealthy), 3 lighthouses, 3 join keys, 3 pending enrollments, an active v43
    canary rollout, and a valid (verifiable) audit chain — so the **whole console**
    (UI-0…UI-2) demos end-to-end with real API responses, no live agents:
    `migrate up → seed-demo → admin-api -dev-auth`. Fails fast on a non-fresh DB.
  - Adversarially reviewed (7-agent): 2 low + 1 info confirmed, the lows fixed (rollout
    wave fraction is now 1-based/count-correct; seed-demo guards a populated DB).
  - ✅ **Recent-reaps dashboard panel (2026-06-18) — device reaper, ADR-adjacent.** A
    `RecentReapsCard` on the Dashboard filters the audit feed for `reaper-reap` (host,
    reason, whether the cert was revoked, when) — needed because the device reaper
    deletes the reaped host's heartbeat, so it drops from the heartbeat-driven fleet
    list. Backend: the **device reaper** (SHIPPED & LIVE on the poc — hourly schedule,
    cert-lapse + grace, overlay-IP reclaim, stale-heartbeat prune, soft-mark
    `reaped_at`/`reap_reason`, conservative defaults, `ncp_reaper_*` metrics) +
    **ephemeral hosts** (recorded at issue, shorter cert TTL, the join-key `ephemeral`
    toggle now wired). The provenance ephemeral badge note ("auto-reaping is future,
    impl 2.12") is now superseded — reaping is live.
  - **Deferred (no backend data — confirmed absent):** the **topology map** (no
    reachability-graph endpoint), **drift sparkline**, **force-renew** action,
    lighthouse **liveness/cert-expiry** (registry only until lighthouses heartbeat),
    region count, and a **device-detail** drill-down (no `GET /devices/{ip}`; the list
    row is the only per-host data). Each needs a new backend endpoint first.
- **UI-3 — Identity facts** *(M5):* group-map editor + cloud-trust settings;
  attestation evidence on device detail.
  - ✅ **M5.3 attestation backend predecessor (2026-06-13).** UI-3 was backend-blocked
    (attestation unwired/gated-off; no cloud-trust store; no evidence fields), so this
    built the predecessor that makes its data exist — **AWS SigV4 instance attestation
    end-to-end**, provider-agnostic by shape (Azure/GCP slot in later). New
    `internal/cloudtrust`: a **dual-control-published** trust config
    (`cloudtrust.publish`, mirroring `policy.publish`) — `{default_groups, aws:[{account,
    arn_patterns, groups, auto_issue}]}` — proposed with `cloudtrust:propose` + step-up
    and approved through the generic `/approvals` flow (no-self-approve, quorum-2). The
    **enroll consumer** now accepts `aws-sigv4`: re-verifies the SigV4 STS attestation
    (`awsattest.Verify`) **bound to the same single-use nonce + host pubkey** the JWS
    verify already consumed, enforces the cloud-trust allowlist (`MatchAWS`), derives
    groups (default ∪ matched account), and auto-issues or queues per the account's
    posture — **fail-closed** when disabled/unconfigured/untrusted. **Provider-agnostic
    evidence** (provider/account/principal/region/verified_at) is captured from the
    STS-vouched identity (never the host), persisted (migration 000011), and exposed on
    `EnrollmentView`. New endpoints `GET /admin/v1/cloudtrust/active` +
    `POST /admin/v1/cloudtrust/propose` (`-cloudtrust-db` loads the active config into
    Core). **Read-only UI** shipped: a **Cloud Trust** page (active trusted accounts +
    default groups) and **attestation evidence** surfaced on the Enrollments rows.
    Tests: cloudtrust unit + the attested enroll path end-to-end (auto-issue+evidence,
    pending, untrusted-denied, binding-mismatch-denied, STS-unavailable-denied,
    disabled-denied) via a mock STS. Adversarially reviewed (6-agent): 3 confirmed
    (1 medium + 2 low), all fixed — STS-unavailable now **denies cleanly** (the host
    re-enrolls with a fresh nonce) instead of nacking into a replay-loop, and STS
    429/5xx are classified unavailable rather than a rejection.
  - **Deferred to UI-3b / later:** ~~the dual-control cloud-trust **editor** (propose/
    approve UI — read-only today)~~ *(superseded 2026-06-18: the **Cloud Trust** editor
    SHIPPED — Add accounts / Propose change, dual-control + step-up)*, **Azure/GCP**
    attestation providers, the full **5.5 immutable-fact group map** (per-account default
    groups stand in for now), live hot-reload of the cloud-trust config (startup-read
    today, like `-policy-db`), and a device-detail drill-down (needs a `GET /devices/{ip}`
    endpoint).
  - ✅ **SSO user enrollment + User Trust admin UI (2026-06-18) — ADR 0004/0009.** A
    sibling identity-facts surface to Cloud Trust: a new **User Trust** page
    (`pages/UserTrust.tsx`, nav `/usertrust`) — the dual-control-published config of which
    IdP AD-group memberships may SSO-enroll, and the mesh groups + netblock + auto-issue
    each is granted (ordered, first-match; whole-config republish through the generic
    `/approvals` flow, gated `usertrust:propose`, mirroring Cloud Trust exactly). SSO
    **provenance** surfaces on the shared `JoinedVia` cell. Backend: the off-mesh gateway
    SAML enrollment portal (no CA), `internal/ssoassert` dedicated-key assertion, Core
    `processSSO` re-verify + usertrust first-match, deploy-threaded through
    genesis/bootstrap/terraform. **CODE-COMPLETE + DEPLOY-THREADED but OFF BY DEFAULT /
    NOT rolled out** — SSO stays disabled until an operator creates the AD SAML app,
    publishes a usertrust config, and sets `sso_acs_url`.
  - ✅ **IPAM console (2026-06-18) — ADR 0010.** A new **IPAM** page (`pages/IPAM.tsx`,
    nav `/ipam`): named-netblock CRUD, the live overlay-pool selector/segments, the
    growth-envelope **Suggest**, and used% live utilization — all SHIPPED & LIVE, with the
    backend admin API (`/admin/v1` netblock CRUD + suggest + allocations), Prometheus
    `ncp_ipam_*` gauges, and a dashboard tile. (This subsumes the "Network/IPAM" item the
    UI-4 line below still lists as part of the headline designer.)
- **UI-4 — Policy & Group-Tag Designer** *(M6 + A1) — the headline:* matrix-default
  + canvas + DSL, the analysis rail (reachability/tests/diff/blast-radius),
  single-admin-aware dual-control publish, canary monitor, drift panel; Network/IPAM.
  - ✅ **UI-4a dual-control publish pipeline (2026-06-13).** The data-backed half of the
    designer (the §4 matrix/canvas/analysis-rail are A1-blocked and deferred). New
    **Approvals inbox** (`pages/Approvals.tsx`): lists dual-control changes by state
    (Pending / All / Committed / Denied / Failed) — both `policy.publish` and
    `cloudtrust.publish` flow through it — with a **review dialog** showing the proposed
    payload + sign-off progress (X/quorum) and **Approve / Deny**. This is the first real
    consumer of the **step-up MFA** primitive: approve is step-up-gated, so a stale-MFA
    approve auto-redirects to re-auth and retries (UI-0b `MutationCache`); deny is the
    ungated single veto. **No-self-approval** is shown (the Approve button is gated with
    a reason when you proposed it) and **server-enforced** (409 backstop); the
    single-admin dead-end is messaged. New **Policy page** (`pages/Policy.tsx`): the
    active published policy (rules + DSL + change id/hash), a **compile preview** (draft
    DSL + groups → server `policy/compile`: valid / invariants-ok / per-host inbound+
    outbound incl. baseline — live-lint, read-only), and **propose for approval**
    (step-up-gated, opens a dual-control change). New pure dual-control helpers
    (`lib/approvals.ts`) unit-tested (Vitest 46). `seed-demo` now publishes an active
    policy + leaves a **pending policy change** for a distinct admin (mock-IdP Ada) to
    approve in the demo. Verified end-to-end (propose → inbox → distinct-actor approve →
    commit → active; self-approve → 409). Adversarially reviewed (3-agent): 1 low fixed
    (the transient `committing` state now shows under an All tab, so a change is never
    invisible mid-commit).
  - **Analysis rail delivered (2026-06-13/-18):** the §4 Policy page now renders the full
    `AnalysisRail` — the **active-vs-draft flow-diff + blast-radius** panel (A1.2a), the
    **reachability query** with "why", the **test runner**, and the all-pairs
    **reachability matrix grid** (A1.1). Still **deferred to UI-4b:** the reachability
    **matrix as the default authoring view** (it is a read-only rail grid today, not the
    editor; no TanStack-grid authoring surface yet), the **Tag Canvas** (no xyflow/WebGL
    dep yet), **test authoring/save** + the publish-gate result surfaced in Approvals
    (A1.2b), the visual **diff overlay onto the matrix**, the CodeMirror DSL editor with
    rich per-span diagnostics, and canary-rollout monitor + drift panel. *(Network/IPAM
    SHIPPED 2026-06-18 — see the IPAM console note under UI-3.)*
- ✅ **Device provenance + /devices filtering (2026-06-13) — backend predecessor + UI.**
  The keystone slice that unblocked three §3.4 planned changes at once (provenance + scope
  filters, join-key name on Enrollments, dashboard "why" drill-downs — see those callouts).
  Backend: `GET /admin/v1/devices` enriches each row with provenance + issued groups from
  the **authoritative** (latest-issued) enrollment via a batched lookup (no SQL JOIN — the
  codebase has none); scope filters (`provider`/`attest_account`/`join_key`) resolve an
  allow-set and the handler **keyset-fills** the page in Go (bounded bind-params, correct
  `next_after`); the `condition` filter reuses `fleet.ConditionSQL` (the SQL twin of the
  `fleet.classify` verdict logic — a test pins `?condition=X` count == `/fleet/health`
  total, so the drill-down can't drift). `EnrollmentView.join_key_name`; `fleet.Reason.link`
  populated for the device-condition codes; migration 000012 indexes
  `enrollments(overlay_ip, status)`. UI: Devices "Joined via" + groups columns with
  click-to-filter and removable filter chips (now `useInfiniteQuery` so the drill-down
  never silently caps), Enrollments `token · <name>`, clickable dashboard "why" rows.
  `seed-demo` now issues a provenance-bearing enrollment per heartbeat (2 AWS accounts + 3
  join keys) so the whole feature demos. Adversarially reviewed (5-agent + verify pass):
  14 confirmed of 32 → fixed the material ones (the UI 200-row cap and the unbounded
  `IN (...)` bind-param cliff, replaced by the keyset-fill loop; single join-key-map load;
  added pagination + populated-conformance tests). Verified: full Go suite + `go vet` + 4
  cross-builds + migrate up/down/up + UI build + 46 UI tests.
- **UI-5 — Trust ops** *(M7–M8):* revocation/blocklist + propagation SLO; CA/key
  rotation wizards; lighthouse fleet management.
  - ✅ **Releases console (2026-06-18) — #39 / ADR 0003.** Out of the original UI-5
    sequence: a new **Releases** page (`pages/Releases.tsx`, nav `/releases`) — the
    nebula + pilot binary registries and per-lane staged **fleet upgrades** to a
    registered generation (binaries added out-of-band via `harbor nebula/pilot add`;
    no upload in the UI), with the canary rollout start/abort controls. Backed by
    `/admin/v1` release-registry list + fleet-upgrade endpoints. SHIPPED & LIVE.
  - **Still deferred:** revocation/blocklist UI + propagation SLO, the CA/key
    rotation wizards (M8), and dedicated lighthouse fleet management beyond the
    registry add/remove already on the dashboard.
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
