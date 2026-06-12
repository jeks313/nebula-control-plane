---
created: 2026-06-11
source: claude-chat
status: draft
project: nebula-control-plane
tags: [networking, nebula, security, ui, admin, design]
---

# Nebula Control Plane — Admin UI Plan

Companion to [[Nebula Control Plane - Design Plan]] (v3) and [[Nebula Control Plane - Implementation Plan]] (v2). Those docs name an "admin API/UI" but never design it. This plans the **Harbor web admin UI** ("the console") and brainstorms — exhaustively — what it should do. Section refs *(§…)* point at the design doc.

## 1. Purpose & where it fits

The console is the human face of Harbor: the place operators approve devices, author firewall policy, manage IPAM, run rotations, investigate incidents, and configure site-wide defaults. It is **served by Harbor Core over the mesh** (`group:control-plane`), reached through Nebula like any other Core API — plus the out-of-band break-glass path (§10) when the mesh itself is down.

Everything below is *also* doable via the admin API/CLI (API-first); the UI is the convenience and safety layer, never the only path (matters for automation and break-glass).

## 2. First principles (the UI's own security posture)

The console is high-value — it's where privilege is exercised — so its own threat model matters:

- **P-UI-1 — The UI is a thin client, never a trust root.** It holds **no signing authority**. All minting goes through Signer→KMS; all dual-control and RBAC are enforced **server-side**. A fully compromised UI tier must not be able to sign a cert, bypass two-person approval, or mutate state the API wouldn't allow. (This keeps the UI *out* of the §2.1 TCB.)
- **P-UI-2 — Mesh-only + SSO + MFA.** Reachable only over the overlay; login via IdP OIDC with MFA; sessions short, re-auth for sensitive actions (step-up auth).
- **P-UI-3 — RBAC everywhere.** The UI renders only what the role permits; the server enforces it regardless of what the client sends. Read-only is the default role.
- **P-UI-4 — Dual-control is a first-class UX, not a checkbox.** Privileged/destructive actions produce a **request** that a *different* authenticated admin must approve; the initiator can never self-approve; the UI shows who must sign off and the pending state.
- **P-UI-5 — Preview / dry-run before commit.** Policy compiles, group-map changes, IP allocations, rotations, and bulk actions all show a **blast-radius preview** ("this affects N hosts") and invariant pre-checks *before* anything happens.
- **P-UI-6 — Every mutation is audited and attributable** (§7); the UI surfaces "this will be logged as …" and links the resulting audit row.
- **P-UI-7 — Hard guardrails on destructive ops.** Typed confirmations, invariant blocks (can't blocklist `control-plane`/lighthouses), rate-limit visibility, and "are you sure — this is irreversible" gates with the exact impact.
- **P-UI-8 — No secrets in the browser.** No private keys, no KMS creds, no long-lived tokens client-side; standard web hardening (strict CSP, CSRF protection, no inline secrets).

## 3. Information architecture (top-level nav)

1. **Dashboard** — fleet & system health at a glance
2. **Devices** — inventory, detail, lifecycle actions
3. **Enrollment** — approval queue, tokens, activity, quotas
4. **Groups** — group catalog + the immutable-fact **group map**
5. **Policy** — firewall policy editor, rollout, simulator, drift
6. **Network** — overlay CIDR, IPAM pools, allocations
7. **Lighthouses** — discovery fleet
8. **Keys & CA** — key inventory + rotation wizards
9. **Revocation** — blocklist + bulk offboarding
10. **Detections** — security events & reconciliation
11. **Audit** — searchable, chain-verified log
12. **Settings** — site/global configuration (§6 below)
13. **Access** — admins, RBAC, the pending-approvals (dual-control) queue
14. **System** — Harbor/Pilot health, versions, deploys, backups

Plus a persistent **global search** (device, overlay IP, cert fingerprint, instance-id, account) and a **notifications/inbox** (pending approvals, expiring certs, firing detections).

## 4. Screen-by-screen breakdown

### 4.1 Dashboard
- Device counts by **state** (active / pending / suspended / decommissioned), **platform** (Linux/Windows/macOS), **cloud/region**, **group**.
- **Cert-expiry posture**: % within N days, expiry histogram, lighthouse expiry callouts.
- **Pending approvals** count → click-through (enrollment + dual-control queue).
- **Active detections/alerts** summary (§7.1) with severity.
- **CA/key status**: active CA, rotation state, days-to-expiry, deletion-protection on/off.
- **Circuit-breaker** gauge (signing rate vs ceiling) and recent trips.
- **System health**: Core replicas, Postgres, KMS reachability, queue depth, lighthouse up/down.
- Recent audit highlights; recent enrollments funnel.

### 4.2 Devices (inventory + detail)
- **List**: fast search + filters (group, cloud, account/subscription, region, platform, state, cert-expiry window, owner, Pilot version, last-seen). Saved views.
- **Detail**: identity & attestation method + **evidence** (which sigv4/IID/Azure facts were verified); groups (with provenance — which group-map rule granted them); overlay IP; **cert history** (fingerprint, serial, CA, validity, signed-by); applied policy/config version; **heartbeat** (last-seen, Pilot/nebula versions, clock sanity, posture facts); connection/discovery metadata.
- **Per-device actions** (RBAC + dual-control where privileged): approve/deny (if pending), **force-renew**, **suspend**, **decommission**, **revoke/blocklist**, reassign groups, view full audit trail.
- **Device timeline**: enroll → renewals → policy applies → drift events → revoke.
- **Bulk actions** with guardrails (bulk revoke = dual-control + rate-limited + blast-radius preview).
- **Conflict inbox**: instance-id re-enrollment conflicts (§4.1 / 5.4) needing human review.

### 4.3 Enrollment & approvals
- **Approval queue** (manual/PENDING path, impl 3.9): list with attestation evidence, requested groups, source account/subscription; approve/deny **with reason**; bulk approve (guarded).
- **Enrollment tokens** (impl 3.4): generate one-time tokens (TTL, device-class, intended groups, max uses=1), list outstanding, revoke; clear "headless on-prem only" framing.
- **OIDC device-flow** status for laptops (impl 9.1): in-flight codes, who's enrolling.
- **Enrollment activity / funnel**: submitted → attested → auto/pending → issued/denied, with failure reasons (great for debugging "why won't this host join").
- **Quota status** (impl 3.10): per-account/subscription and per-instance-id usage vs limits; adjust quotas (privileged).

### 4.4 Groups & group map
- **Group catalog**: define groups, descriptions, and a **reverse view** of what each group grants (computed from policy — "members of `db` can be reached by `web:5432`").
- **Group map editor** (§4.3a) — *the* security-critical screen: the **immutable-fact → groups** mapping (AWS account + role-path, Azure subscription + resource-group, explicit records). UI makes it impossible to key on mutable tags. Versioned, **dual-control** to publish.
- **Preview**: "a device from account X / role Y would receive groups […]" before saving.
- **Version diff** between group-map revisions.

### 4.5 Firewall policy
- **Editor**: group-based DSL (impl 6.1) with a structured form *and* raw view; default-deny baseline shown explicitly.
- **Compile preview** (impl 6.2): render the per-host firewall section for a chosen host/group.
- **Invariant results** (impl 6.3): green/red on "control-plane reachable," "lighthouse discovery intact" *before* publish; publish blocked on red.
- **Dual-control publish** (impl 6.5): draft → request review → second approver → publish; diff shown to the approver.
- **Version history** + diff + one-click rollback to a prior signed version.
- **Rollout monitor** (impl 6.6): canary wave progress, per-wave heartbeat health, **auto-rollback status**, manual abort button.
- **Reachability simulator**: "can group A reach group B on port N?" answered from current/draft policy.
- **Drift report** (impl 6.7): hosts that attempted local edits, reverted.

### 4.6 Network & IPAM
- **Overlay CIDR / default network block** (site setting, §6) shown with current utilization.
- **Pools**: per-cloud/region sub-ranges (e.g. AWS `100.64.0.0/17`, Azure `100.64.128.0/17` — overlay block kept clear of k3s `10.42/10.43` defaults and LAN ranges) with utilization gauges and **exhaustion warnings**.
- **Allocation table**: IP → device, state, quarantine countdown, free/used; search by IP.
- **Reservations**: static allocations for lighthouses/gateways/Core.
- **Visuals**: utilization heatmap; projected exhaustion given enrollment rate.

### 4.7 Lighthouses
- **Fleet view** (impl 6.8): list, status, public address(es), cert expiry, discovery load/health.
- **Add / replace / remove** with **propagation status** — which hosts have the updated `static_host_map` — and the invariant guaranteeing discovery is never lost mid-change.
- Underlay reachability checks (UDP port open, NAT/hole-punch health) from §0.7.

### 4.8 Keys & CA
- **Key inventory**: host CA(s), config-signing key, release-signing key — purpose, KMS ARN, curve, **state** (staged/active/draining/retired), validity, deletion-protection.
- **CA rotation wizard** (impl M8): staged → **trust-distribution progress (% of fleet trusting `[CA1,CA2]`)** → cut-over → drain (live "active certs per CA") → retire, with each step gated on the prior being safe.
- **Emergency rotation** (impl 8.6): prominent danger styling, dual-control, explicit "expect tunnel churn" acknowledgement.
- **Config-signing & release-key rotation** (same overlap mechanism).
- KMS health + deep link to CloudTrail; deletion-alarm status.

### 4.9 Revocation & blocklist
- **Blocklist view**: current blocked fingerprints, when/by-whom/why.
- **Add to blocklist** (single) / **bulk revoke** (dual-control + rate-limited; UI shows the rate budget remaining).
- **Propagation status**: % of the **healthy fleet** carrying the updated blocklist — the SLO that actually matters (§4.7), not the target host.
- **Invariant enforcement**: UI refuses to blocklist `control-plane`/lighthouses.

### 4.10 Detections & security events
- **Detection feed** (§7.1): group-never-held, new account/subscription, signing-rate anomaly, **audit chain-break**, double-enroll, off-window policy change, **issued-vs-inventory reconciliation**, KMS deletion attempts.
- **Triage**: acknowledge / assign / link to device + audit; suppress-with-reason.
- **Reconciliation report**: issued certs vs live AWS/Azure inventory → orphan certs (cert with no running instance).

### 4.11 Audit
- **Searchable log** (impl 2.2): filter by actor, action, target, time range; per-object trails (device/policy/key).
- **Chain-integrity indicator**: verified against the **WORM copy** (impl 2.13); loud banner if the chain breaks.
- **Export** (CSV/JSON) for compliance; signed export option.
- "Who did what, when, and was it dual-approved" is one query away.

### 4.12 Access (admins, RBAC, approvals)
- **Admin directory** (from IdP): roles, last login, **MFA status**.
- **Role management** (RBAC, impl 2.11): define roles, scope permissions; principle-of-least-privilege presets.
- **Dual-control / pending-approvals queue** (cross-cutting): every two-person action awaiting a second approver — policy publishes, bulk revokes, group-map changes, key rotations, quota changes — in one place.
- **Break-glass usage log** (impl 9.2) and session management (revoke sessions).

### 4.13 System & operations
- **Harbor health**: replicas, Postgres (lag, failover state), queue depth, KMS, gateway status.
- **Version landscape**: Harbor version; **Pilot/nebula version distribution across the fleet** (drives 4.8 skew awareness) — highlight N-2 or older.
- **Self-update channel** (impl 9.6): available releases, rollout waves, rollback controls.
- **Deploy/upgrade status** (impl 9.9) and **backup/DR status + last restore drill** (impl 9.10).

## 5. Cross-cutting UX

- **Notifications/inbox** — expiring certs, pending approvals, firing detections, rollout needing attention.
- **Global search** across all object types.
- **Saved views & filters** per operator.
- **Everything has a "why"** — provenance shown (why this device has these groups, which rule, which version).
- **Forensic time-travel** — view a device/policy/IP as of a past timestamp (from audit).
- **Keyboard-friendly, dense, desktop-first** ops tool; responsive enough for a phone in an incident.
- **Consistent destructive-action pattern** — preview → typed confirm → (dual-control if privileged) → audited.

## 6. Site / global settings (exhaustive — the core ask)

The **Settings** area holds the site-wide defaults that everything else inherits. Grouped:

### 6.1 Network & addressing
- **Default overlay network block** (primary CIDR) and IPv6 overlay block.
- **Per-cloud/region sub-range scheme** (AWS/Azure/on-prem allocations).
- Default **pool sizing** + reuse **quarantine window**.
- Reserved ranges (lighthouses, gateways, Core).
- Overlay **MTU** default (from the §0.7 spike).

### 6.2 Cloud trust & auto-assignment *(explicitly requested)*
- **Approved AWS accounts** — allowlist of account IDs, each with allowed **role-path patterns** and the **default groups auto-assigned** to devices from that account/role. (Immutable-fact based, §4.3a.)
- **Approved Azure subscriptions** — allowlist of subscription IDs (+ resource groups), each with **default groups**.
- Per-account/subscription **auto-approve vs require-manual-review** toggle.
- Per-account/subscription **enrollment quotas** and default device-class.
- Attestation policy: which evidence is **required** (sigv4 + IID cross-check on/off; Azure chain pinning; ARM cross-check on/off).
- Cross-account role ARNs Harbor assumes for `DescribeInstances`/ARM checks.

### 6.3 Enrollment & approval policy
- Default **device classes** (server/laptop/lighthouse/ephemeral) and their group/lifetime defaults.
- One-time token defaults (TTL, max uses).
- OIDC/IdP settings for the laptop device flow.
- Conflict policy (instance-id re-enrollment → always review vs auto-rebuild rules).
- Naming policy (cosmetic only — §4.1).

### 6.4 Certificate lifecycle
- Default **cert lifetimes** per device class; longer for lighthouses/servers.
- **Renewal fraction** (default ⅔) and **jitter window** (impl 4.4 — stampede protection).
- Clock-skew tolerance and **nonce TTL** (impl 1.13 / 3.2).
- `NotBefore` backdating amount.

### 6.5 Security limits & guardrails
- **Signing circuit-breaker ceiling** (certs/hour) and trip behavior.
- **Enrollment quota** defaults (per-account, per-instance-id).
- **Bulk-operation rate limits** (bulk revoke/renew).
- Blocklist **propagation SLO** threshold; invariant-protected groups (control-plane, lighthouse) listed read-only.
- Gateway rate-limit / WAF thresholds.

### 6.6 Lighthouses & discovery
- Default lighthouse set advertised to the fleet.
- Discovery/keepalive tuning defaults.
- Underlay requirements reference (ports, SG/NSG expectations).

### 6.7 Identity & access
- **IdP / OIDC config** for admin SSO (issuer, client, claim→role mapping) and for laptop enrollment.
- **RBAC roles** and default least-privilege presets.
- **Dual-control matrix** — which actions require two approvers (policy publish, bulk revoke, group-map, key rotation, settings changes), configurable but with hard minimums.
- **Change windows / maintenance windows** for policy publishes and rotations.
- Step-up-auth requirements per action class.

### 6.8 Notifications & integrations
- **SIEM** export endpoint (detections + audit), **object-lock/WORM** target (impl 2.13).
- Alerting channels (PagerDuty, Slack, email) and routing per severity.
- Webhooks for enrollment/revocation events (e.g., CMDB sync).

### 6.9 Retention & compliance
- Retention for **audit**, **attestation blobs** (encrypted, short), enrollment records, heartbeats.
- **Data-residency** region for Harbor state (relevant to the deployment's approved region set).
- Compliance export formats / signing.

### 6.10 Environment & operations
- **Environment label** (staging vs prod — separate trust domains, §Deferred in impl plan) shown prominently to prevent cross-env mistakes.
- Feature flags.
- Tag/label taxonomy for devices.
- Pilot/nebula **self-update channel** policy (auto/staged/manual; wave sizes).

## 7. Build phasing (map UI to backend milestones)

The console grows with the backend; don't build screens before their data exists. The **admin CLI (impl 2.8) is the source API** the UI consumes — UI is purely additive.

- **UI-0 (after impl M2–M3):** auth shell (SSO/MFA/RBAC), **read-only Dashboard + Devices list/detail**, Audit viewer. Proves the thin-client/server-enforced model early.
- **UI-1 (with impl M3):** Enrollment approval queue + tokens; conflict inbox.
- **UI-2 (with impl M4):** fleet health/expiry dashboards; version-landscape; heartbeat detail.
- **UI-3 (with impl M5):** group map editor (immutable facts) + cloud-trust settings (approved accounts/subscriptions, auto-assign).
- **UI-4 (with impl M6):** policy editor + compile preview + invariants + dual-control publish + rollout monitor + drift; Network/IPAM screens.
- **UI-5 (with impl M7–M8):** revocation/blocklist with propagation status; **CA/key rotation wizards**; lighthouse fleet management.
- **UI-6 (with impl M9):** detections feed + reconciliation; full Settings; Access/RBAC admin; System/ops (deploys, backups, self-update); break-glass log.

Dual-control UX (P-UI-4) and the preview/guardrail patterns (P-UI-5/7) are built once in UI-0/UI-1 and reused everywhere.

## 8. Tech & open questions

- **Frontend:** SPA (React/Svelte/SolidJS) consuming the Core admin API, or server-rendered (HTMX/Templ) for a smaller attack surface and no client build. *Recommendation:* lean server-rendered or a minimal SPA — fewer moving parts, easier to keep the UI a dumb client (P-UI-1). **Open question.**
- **Where served:** by Harbor Core over the mesh; confirm it's a separate process from the signing-critical paths (a UI bug shouldn't touch the Signer).
- **Auth:** OIDC to the IdP, short sessions, step-up auth, RBAC claims; reuse impl 2.11.
- **API:** the UI must use the *same* versioned admin API as the CLI (no privileged backdoor); everything the UI can do is scriptable.
- **Offline/break-glass:** define a minimal break-glass UI (or CLI-only) reachable via the out-of-band path (impl 9.2) when the mesh is down.
- **Real-time:** rollout monitors / propagation status want live updates (SSE/websocket over the mesh) — confirm acceptable.
- **Open:** do we need a read-only "auditor" external view, or is mesh-only access sufficient for compliance reviewers?

## Sources / references

- [[Nebula Control Plane - Design Plan]] (v3) — §2.1 TCB, §4.x flows, §7 audit/detections, §9 API, §10 runbooks.
- [[Nebula Control Plane - Implementation Plan]] (v2) — milestones the UI screens map onto.
