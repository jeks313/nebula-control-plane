# Planning docs

In-repo copies of the Nebula Control Plane planning docs, so the repo is self-contained
(no vault required for a cold start).

**Status (2026-06-18):** The original planning docs (below) have been joined by an **ADR series (0001–0010)**, three build **decision logs** (IPAM / SSO / reaper), and several **runbooks** as the design landed in code. Most of the original milestone scope is SHIPPED & LIVE on the `poc` stack (which *is* the prod control plane today). See each doc's own `Status (2026-06-18)` / `status:` line for current state.

## Original planning docs

| Doc | Purpose |
|-----|---------|
| `Nebula Control Plane - Design Plan.md` (v3) | Architecture, security model, flows. Source of truth for *what* & *why* (uses `§`/`P` refs). |
| `Nebula Control Plane - Implementation Plan.md` (v2) | Milestones **M0–M10**, PR-sized steps with "Done when". Source of truth for *order* & *scope*. (See its own `Status (2026-06-18)` line — most milestones are SHIPPED & LIVE.) |
| `Nebula Control Plane - Protocol Spec.md` (v1) | The Pilot↔Harbor **wire protocol** (enrollment/attestation/bundle/lifecycle). M3–M5 implement against it; reviewed at 9.7. |
| `Nebula Control Plane - Genesis Runbook.md` | The two-operator **genesis ceremony** (CA + config-signing roots + first lighthouse). Implements 3.1. **LIVE** — this exact flow built the `poc` stack. |
| `Nebula Control Plane - Chaos and Outage Runbook.md` (v1) | **Harbor outage (P3)**: what survives, the worst case (cert lifetime = outage budget), emergency response. Implements 4.9. |
| `Nebula Control Plane - Infrastructure Plan (AWS).md` (v2) | Local-first → minimal AWS harness → full production (incl. k3s Tier 1+). |
| `Nebula Control Plane - Admin UI Plan.md` | Harbor web console + site settings. |
| `Nebula Control Plane - UI Implementation Plan.md` | The React admin console build plan. **SHIPPED & LIVE** (`-tags ui`, served on :443). |
| `Nebula Control Plane - Security Posture - Public Enroll Endpoint.md` | Threat model + hardening for the public enrollment endpoint (the pull-based gateway). |

## Architecture decision records (ADRs 0001–0010)

Each ADR captures one decision and its rationale. Status reflects the live `poc` stack.

| ADR | Decision | Status |
|-----|----------|--------|
| 0001 — Firewall Policy Scoping | How central firewall policy is scoped to groups. | accepted |
| 0002 — Post-Enrollment Group Reassignment | Moving a host between groups after it enrolled. | accepted |
| 0003 — Pilot + Nebula Self-Update & Distribution | Self-update, staged canary rollout, failed-sha quarantine. | SHIPPED & LIVE (live-validated) |
| 0004 — SSO-Driven User Enrollment | SAML user enrollment via the off-mesh gateway + usertrust. | CODE-COMPLETE, OFF BY DEFAULT / NOT ROLLED OUT |
| 0005 — Pull-Based Enrollment Gateways | Off-mesh gateway; Harbor *pulls* enrollments via mTLS collect. | SHIPPED & LIVE (Fargate) |
| 0006 — Distroless Container Images (Fargate gateway & lighthouse) | Distroless images; lighthouse uses a `cmd/nebula-boot` shim. | SHIPPED & LIVE |
| 0007 — Production Deploy | The `poc` *is* the prod stack (Aurora + KMS + ACME + Fargate + SSM). | SHIPPED & LIVE (prod-grade gaps remain) |
| 0008 — Client Install & Bootstrap | `pilot install`; Linux / macOS(launchd) / Windows(SCM) backends. | SHIPPED & LIVE (live-validated) |
| 0009 — Control-Plane Trust-Zone Separation | Trust-zone split that backs SSO enrollment. | CODE-COMPLETE, OFF BY DEFAULT |
| 0010 — IPAM: Named Netblocks & Per-Join-Method Allocation | DB-driven netblock resolver, per-method binding, auto-grow. | SHIPPED & LIVE |

## Decision logs (build records)

| Doc | Contents |
|-----|----------|
| `IPAM-DECISIONS.md` | IPAM build decisions D1–D23 (ADR 0010). |
| `SSO-DECISIONS.md` | SSO enrollment build decisions (ADR 0004 / 0009). |
| `REAPER-DECISIONS.md` | Device reaper build decisions R1–R20 (cert-lapse IP reclaim — SHIPPED & LIVE). |

## Runbooks & operational notes

| Doc | Purpose |
|-----|---------|
| `Nebula Control Plane - Runbook - Publishing pilot and nebula releases.md` | How to cut + publish pilot/nebula releases (release registry + canary). |
| `Nebula Control Plane - Runbook - Entra ID SAML SSO for the Console.md` | Wiring the Harbor **console** login to Entra ID (SAML) — a separate prod item from mesh SSO enrollment. |
| `Nebula Control Plane - Onboarding the poc mesh into AD (Entra ID) SSO.md` | Operator steps to turn on ADR 0004 mesh SSO enrollment (AD app + usertrust publish + `sso_acs_url`). |
| `Nebula Control Plane - Code Review First Pass.md` | First-pass code review notes. |

## Provenance & sync

These originated in Chris's Obsidian vault (`~/Data/knowledge/Plans/`). They are
**copies** — keep them in sync if edited in either place. The docs use Obsidian `[[wikilinks]]`
(e.g. to `PgDog…`, `Postgres by Example`) that only resolve inside the vault; they read fine as
plain text here.

Recommended: treat **this repo as canonical** going forward (it's a standalone project) and copy
changes back to the vault for browsing, rather than the reverse.
