# Planning docs

In-repo copies of the Nebula Control Plane planning docs, so the repo is self-contained
(no vault required for a cold start).

| Doc | Purpose |
|-----|---------|
| `Nebula Control Plane - Design Plan.md` (v3) | Architecture, security model, flows. Source of truth for *what* & *why* (uses `§`/`P` refs). |
| `Nebula Control Plane - Implementation Plan.md` (v3) | Milestones **M0–M10**, PR-sized steps with "Done when". Source of truth for *order* & *scope*. |
| `Nebula Control Plane - Protocol Spec.md` (v1) | The Pilot↔Harbor **wire protocol** (enrollment/attestation/bundle/lifecycle). M3–M5 implement against it; reviewed at 9.7. |
| `Nebula Control Plane - Genesis Runbook.md` (v1) | The two-operator **genesis ceremony** (CA + config-signing roots + first lighthouse). Implements 3.1. |
| `Nebula Control Plane - Infrastructure Plan (AWS).md` (v2) | Local-first → minimal AWS harness → full production (incl. k3s Tier 1+). |
| `Nebula Control Plane - Admin UI Plan.md` | Harbor web console + site settings. |

## Provenance & sync

These originated in Chris's Obsidian vault (`/home/jeks/Data/knowledge/Plans/`). They are
**copies** — keep them in sync if edited in either place. The docs use Obsidian `[[wikilinks]]`
(e.g. to `PgDog…`, `Postgres by Example`) that only resolve inside the vault; they read fine as
plain text here.

Recommended: treat **this repo as canonical** going forward (it's a standalone project) and copy
changes back to the vault for browsing, rather than the reverse.
