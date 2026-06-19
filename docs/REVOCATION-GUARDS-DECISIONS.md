# Revocation Guards — Decision Log

The two security guards layered on the cert blocklist (implementation-plan **7.2**, design
**§4.7 / P10**): (1) the registry must refuse to blocklist a **control-plane/lighthouse**
fingerprint, and (2) **bulk** revoke must be **dual-control + rate-limited**. Built on top of
the existing `internal/revocation` registry (single-host add/lift/list) and the live
`-blocklist-db` propagation path. Conservative defaults; security-critical, so it shipped
through a delegated build → adversarial security review → fix → re-verify loop.

**Status (2026-06-19):** SHIPPED (code + tests, gates green, re-verified SAFE). NOT yet
deployed to the live poc — see the deploy note at the bottom.

## Guard 1 — control-plane protection

| # | Decision | Rationale |
|---|----------|-----------|
| RG1 | The control-plane check is **always-on inside `Registry.Add`** — not an injected/optional predicate. It resolves the fingerprint → latest **issued** enrollment (`enrollments WHERE fingerprint=? AND status='issued' ORDER BY id DESC`) → refuses if `policy.GrantsReservedGroup(groups)` (`control-plane`/`lighthouse`). | No caller (CLI, reaper, future API) can forget the guard. Default-secure. |
| RG2 | **Fail-closed** on a DB error during the check (refuse the revoke); **allow** on unknown fingerprint (not a known control-plane host). | Can't confirm safety ⇒ don't blocklist. An unknown fp is, by definition, not control-plane. |
| RG3 | **Genesis now writes issued `enrollments` rows** for the lighthouse (always) and Core (only when `-core-pub` is given), with the reserved groups + overlay IP + `method='genesis'`. | The genesis-minted control-plane certs previously had **no** enrollment row, so RG1's group lookup missed them entirely (the CRITICAL adversarial finding). Recording them makes the group check authoritative — and fixes that those certs could not renew (`coreapi.handleRenew` needs the row). Idempotent (keyed on fingerprint+issued). |
| RG4 | A belt-and-suspenders **central-netblock** guard (`WithCentralBlock`) is **always-on + fail-closed** on every Add-capable CLI path (single `blocklist add`/`remove` and `bulk-revoke`), derived from a now-**required** `-pool` via `genesis.CentralBlock` — mirroring the reaper's wiring in `serve.go`. | Defense-in-depth for a reserved-range host that somehow lacks the group label, and it protects the `-device <central-ip>` path directly. RG3 is the primary fix on the `-fingerprint` path. |
| RG5 | `Lift` (un-revoke) is **unguarded**. | Lifting only removes a block; it can never blocklist the control plane. |

## Guard 2 — bulk revoke

| # | Decision | Rationale |
|---|----------|-----------|
| RG6 | A **bulk** revoke is a dedicated dual-control Kind (`revocation.bulk-revoke`) requiring **two distinct operators** (Propose + Approve), mirroring `cloudtrust publish` / `usertrust publish`. The single `blocklist add` stays single-operator/RBAC (unchanged). | Mass-distrust is the dangerous operation; the everyday single revoke shouldn't pay the dual-control tax. |
| RG7 | Per-operation size cap **`MaxBulkFingerprints = 100`**. | Bounds the blast radius of any one bulk op; forces a larger purge to be split + re-deliberated. |
| RG8 | Window rate **`MaxBulkPerWindow = 3` operations per `BulkWindow = 1h`**, counted as **operations** (via the `approvals`/dual-control ledger, `kind=bulk-revoke`, state committing/committed, in-window), **durable** (DB-backed — survives process restart / HA). | A security rate-limit must not reset on restart or be per-process; counting ops (not rows) avoids one 100-fp op exhausting a row-based budget. |
| RG9 | **Atomic + serialized**: every fingerprint is pre-validated for control-plane **before any write** (a single control-plane fp rejects the whole bulk, zero rows); the window-count check + per-fingerprint writes run in **one transaction** with a Postgres `pg_advisory_xact_lock` (SQLite serializes via its single writer). | Atomicity prevents a partial bulk; the lock closes a TOCTOU where concurrent committers on HA Postgres all read a stale count and exceed the cap. |

## Defaults worth retuning
`MaxBulkFingerprints = 100`, `MaxBulkPerWindow = 3 / 1h`. Conservative; adjust if real ops
need larger or more frequent bulk purges.

## Adversarial review (for the record)

The first build passed gates but the security review found **3 confirmed blockers**, all fixed
above and re-verified SAFE:

- **CRITICAL** — genesis control-plane/lighthouse certs were blocklistable (no `enrollments`
  row ⇒ RG1 returned ALLOW). Fixed by **RG3** (genesis records the rows). Regression test:
  `internal/genesis.TestGenesisRecordsProtectedEnrollments`.
- **HIGH** — the central guard was opt-in and absent on the single-add path. Fixed by **RG4**
  (always-on + fail-closed, required `-pool`).
- **HIGH** — the bulk window-rate counted *rows* not *ops* and was a TOCTOU (count-then-write
  unserialized). Fixed by **RG8/RG9** (ops-count + transaction + advisory lock). Regression
  test: `internal/revocation.TestApplyBulkWindowRateCountsOps`.

A fourth probe (atomicity / fail-open write paths) found the guards already held.

## Deploy note

The **RG3 genesis fix protects future bootstraps**. The **live poc's** control-plane certs were
minted before this change, so they have no `enrollments` row — protecting the *existing*
harbor-core/lighthouse on the live poc requires a harbor rebuild **plus a 2-row backfill** of
those certs' issued enrollments. Low urgency: the guards only fire on `harbor blocklist add` or
a reaper revoke, neither of which is active on the poc today.
