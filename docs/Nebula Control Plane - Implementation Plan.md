---
created: 2026-06-11
source: claude-chat
status: draft-v2
project: nebula-control-plane
tags: [networking, nebula, security, implementation, roadmap, go, aws]
---

# Nebula Control Plane — Implementation Plan (v2)

Companion to [[Nebula Control Plane - Design Plan]] (v3). This breaks the design into the smallest viable, independently-shippable steps. Section references like *(§4.3)* point at the design doc.

> **Revision history**
> - **v1** — initial milestone/step breakdown.
> - **Windows pass** — added cross-platform Pilot (Windows Service/MSI, DACLs, Authenticode, CI runners): steps 1.2w, 1.3, 1.3a, 1.8, 1.10–1.12, 9.1, M0.4.
> - **v2 (2026-06-11)** — independent gap pass. Added the *connective tissue and operations* the trust-spine-focused v1 missed: async enrollment delivery + internal queue (3.0a, 3.3a, 3.6a), manual approval workflow (3.9), reusable dual-control/RBAC/SSO + config & secrets + observability + device-state + audit-export (2.9–2.14), release-key custody (1.2a), renewal jitter/stampede (4.4, 9.8), version-skew (4.8), P3 chaos test (4.9), lighthouse lifecycle + underlay (0.7, 6.8), enrollment quotas (3.10), protocol spec (3.0), clock enforcement (1.13), Harbor deploy/upgrade + DB DR (9.9–9.10), and a Deferred/optional list.
> - **v3 (2026-06-12)** — **Linux-first sequencing.** Pulled all Windows/macOS work out of its per-milestone slots and consolidated it into a new final milestone **M10 (Windows + macOS parity)**. Build the whole system end-to-end on Linux (M1→M9), then circle back for cross-platform. Until M10, a Pilot step is "done" on Linux acceptance alone, with Windows behavior stubbed but compile-clean.

## How to read this

- **Steps are PR-sized** — roughly a half-day to two days each, each independently reviewable and testable.
- **Each step has a "Done when"** — a concrete acceptance check. If you can't write one, the step is too big; split it.
- **Milestones end in a demo** — a capability you can show working end to end.
- **Security lands with the feature.** Audit, the signing circuit-breaker, binary-digest checks, and least-privilege are in from their first relevant step — never a later "hardening" bolt-on.

**Sequencing strategy:** (1) a throwaway **spike** proves the riskiest unknowns — does KMS-signed Nebula cert v2 even work; (2) a **walking skeleton** gets one host on the mesh end-to-end with the thinnest possible Harbor; (3) thicken outward — lifecycle, attestation, policy, rotation, hardening. Don't build Harbor's breadth before the trust spine is proven.

**Tech baseline (from design):** Go (Harbor + Pilot, importing `github.com/slackhq/nebula/cert`), Postgres, AWS KMS (P256, cert v2), JWS/COSE for signed envelopes.

**Platform scope for Pilot — Linux-first, Windows/macOS last (decision 2026-06-12).** Build the **entire system end-to-end on Linux first** (M1→M9), then add **Windows and macOS parity as a final consolidation milestone, M10.** Rationale: prove the whole trust spine — enrollment, lifecycle, policy, rotation — on one platform before paying the per-step cross-platform tax. The target fleet is Windows-heavy, so Windows parity is *essential*, but it is sequenced **last, not per-step**. Until M10, a Pilot step is **"done" on Linux acceptance alone**; cross-platform code stays compile-clean (`GOOS=windows` builds) with Windows-specific behavior **stubbed and tracked in M10** — a Linux stub must never silently pass for the Windows implementation. **iOS/Android remain out of scope** (Nebula's own apps + MDM enrollment, design §12).

> **Deferred to M10** (pulled out of their original slots): **1.2w** (Authenticode/notarization), the **Windows half of 1.3** (DACL) and **1.3a** (DPAPI/Keychain), **1.10** (Windows Service + MSI), the **Windows/macOS half of 1.11** (CI runners), **1.12** (macOS launchd), and the **laptop OS-integration parts of 9.1** (Windows/macOS OIDC device flow). Their Linux equivalents stay in place. The step text below is left intact for provenance; treat those items as scheduled in M10.

**Must-fix before M3 code (from the v2 gap pass):** #1 async-delivery (3.0a/3.6a), reusable dual-control/RBAC (2.11), secrets + release-key custody (2.10/1.2a), and renewal jitter (4.4). The first three are architectural-cheap-now/expensive-later; jitter prevents a self-inflicted outage.

---

## Milestone 0 — Spike: de-risk the unknowns (throwaway)

Goal: prove the foundations work *before* committing to architecture. Code here is disposable; capture findings in the design doc's open-questions (§12).

> **M0 results (2026-06-11) — feasibility PASSED.** ✅ 0.1, 0.2, **0.3 (HSM/PKCS#11 CA → tunnel — the make-or-break)**, 0.5, all on a `netns` lab with **SoftHSM standing in for KMS**. Findings:
> - nebula **1.10.3 defaults to cert v2**; PKCS#11 CA signing requires **P256**.
> - Build `nebula-cert` with **`-tags pkcs11` pinned to the *installed* nebula version** — master renamed `-ip`→`-networks`, so an unpinned build breaks flag/format compat.
> - Correct HSM flow: **`keygen` the host key locally → `sign -pkcs11 <CA-uri> -in-pub <host.pub>`** (CA key stays in the module, host private key never leaves the host — validates **P1**). `sign -pkcs11` alone wrongly uses the HSM key as the *subject* key.
> - The SoftHSM CA private key is `never extractable` — the exact KMS property; the AWS KMS path is the same shape, different backend.
> - Still open: **0.4** reload semantics, **0.6** deny-path automation, **0.7** real NAT traversal. Harness: `spike/m0/`.

- **0.1** Pin a Nebula version; create a **cert v2 / P256 CA** with `nebula-cert` (`-curve P256`). *Done when:* a P256 CA + one host cert verify with `nebula-cert print`.
- **0.2** Stand up 2 nodes + 1 lighthouse by hand with those certs; confirm an encrypted tunnel + ping across the overlay. *Done when:* `nebula` on host A reaches host B's overlay IP.
- **0.3** Replace the local CA with an **AWS KMS P256 key**; sign a host cert via [`nebula-cert-kms`](https://github.com/NebulaOSS/nebula-cert-kms) (or PKCS#11). *Done when:* a KMS-signed cert is accepted and a tunnel forms — **this is the single biggest feasibility risk; prove it first.**
- **0.4** Empirically map **reload semantics** (§12 caveat): what does `SIGHUP` hot-reload (firewall rules?) vs. what needs a restart (host cert? CA bundle?), on the pinned version, **on Linux, Windows, and macOS** (Windows has no SIGHUP at all — establish its reload trigger/equivalent or confirm restart-only). *Done when:* a written per-platform matrix of change → reload-or-restart lands in the design doc.
- **0.5** Verify **blocklist is peer-enforced at handshake** (§4.7): blocklist host B's fingerprint on host A, confirm A refuses B even though B still wants to connect. *Done when:* behavior confirmed and documented.
- **0.6** Confirm Nebula **groups in cert → firewall rule** semantics: a rule referencing `group:x` admits only certs carrying that group. *Done when:* a deny + an allow both demonstrated.
- **0.7** *(new)* **Underlay networking spike**: required UDP port(s); security-group/NSG rules for public lighthouse UDP; **MTU / overlay-MTU** behavior (Nebula's classic fragmentation footgun); NAT-traversal/hole-punching across two real clouds. *Done when:* documented underlay requirements + an MTU setting that avoids fragmentation on AWS↔Azure tunnels.

> Exit gate: if any of 0.3/0.4/0.5/0.7 surprises us, revisit the design before writing production code.

---

## Milestone 1 — Walking skeleton: Pilot supervises Nebula (local only)

Goal: a real `pilot` binary that owns a Nebula process on one host. No Harbor yet; certs/config are placed manually.

- **1.1** Repo + module scaffolding; `pilot` and `harbor` as separate binaries in one module; Makefile, `golangci-lint`, unit-test CI. *Done when:* CI green on an empty `--version`.
- **1.2** **Signed-release pipeline skeleton** (cosign/sigstore) producing signed `pilot`/`nebula` artifacts. Lands now because the update channel is a top-tier trust root (§2.1) and retrofitting signing is painful. *Done when:* CI emits a signed artifact + verifiable signature.
- **1.2a** *(new)* **Release-signing key custody.** §2.1 makes this **co-equal with the CA** (worst case = fleet RCE), so it can't be a loose CI secret: KMS/HSM-backed key, **dual-control signing** (no single identity can sign a release), restricted release branch/tag, provenance (SLSA-style) attestation. *Done when:* a release cannot be signed by one person; signing identity is KMS/HSM-held and audited.
- **1.2w** **Platform-native code signing** alongside sigstore — OS execution trust ignores cosign. **Authenticode** for Windows binaries + installer (else SmartScreen/AV friction and no real Windows trust anchor); **codesign + notarization** for macOS. Provision the signing certs/identities and wire them into the release pipeline. *Done when:* Windows artifacts are Authenticode-signed and pass SmartScreen on a clean VM; macOS artifacts notarize and run without Gatekeeper prompts.
- **1.3** Pilot: config/file layout + permissions, **per-platform** — host key, cert, CA bundle, pinned Harbor pubkeys, rendered `config.yml` under a fixed dir. POSIX uses `0600`/dir `0700`; **Windows has no `chmod`** — restrict the host key via a **DACL** (owner = service account + SYSTEM, inherited ACEs removed), under `%ProgramData%`. *Done when:* `pilot init` lays out the dir with correct protection on each platform; **separate Linux and Windows tests** assert the key is unreadable by other principals.
- **1.3a** **Host-key-at-rest protection** spec + impl. The design's TPM ambition (§12) is far off, but nearer-term per-platform options exist: **Windows DPAPI/CNG** (optionally TPM-backed) to wrap the key; **macOS Keychain**; Linux kernel keyring or file perms as the floor. Pick the v1 floor and the upgrade path. *Done when:* the host key on Windows is DPAPI-wrapped at rest (not plaintext on disk); decision recorded in the design doc §12.
- **1.4** Pilot: **local Nebula keypair generation** (P256), private key never written world-readable. *Done when:* keypair generated, pubkey exportable, unit test asserts key never leaves the struct/file boundary.
- **1.5** Pilot: **nebula binary digest verification before exec** (§5). *Done when:* exec refused + logged if digest mismatches; passes when it matches.
- **1.6** Pilot: **supervise the nebula subprocess** — start, liveness, exponential-backoff restart, signal forwarding, clean shutdown. *Done when:* killing the child triggers a backed-off restart; SIGTERM to Pilot stops both cleanly.
- **1.7** Pilot: **config rendering** from a template + a local values file (placeholder for Harbor-supplied policy). *Done when:* template renders a valid `config.yml` Nebula accepts.
- **1.8** Pilot: **reload vs restart** logic per the 0.4 matrix — SIGHUP path for firewall changes (Unix), staged restart for cert changes; **Windows uses the restart path for everything** (no SIGHUP). *Done when:* on Linux a firewall-only change reloads without dropping a live ping; on Windows the same change applies via supervised restart with a bounded, measured blip; a cert change swaps with ≤ one restart on both.
- **1.9** Package Pilot as a **systemd unit** (Linux) running as a dedicated least-priv account with only `CAP_NET_ADMIN`. *Done when:* `systemctl start pilot` brings up the mesh node; no extra capabilities granted.
- **1.10** Package Pilot as a **Windows Service** — service wrapper (lifecycle, restart, graceful stop integrated with SCM), running as a dedicated **least-privilege service account** (or virtual account / gMSA), holding only the rights needed for the TUN adapter (Wintun) — *not* LocalSystem if avoidable. Ship an **MSI** (or MSIX) installer that registers the service, lays out `%ProgramData%` with the 1.3 DACLs, and installs the signed binaries. *Done when:* the MSI installs on a clean Windows Server + Windows 11 VM, the service starts the mesh node, and uninstall is clean.
- **1.11** **CI runners for Windows (and macOS)**: cross-compile + run the Linux/Windows Pilot acceptance tests (perms 1.3, supervision 1.6, reload/restart 1.8, service 1.10) on native runners. *Done when:* the Pilot test suite is green on Linux and Windows runners in CI; macOS runner stubbed for M9.
- **1.12** *(deferred to M9 with the laptop path)* macOS Pilot: **launchd** plist, Keychain-backed key (1.3a), notarized package. Tracked here so it isn't forgotten; built in M9.1.
- **1.13** *(new)* **Clock / NTP sanity on Pilot.** The whole nonce-TTL / cert-validity / attestation-freshness model assumes synced clocks (§4.3). Pilot checks local clock against a trusted source, **alerts on drift, and refuses enroll/renew beyond a hard skew threshold** (fail-closed on identity, P8). *Done when:* a host with a clock skewed past threshold refuses to enroll and emits a clear diagnostic.

> Demo: `pilot` runs as a **systemd service on Linux**, supervises Nebula with hand-placed KMS-signed certs, joins the spike mesh, and survives child crashes. *(Windows Service parity → M10.)*

**M1 progress (2026-06-12).**
- ✅ **1.1** — `pilot`/`harbor` split binaries, Makefile, `go build`/`go test` green (Linux + `GOOS=windows` cross-compile). (CI runner itself is 1.11.)
- ✅ **1.5** — `internal/binverify` SHA-256 gate, wired into `pilot supervise -sha256`; exec refused + logged on mismatch.
- ✅ **1.6** — `internal/supervisor`: start, monitor, exponential-backoff restart (resets after a stable run), clean SIGTERM→SIGKILL shutdown. Children run in their own **process group** so the whole tree dies on shutdown (fixed an orphaned-child hang). Unix/Windows split (`process_*.go`).
- ✅ **1.3 (POSIX floor)** — `internal/paths` lays out the host dir; `pilot init` creates it `0700`, host key `0600`. **Windows DACL + DPAPI-at-rest (1.3 Windows / 1.3a) remain stubbed** with explicit TODOs in `secure_windows.go` — no confidentiality claim on Windows until there's a runner to assert it (1.11).
- ✅ **1.4** — `internal/hostkey` generates the P256 key-agreement key in-process via `crypto/ecdh` (the exact primitive `nebula-cert` uses) and marshals it with Nebula's own PEM functions — byte-identical to `nebula-cert keygen -curve P256`, no bespoke crypto. Private scalar has **no exported accessor**; it only reaches an `O_EXCL` `0600` file and never clobbers a live key.
- ✅ **1.7** — `internal/nebulaconfig` renders `config.yml` from an embedded template (shape mirrors the M0-proven config); PKI paths come from the layout, policy fields from an optional values file with tight defaults (outbound open, **inbound ICMP-only** until Harbor policy lands at M6).
- ✅ **1.9 (artifacts + offline-verified)** — systemd packaging under `packaging/systemd/`: a hardened `pilot.service` (Type=exec, dedicated `nebula-pilot` account, **ambient `CAP_NET_ADMIN` only** + `CapabilityBoundingSet=CAP_NET_ADMIN` + `NoNewPrivileges`, `ProtectSystem=strict`, `DevicePolicy=closed`+`DeviceAllow=/dev/net/tun`, syscall/address-family filters), an idempotent `install.sh` (creates the user, installs binaries, lays out `/etc/nebula-control-plane` 0700, runs `pilot init`, enables the unit), `uninstall.sh`, `values.example.yml`, and a README. `systemctl reload` → SIGHUP → nebula hot-reload (ties to 1.8). **`systemd-analyze verify` passes; offline security score 1.7/"OK"** (`make systemd-verify`). *Runtime "Done when" (systemctl start brings up the node; child holds exactly CAP_NET_ADMIN) needs root on a host/VM + a signed cert — documented as a step-by-step acceptance in the packaging README; not run on the dev workstation.*
- ✅ **1.13** — clock/NTP sanity. `internal/clock` is a dependency-free SNTP (RFC 4330) client computing local-vs-reference offset; `Check` fails closed beyond a max-skew. `pilot clock-check` exits **0** (synced), **1** (skew → fail-closed), or **2** (time undeterminable) — distinct codes so the M3 enroll/renew gate can decide fail-open vs fail-closed on *unreachable* time. Hermetic unit tests (fake NTP server) + verified live against `pool.ntp.org` (offset ~0, all three exit codes). Documented as a sanity check vs gross drift, not a security-grade time source (NTS/Harbor-signed-time is the upgrade path).
- ✅ **1.8** — reload-vs-restart matrix. Resolved Nebula v1.10.3's reload semantics (design §12): SIGHUP hot-reloads firewall, lighthouse/static-host-map, punchy, logging, **and a same-IP/same-curve PKI refresh**; restart is needed only for `listen.host`/`listen.port`, `tun.dev`, or a cert IP/curve change. `internal/reconcile.Classify`/`Apply` encodes the matrix; the supervisor gained `Reload()` (SIGHUP to nebula) and `Restart()` (supervised stop+start); `pilot supervise` forwards **SIGHUP → hot-reload** (Unix), and Windows degrades reload→restart (no SIGHUP). **Proven with real nebula:** a live firewall change applied via SIGHUP with the **nebula PID unchanged** (no restart). Unit tests cover the classification, the Windows restart-fallback, real SIGHUP delivery, and a single-cycle restart.
- **Acceptance proven end-to-end:** `pilot init` → P256 CA signs the pilot-generated pubkey → **`nebula -test` accepts the rendered config with that key+cert loaded**. Automated as `internal/integration` (skips if `nebula`/`nebula-cert` absent; `make m1-smoke`).
- **Still open in M1 (Linux):** 1.2/1.2a (signed-release pipeline + key custody) — the only remaining Linux M1 work; not on the functional critical path (Pilot's digest gate 1.5 is the consumer), so it can run alongside M2. **Windows/macOS items (1.2w, 1.3-DACL, 1.3a, 1.10, 1.11-Win/mac, 1.12) are deferred to → M10.** *(Note: the "no live ping dropped" half of 1.8's acceptance needs the netns lab under sudo; the no-restart property was verified directly via stable PID. The runtime half of 1.9 needs root on a host/VM.)*

---

## Milestone 2 — Harbor Core skeleton + the signing spine

Goal: the minimum Harbor that can mint a cert safely, **plus the platform plumbing every later milestone reuses** (observability, secrets, RBAC/dual-control, device state, audit export). No network enrollment yet — drive it via an internal admin CLI.

- **2.1** Postgres + migration tooling; first tables: `keys`, `audit_log`. *Done when:* migrations apply/rollback cleanly in CI.
- **2.2** **Hash-chained audit log** primitive (§7): append-only, each row carries prev-hash; a verifier detects tampering. *Done when:* unit test proves a mutated row breaks chain verification. Land this first so every later action is auditable from day one.
- **2.3** **Signer service**: wrap KMS `Sign`/`GetPublicKey` for the CA key; assemble + sign a Nebula cert from a pubkey + template. *Done when:* Signer produces a cert identical-in-validity to the 0.3 path, logged to audit.
- **2.4** Signer **template validation** (§4.3): reject out-of-allocation IPs, disallowed groups, insane lifetimes — *before* calling KMS. *Done when:* malformed templates are refused with typed errors; tests cover each rule.
- **2.5** Signer **circuit-breaker** (§4.3): fleet-wide certs/hour ceiling; breach → halt + alarm + audit. *Done when:* exceeding the test ceiling halts signing and emits an alert event.
- **2.6** **IPAM allocator**: `devices`, `ip_allocations` tables; allocate/release with quarantine; pool config + per-cloud sub-ranges. *Done when:* concurrent allocations never collide (test with parallel requests); released IPs honor quarantine.
- **2.7** **Cross-account KMS isolation** (§6.3): Signer assumes a scoped role into the PKI account; that role can `Sign`/`GetPublicKey` only; SCP denies delete/policy-edit. *Done when:* Signer works via assumed role; a deletion attempt is denied by SCP (verified in a sandbox account).
- **2.8** Admin CLI: `harbor issue-cert` driving 2.3–2.6 end to end. *Done when:* CLI mints a cert for a fake device, IP allocated, audit row chained.
- **2.9** *(new)* **Observability baseline** — scaffold at the *start* of M2 so everything after is observable: structured logging, metrics (Prometheus), `/healthz` + `/readyz`, request tracing, and a minimal SLO doc for Harbor services; plus a `pilot diagnose` command for the "won't enroll" case. *Done when:* every Harbor service exposes health/metrics; a failed sign produces a traceable, structured error end to end.
- **2.10** *(new)* **Harbor config & secrets management.** Provision and rotate: DB DSN, KMS ARNs, the **shared gateway↔Core nonce HMAC key** (with auto-rotation, §4.8), the **gateway TLS cert**, and **service-to-service auth**. Use Secrets Manager / SSM + IAM roles; no static secrets in images. *Done when:* no secret is baked into an artifact; nonce-key rotation works with overlap; a secret rotation needs no redeploy.
- **2.11** *(new)* **Reusable dual-control + RBAC + admin SSO.** One primitive — *not* reinvented per feature — providing: admin login via **IdP SSO + MFA**, RBAC roles, and a **two-person approval** workflow reused by policy publish (6.5), bulk revoke (7.2), privileged-group grants, and CA/key rotation. *Done when:* a privileged action requires two distinct authenticated approvers; single-approver attempts are blocked and audited.
- **2.12** *(new)* **Device lifecycle state machine.** Define + enforce `pending → active → suspended → decommissioned → re-enrolling` with legal transitions, each audited. Conflict handling (5.4), revocation (M7), and re-attestation all key off this. *Done when:* illegal transitions are rejected; state changes are audited.
- **2.13** *(new)* **Durable audit export (WORM).** Ship the hash-chained log off mutable Postgres to **object-lock / WORM** storage (§7) + SIEM, continuously, with gap detection. *Done when:* tampering with or deleting Postgres rows is detectable against the immutable copy.

> Demo: `harbor issue-cert` mints a KMS-signed cert with IPAM + validation + circuit-breaker + audit — the whole trust spine — and every action is observable, the audit is exported to WORM, and a privileged CLI action requires two approvers.

**M2 progress (2026-06-12).**
- **Data layer decision:** **GORM** with a one-line dialect swap — **SQLite** (pure-Go `glebarez`, cgo-free) for minimal-footprint local dev, **Postgres** (`gorm.io/driver/postgres`) slottable for prod. `internal/store` is the single data layer; schema is owned by versioned migrations, not AutoMigrate.
- ✅ **2.1** — migrations + first tables (`keys`, `audit_log`). `internal/store/migrate` runs **gormigrate** over the GORM connection with **per-dialect SQL files** (sqlite/postgres), so up/down work on both backends. *(golang-migrate was rejected: its sqlite driver blank-imports modernc, colliding with the pure-Go GORM sqlite driver on the `"sqlite"` name.)* Timestamps are stored as integer nanoseconds for clean portability. `harbor migrate up|down`. **Acceptance:** test applies + rolls back, **and reopens a fresh connection** to prove the migration persisted to disk (guards against accidental in-memory DBs — a real bug caught during M2).
- ✅ **2.2** — hash-chained audit log. Append-only; each row's SHA-256 commits to its seq, ts, actor/action/target/details, **and the previous row's hash** (length-prefixed fields, no concatenation ambiguity). Genesis row chains from 32 zero bytes. `AppendAudit` is serialized (single logical writer; HA multi-writer needs a DB advisory lock → tracked for M9.5). `VerifyAudit` walks the chain and fails at the first hash mismatch (tamper), broken link, or seq gap (deletion/reorder). `harbor audit add|verify`. **Acceptance proven (unit + CLI):** a clean chain verifies; mutating a row makes `audit verify` fail with `hash mismatch at seq N` and exit 1; deleting a middle row is caught as a gap. *(Truncating the latest rows is only catchable against the WORM anchor — 2.13.)*
- ✅ **2.3** — Signer service. `internal/signer` assembles + signs Nebula **cert v2 / P256** leaves from a `Template` via Nebula's `TBSCertificate.SignWith` external-signing hook. Pluggable **`Backend`** (`PublicKey`/`SignDigest`→ASN.1 DER): **`SoftwareBackend`** (in-proc, tests/dev), **PKCS#11 backend** (SoftHSM/HSM; build-tagged `pkcs11`, cgo, via `crypto11`), KMS to come. `New` fails fast if the backend's public key ≠ the CA cert. Every outcome is audited (issue-cert / rejected / circuit-tripped). **Proven over real SoftHSM** (`make signer-softhsm`): a non-exportable SoftHSM key signs the CA *and* a leaf, and Nebula's `CAPool` verifies it. **Default build stays pure-Go/cgo-free** (linux+windows); PKCS#11 is opt-in via `-tags pkcs11`.
- ✅ **2.4** — template validation (design §4.3), enforced *before* the CA key is touched, with typed errors: empty name, bad P256 pubkey, no networks, **IP outside the allocation**, **group not in the allowed set**, invalid validity window, **lifetime over the policy max**, and NotAfter-after-CA. Table tests cover each; Nebula's own `checkCAConstraints` is a second layer.
- ✅ **2.5** — signing circuit-breaker. Fleet-wide certs/hour ceiling (sliding window) that **latches open** on breach (a breach is a security event, not a transient), **alarms exactly once** + audits `signing-circuit-tripped`, and refuses all further issuance until an operator `ResetBreaker()` (to be dual-controlled at 2.11). Tested: 3 issue, 4th trips, 5th still refused with no second alarm, reset re-arms.
- ✅ **2.6** — IPAM allocator. New tables `devices` + `ip_allocations` (migration 000002, both dialects). `internal/ipam` allocates the lowest free overlay IP from a `Pool` (with per-cloud **sub-ranges**, §6.3, and a reserved list); the **`UNIQUE(ip)` constraint is the collision guard** — racing allocators that pick the same address retry on `gorm.ErrDuplicatedKey` (enabled portably via `TranslateError`). `Release` honors a **quarantine TTL** (held unusable until the window passes; expired rows lazily purged), so a recycled IP can't collide with a still-valid cert. `harbor ipam allocate|release`. **Acceptance proven:** 150 concurrent allocations yield 150 distinct IPs (no collision); a quarantined IP is skipped until its window expires, then reused; pool exhaustion and unknown sub-range return typed errors. *(SQLite capped to one connection — standard single-writer practice; the UNIQUE-retry path still exercises real INSERT contention.)*
- ✅ **2.8** — `harbor issue-cert` ties 2.3–2.6 together end to end: parse the host's public key → **allocate an overlay IP (2.6)** → **sign a cert v2 leaf (2.3)** under **policy (2.4)** + **breaker (2.5)** → **chained audit (2.2)**; on a signing failure the IP is released (no leak). Added **`harbor ca-init`** (a local CA bootstrap — not the full genesis ceremony, that's 3.1) and a **persistable `SoftwareBackend`** so the **default cgo-free binary** does the whole flow with no SoftHSM (SoftHSM still available via `-backend pkcs11`); plus `signer.SelfSignCA` (reused by 3.1 later). **Acceptance proven two ways:** an automated package-level test (`internal/integration`) allocates+signs+verifies against the CA and checks the audit chain; and a CLI smoke where `pilot init` → `harbor ca-init` → `harbor issue-cert` yields a leaf that **`nebula-cert verify` accepts**, with `harbor audit verify` confirming the chain.
- **M2 functional spine complete.** Harbor can mint a validated, rate-limited, IP-allocated, audited, Nebula-verifiable cert from a host pubkey, all on a zero-setup local SQLite + software (or SoftHSM) CA.
- **Still open in M2:** 2.7 (cross-account KMS isolation — AWS/IAM work, do when we touch real KMS; KMS `Backend` lands then) and 2.9–2.13 (observability, secrets, dual-control/RBAC, device-state, WORM export).

---

## Milestone 3 — First real join: token enrollment (gateway + core)

Goal: a fresh host enrolls over the network with a one-time token and joins the mesh. This is the first true end-to-end. **Async by construction** — the gateway is credential-less and Core is mesh-only, so the flow is submit → poll → receive.

- ✅ **3.0** *(new)* **Protocol specification** — written: [[Nebula Control Plane - Protocol Spec]] (v1, repo `docs/Nebula Control Plane - Protocol Spec.md`). Covers endpoints (gateway public / Core mesh-only), `/v1` versioning + N/N-1 negotiation, **JWS (ES256) envelopes** with two roles (host-request PoP key vs. pinned config-signing bundle key), the **stateless HMAC nonce** + Core replay cache + freshness/clock rules, the **submit→ticket→poll→bundle** async flow, per-method credentials (token now; aws-sigv4/azure in M5; oidc reserved), the **issued bundle** + Pilot fail-closed verification order, a stable **error-code enum**, mesh-only **renew/heartbeat** with a typed command channel, and a §10 open-items list for the 9.7 review. M3–M5 implement against it — `internal/nonce`, `internal/wire`, and `internal/gateway` (3.2) reference its §4.3/§7 directly, so 3.0 is now fully satisfied (further M3–M5 code keeps building to it).
- ✅ **3.1** **Genesis ceremony tooling + runbook** (§3.1). `internal/genesis` + `harbor genesis` create the **two trust roots** — the CA key (certs) and the **config-signing key** (bundles, protocol §6) — and issue the **first lighthouse cert** from the lighthouse's *own* pubkey (P1 preserved); both roots recorded in `keys`, every step in the chained audit log under **two distinct operators** (a stand-in for cryptographic dual-control, 2.11). Software backend for local (keys to `ca.key`/`config-signing.key`) or `pkcs11` for HSM. Runbook: [[Nebula Control Plane - Genesis Runbook]]. **Acceptance proven:** `pilot init` → `harbor genesis` yields a lighthouse cert that `nebula-cert verify` accepts and a lighthouse config `nebula -test` accepts; keys recorded; audit chain intact (genesis-ca, genesis-config-key, issue-cert, genesis-complete). Automated as `internal/integration` `TestGenesisRun`. *(KMS backend + offline/air-gapped production ceremony land with 2.7/M8.)*
- ✅ **3.2** **Enrollment Gateway `GET /v1/nonce`**. `internal/nonce` mints/verifies the stateless `base64url(ts ‖ HMAC-SHA256(k_gw,"ncp-nonce-v1"‖ts‖binding)[:16])` per protocol §4.3 — a **keyring** (primary + previous) so `k_gw` rotates with overlap. `internal/wire` carries the shared **error model** (§7, code→status/retryable table) + response types. `internal/gateway` serves the route; **`cmd/gateway`** is a **separate, credential-less binary** (no DB/KMS imports — enforces P3) with hardened HTTP timeouts and rotation flags. **Acceptance proven:** unit tests cover mint/verify, wrong-binding/forged/expired/future-skew/malformed rejects, and rotation overlap; a live binary returns a `no-store` JSON nonce, `400 invalid_request` on missing binding, `405` on POST. *(Nonce single-use is by design enforced at Core's replay cache, 3.4.)*
- ✅ **3.3** Gateway `POST /v1/enroll`. Verifies, in order: edge **rate-limit by IP** (cheap shed) → hard **body cap** (`MaxBytesReader`, pre-parse) → JWS-envelope + payload parse → **schema/version** checks → P256 pubkey parse + **rate-limit by pubkey_hash** → **request-JWS proof of possession** (`internal/jws` ES256, `typ`/`kid` checked) → **nonce** (freshness + binding) → mint a **retrieval ticket** (enrollment_id + retrieval secret; only the secret's SHA-256 travels onward) → **publish** the vetted candidate to the queue. **No DB/KMS** (`cmd/gateway` imports neither). New reusable pieces: `internal/jws` (flattened ES256, raw R‖S per RFC 7518), `internal/ratelimit` (per-key token bucket), `internal/queue` (Candidate + `Queue` iface + in-memory impl), `internal/wire` enroll schema + `PubkeyHash`. **Acceptance proven:** httptest covers happy-path (202 + candidate queued), bad signature (401, not queued), wrong-nonce-binding (invalid_nonce), missing nonce/unknown method (invalid_request), oversized body (rejected); jws/ratelimit unit-tested.
- ✅ **3.3a** **Internal queue + gateway↔Core trust.** `queue.Durable` — a **SQLite-backed** queue in **its own store** (separate from Harbor's main DB, so the gateway gets queue-only access — least privilege, P3). Each message carries an **HMAC** over its contents (the gateway↔Core shared key) so Core **dead-letters forged/tampered messages**; the unique `enrollment_id` makes **publish idempotent** (replay-safe); **lease/ack/nack** give at-least-once with **poison handling** (dead-letter after `MaxAttempts`); a depth cap gives **backpressure** (`ErrBackpressure` → gateway returns retryable). Core consumption is **idempotent** (`Consumer.Process` returns the recorded result for a redelivered `enrollment_id`); `Consumer.Drain` claims→processes→acks terminal / nacks transient. `cmd/gateway -queue-dsn -queue-key` uses it (in-memory remains the dev default). *Acceptance proven:* a **forged message is dead-lettered, not delivered**; duplicate publish → idempotent no-op; backpressure + poison + lease-reclaim; **end-to-end** `gateway POST → durable queue → Core drain → issued cert verifies`; queue-down → publish error → enroll `retryable` (data plane untouched). *(Production swaps SQS/NATS behind `queue.Queue`; HA replay-cache is M9.5.)*
- **3.3a** *(new)* **Internal queue infrastructure + gateway↔Core trust.** Stand up the queue (e.g. SQS/NATS): authenticated publish from the gateway, Core as the only consumer, poison-message handling, backpressure, and at-least-once semantics with idempotent processing. The gateway's only privilege is *publish + read-own-result* — nothing else. *Done when:* a forged/replayed queue message is rejected by Core; queue outage degrades gracefully (enroll returns retryable, data plane unaffected).
- ✅ **3.4a** **Join keys** (§4.1c). `internal/joinkey` + migration 000003 (`join_keys`): scoped (groups, sub_range), capped (`max_uses`, atomic `ValidateAndConsume` via conditional UPDATE — concurrency-safe), expiring, revocable; **secret stored as SHA-256 only**, shown once. `harbor joinkey create|list|revoke`; `auto_issue` defaults false and the CLI prints a loud warning when set. *Done:* create/list/revoke proven; revoke + exhaust + expire + unknown-secret unit-tested.
- ✅ **3.4** Core enroll consumer. `internal/enrollment.Consumer` drains a `queue.Candidate` and, trusting the gateway for nothing: re-verifies the request JWS + nonce, enforces the **nonce replay cache** (`internal/replay`, single-use §4.3), **validates+consumes** the join key, binds the pubkey, records the enrollment. **Approval default-deny for bearer secrets:** a join-key join → **PENDING** unless the key sets `auto_issue`; `Approve()` issues a pending one (the 3.9 RBAC/dual-control wraps this primitive). On issue: IPAM-allocate → sign cert → record (IP released on a failed sign). *Acceptance proven (`internal/integration`):* default→PENDING then **approve→issued cert that verifies against the CA**; `auto_issue`→issued immediately; **replay rejected**; revoked key → denied.
- ✅ **3.5** **Group resolution from the join key** — the issued cert's groups come from the key (`signer` enforces the policy envelope), never from host-`requested_groups`. Verified by the integration test (cert carries exactly the key's groups). Immutable-fact attestation groups are M5 (5.5).
- ✅ **3.6** Core assembles the **JWS-signed config bundle** (`internal/bundle`): leaf cert + `ca_bundle` + device/groups + lighthouses, signed by the **config-signing key** (genesis root, via `jws.SignBackendES256` — converts the backend's DER to JWS R‖S, so HSM/KMS works). Written to the result store on issue (auto or approval). `bundle.Verify` is Pilot's gate. *Done:* a bundle verifies against the **pinned** config-signing pubkey (and the leaf inside verifies against the CA); wrong-key/tamper rejected.
- ✅ **3.6a** **Async result delivery.** A **result store** in the shared gateway↔Core store + gateway **`GET /v1/enroll/{id}`** poll: released **only to the holder of the retrieval secret** (wrong/unknown secret → `not_found`, no oracle), TTL-bounded, **one-time read** of an issued bundle (second read → `gone`). Statuses: `pending` (202) / `issued` (200 + bundle) / `denied`. *Acceptance proven end-to-end:* gateway `POST /enroll` → Core `Drain` issues + writes result → gateway `GET /enroll/{id}` returns a **bundle JWS that verifies against the pinned key**; second poll → 410; wrong secret → 404.
- ✅ **3.7** Pilot **enroll flow** (async-aware). `internal/enrollclient` + `pilot enroll -gateway -join-key -config-pub`: gen/load host key → fetch nonce → JWS-signed submit (PoP via `hostkey.SignDigest`) → **poll** (404/202 → keep polling; issued → done; denied → stop) → **verify the bundle against the pinned config-signing key** → verify the leaf vs the CA and that it's **bound to our key** → write `ca.crt`/`host.crt` (0644) + render `config.yml`; key stays 0600 (P1). *Acceptance proven (`internal/integration`):* with a background Core drainer, `pilot enroll` on an `auto_issue` key → **issued, files written, and `nebula -test` accepts the rendered node config**; a default (non-`auto_issue`) key → **pending, no cert written** (awaiting approval). *(The live mesh ping needs the netns lab + a running lighthouse/Core drainer — the M3 demo harness, like M0's sudo tests; the wire flow + node-config validity are proven here.)*
- ✅ **3.8 (local-first)** **E2E harness** — `spike/m3/demo.sh` / `make m3-demo`: one command spins **genesis → gateway + `harbor enroll worker` (real separate processes) → join flow** and asserts each step: auto-issue join, default-key→PENDING, `enroll approve`, **ticket resume → join**, audit-chain intact, and `nebula -test` on the enrolled config. Zero-setup (SQLite + software CA + processes), throwaway temp dirs, cleaned up on exit; stable across runs. *(The faithful Postgres + KMS + multi-VM scenario is the infra-plan variant — same binaries, different `-driver`/`-backend`/queue.)*
- **3.9** *(new)* **Manual approval workflow.** The `PENDING` path — **the default for every join-key (non-attested) enrollment** (§4.1c), plus conflicts and non-`auto_issue` flows: an admin queue to **list / approve / deny** enrollments (showing name, pubkey fingerprint, source, join-key id), approver authz via 2.11, full audit. *Done when:* a join-key enrollment waits in the queue and only issues after an authorized approval; denials are recorded.
- ✅ **3.10** **Enrollment quota enforcement** (§4.0) — **per-join-key rate** quota (the live dimension; per-account/per-instance arrive with M5 attestation). Distinct from `max_uses` (lifetime cap) and the fleet-wide signing breaker (2.5). DB-backed (durable/HA-friendly): the Consumer counts accepted (pending+issued) enrollments for the key in a sliding window and, if `quota_per_hour` would be exceeded, **denies before consuming a use**, records denied + audits `enroll-quota-exceeded` (the alert). Split `joinkey.Lookup`/`Consume` so the quota gate runs before the use is taken. `harbor joinkey create -quota N`. *Acceptance proven:* a `quota=2` key issues twice then the 3rd is denied with `ErrQuota` (blocking both auto-issue and pending), and the blocked attempt does **not** consume a use.

> Demo: bare host → `pilot enroll -join-key …` → (auto_issue key) on the mesh, pinging another node; a default join key instead **lands in the approval queue and joins only after an admin approves**. Pains **#1 (IP) and #2 (joining)** solved for the join-key path.
>
> ✅ **Live multi-process demo proven (2026-06-12):** `harbor genesis` → `gateway` + **`harbor enroll worker`** (Core) as separate processes → `pilot enroll` (auto_issue) joins (IP .2); a default key → **PENDING** → `harbor enroll pending` → `harbor enroll approve` → host **resumes its saved ticket** and joins (IP .3); audit chain intact; enrolled config passes `nebula -test`. Only the actual overlay *ping* needs the netns/root lab.

**Harbor Core CLIs (2026-06-12):** `harbor enroll worker` (durable-queue consumer loop), `harbor enroll pending` (approval queue), `harbor enroll approve <id> -approver A` (the 3.9 primitive). Pilot persists its retrieval ticket (`enroll-ticket.json`, 0600) and **resumes** after approval rather than re-enrolling.

---

## Milestone 4 — Lifecycle over the mesh: renewal & heartbeat

Goal: certs renew themselves with zero downtime; Harbor sees fleet state; the data plane survives Harbor being down. Solves pain **#3**.

- **4.1** **Core becomes a mesh node**: Core runs Pilot+nebula in `group:control-plane`; Core API bound to its overlay IP. *Done when:* an enrolled host can reach Core's API over the tunnel; the public internet cannot. *(Code: `harbor core-api` serves the mesh-only API; binding it to the overlay IP + the public-can't-reach assertion is the netns/deploy step.)*
- ✅ **4.2** **Mesh tunnel-identity auth** (§4.5). `internal/coreapi` authenticates a request by its **source overlay IP** → the current issued enrollment at that address (Nebula ties a peer's source IP to its cert, so the IP *is* the identity). *Proven:* a renew from an overlay IP with no enrolled device is **403** (`account_not_allowed`).
- ✅ **4.3** `POST /v1/certs/renew` (mesh-only). `internal/coreapi` re-signs the **same identity** (IP + name + groups from the device record) with the request's **new key** (JWS PoP, `ncp-renew+jws`), no re-attestation/IPAM, returns a config-signing-signed bundle, audits `cert-renewed`. `harbor core-api` serves it; `pilot renew` / `enrollclient.Renew` rotate the key client-side (atomic key+cert swap → SIGHUP hot-reload). *Proven (`internal/integration`):* a host renews and gets a **fresh cert with the same IP/name/groups, bound to the new key, verifying against the CA**.
- ✅ **4.4** Pilot **proactive renewal** at ~⅔ life **with randomized jitter**. `internal/renew`: `Schedule` targets ⅔ of the cert's life ± jitter (default ±7.5% of life); `Manager` reads the host cert window, waits, calls `enrollclient.Renew` (rotates key → atomic key+cert swap), then triggers the supervisor's **SIGHUP hot-reload** (same IP/curve = zero restart). `pilot supervise -core -config-pub -dir` runs the renewal loop alongside nebula. *Proven:* a **1,000-host cohort with the same window spreads across the jitter band** (not a spike), centered at ⅔ life; a past-⅔-life cert triggers an **immediate renew + reload**. *(The live "no dropped ping" over the mesh — renew while pinging — is the netns demo; the M1.8 SIGHUP-no-restart proof + same-IP/curve renewal make it zero-downtime.)*
- **4.5** **Core self-renewal local path** (§3.1): Pilot-on-Core renews via loopback to Signer, not over the mesh, scoped to Core's own identity. *Done when:* Core re-certs itself with the overlay forcibly degraded.
- **4.6** `POST /v1/heartbeat`: versions, cert expiry, applied config version, drift, clock; **typed command channel** back (renew / apply-config-N / restart) — never arbitrary exec. *Done when:* heartbeats persist; an unknown command type is rejected.
- **4.7** **Expiry/health dashboards + alerts**: "% of fleet within N days of expiry," lighthouse expiry, clock drift. *Done when:* alerts fire in a drill where renewal is blocked.
- **4.8** *(new)* **Pilot↔Harbor version compatibility.** You can't upgrade 10k Pilots atomically, so define API **versioning + skew policy** and a negotiation handshake; CI runs a **mixed-version matrix** (old Pilot ↔ new Harbor and vice-versa). *Done when:* an N-1 Pilot interoperates with current Harbor; breaking changes are gated behind version negotiation.
- **4.9** *(new)* **P3 chaos test + documented limit.** Take Harbor fully offline mid-renewal and assert the **data plane is unaffected** (existing tunnels + valid certs keep working). Document the genuine worst case — **Harbor down longer than cert lifetime** → hosts age out — with the expiry-% alert (4.7) as the control and an emergency response in the runbook. *Done when:* the chaos test passes; the limitation + response are written down.

> Demo: a host enrolled days ago silently rolls to a new cert; Harbor dashboard shows the fleet's expiry posture; killing Harbor mid-test doesn't drop a single tunnel.

---

## Milestone 5 — Cloud attestation (zero-touch cloud enrollment)

Goal: AWS/Azure VMs enroll with no token. Introduces the immutable-fact group map.

- **5.1** **AWS sigv4 attestation — Pilot side** (§6.1): build a signed `sts:GetCallerIdentity` with `X-Harbor-Nonce` + `X-Harbor-Pubkey-Hash` in the signature. *Done when:* request builds from instance role creds.
- **5.2** **AWS sigv4 — Core verify**: execute/validate the presigned request; check account + role-path allowlist; verify nonce+pubkey binding. *Done when:* a real EC2 instance auto-enrolls; a replayed/foreign request is refused.
- **5.3** **IID secondary cross-check** + `ec2:DescribeInstances` (running state, account/region — **not tags for authz**). *Done when:* enrollment requires both sigv4 and a matching live instance.
- **5.4** **One-enrollment-per-instance-id** conflict handling (§4.1): second active enrollment → alert + PENDING (3.9), never silent auto-issue. *Done when:* a rebuild scenario raises a review, not a duplicate identity.
- **5.5** **Group map from immutable facts** (§4.3a): versioned, signed, dual-control (2.11) `group_map` keyed to account/role/subscription — replaces the M3 static stub. *Done when:* groups derive only from immutable facts; a tag-based escalation attempt yields no extra groups (regression test).
- **5.6** **Azure attested data** — Pilot fetch (with nonce) + Core verify (chain to Azure CA, subscription/vmId allowlist, optional ARM check). *Done when:* a real Azure VM auto-enrolls; chain-rotation handling tested.
- **5.7** **PrivateLink / Azure Private Endpoint** enrollment paths (§4.0) so cloud VMs never touch the public gateway. *Done when:* a VM enrolls with the public gateway firewalled off from it.

> Demo: launch an EC2 instance and an Azure VM with the right role/identity → both appear on the mesh automatically, correct groups, no human step.

---

## Milestone 6 — Central firewall policy (solves pain #4)

Goal: Harbor owns the firewall; hosts can't drift; the fleet can't sever itself.

- **6.1** Policy **data model + group-based DSL** (`allow group:web → group:db tcp 5432`); default-deny baseline (§4.4). *Done when:* policy parses/validates; default is deny.
- **6.2** **Compiler**: global policy → per-host firewall section (only rules touching the host's groups). *Done when:* compiled output matches hand-written expectation for sample fleets.
- **6.3** **Compile-time invariants** (§P10): cannot publish a policy that removes reachability to `group:control-plane` or blocks lighthouse discovery. *Done when:* an invariant-violating policy is rejected at compile, regardless of approvals.
- **6.4** **JWS-signed policy/config bundles** + Pilot verification before apply. *Done when:* an unsigned/tampered bundle is refused by Pilot.
- **6.5** **Dual-control publish** workflow — *reusing the 2.11 primitive* — + audit. *Done when:* single-approver publish is blocked; two-approver succeeds and is chained in audit.
- **6.6** **Staged canary rollout + auto-rollback** (§4.4): canary wave → watch heartbeats → missing-heartbeat threshold auto-reverts + freezes → widen in waves. *Done when:* an intentionally-bad canary auto-rolls-back without operator action.
- **6.7** Pilot **drift detection + revert**: local firewall edits reverted to the signed version next sync; tamper logged. *Done when:* a manual edit is reverted and reported.
- **6.8** *(new)* **Lighthouse fleet lifecycle.** Add / replace / remove a lighthouse and **propagate the updated `static_host_map`** (and `am_lighthouse` settings) to every host via the signed config bundle, with the 6.3 invariant guaranteeing discovery is never lost mid-change. *Done when:* replacing a lighthouse updates the whole fleet with no discovery outage; a removed lighthouse stops being advertised.

> Demo: author a rule centrally, watch it canary across the fleet with auto-rollback armed, watch a hand-edit get reverted, and roll a lighthouse out of the fleet live.

---

## Milestone 7 — Revocation & offboarding

Goal: kill a host fast and safely; make revocation itself non-weaponizable.

- **7.1** **Blocklist distribution** via the signed config bundle; rely on **peer-side enforcement** (§4.7). *Done when:* blocklisting host B causes all *other* hosts to refuse B within the propagation SLO, even if B's Pilot ignores it.
- **7.2** **Revocation-as-DoS guards** (§P10/§4.7): cannot blocklist `control-plane`/lighthouses; **bulk revoke = dual-control (2.11) + rate-limited**. *Done when:* a mass-revoke needs two approvers and can't target the control plane.
- **7.3** **Decommission flow**: revoke enrollment (forces re-attest), drive device state (2.12), release IP to quarantine, auto-reap on cloud terminate events. *Done when:* a terminated EC2 instance is reaped and its IP quarantined automatically.
- **7.4** **Human-device offboarding** hook: IdP user disable → stop renewals for their devices (pairs with M9 OIDC). *Done when:* disabling a user halts their devices' renewals.

> Demo: blocklist a compromised host and watch peers drop it; attempt a reckless mass-revoke and watch the guardrails stop it.

---

## Milestone 8 — CA & key rotation (the dangerous machinery)

Goal: rotate the trust roots online, with a drill that proves it.

- **8.1** **Multi-CA trust bundle distribution**: ship `[CA1, CA2]`, confirm 100% adoption via heartbeat before any cut-over. *Done when:* every host reports trusting both before step 8.3 is allowed.
- **8.2** **CA lifecycle state machine** (`staged→active→draining→retired`); won't retire a CA with live dependents (§4.6). *Done when:* state transitions are enforced; illegal transitions rejected.
- **8.3** **Signing cut-over** to CA2 + **drain tracking** (active certs per CA) + force-renew stragglers. *Done when:* fleet migrates to CA2 and CA1 reaches zero dependents.
- **8.4** **CA1 retirement**: distrust + scheduled KMS deletion with alarms. *Done when:* `[CA2]`-only bundle deployed; deletion scheduled with deletion-alarm wired.
- **8.5** **Config-signing key rotation** by the same dual-key-overlap mechanism. *Done when:* config bundles verify across the K1→K2 overlap with no Pilot rejections.
- **8.6** **Emergency rotation path** (immediate distrust + mass re-issue). *Done when:* a simulated CA-compromise runbook completes in staging.
- **8.7** **Full rotation drill in staging** (design §13). *Done when:* a real end-to-end CA rotation runs on a staging fleet with zero data-plane outage; findings recorded.

> Demo: rotate the CA on a live staging mesh, start to finish, without dropping tunnels.

---

## Milestone 9 — Hardening, operations & assurance

Goal: production-readiness, the laptop path, and the assurance work from design §13.

- **9.1** **OIDC device-code flow** for laptops (§4.1b): device→human binding, MFA, offboarding hook — on **both Windows and macOS laptops**. Completes the **macOS Pilot (M1.12)**: launchd plist, Keychain-backed key (1.3a), notarized package; and the Windows laptop variant reuses the M1.10 service/MSI. *Done when:* a Windows laptop and a macOS laptop each enroll via browser+MFA and join the mesh; disabling the user halts both.
- **9.2** **Out-of-band admin break-glass** (§10): SSM Session Manager / bastion path into Core that doesn't ride Nebula; dual-operator + alarms. *Done when:* an admin can reach Core with the mesh fully down.
- **9.3** **Detection catalog → SIEM** (§7.1): wire each detection (group-never-held, new account, signing-rate, chain-break, double-enroll, off-window policy change, issued-vs-inventory reconciliation, KMS deletion). *Done when:* each detection fires in a drill.
- **9.4** **Posture-gated renewal** (optional): renewal conditioned on disk-encryption/patch facts. *Done when:* a non-compliant host is denied renewal in a test policy.
- **9.5** **HA Harbor**: multiple Core replicas, Postgres failover (see [[PgDog - Horizontal Scaling for PostgreSQL]] if scaling demands it), multi-region KMS keys verified. *Done when:* killing a Core replica causes no enrollment/renewal outage.
- **9.6** **Signed, waved self-update channel** for Pilot/nebula with health gates + rollback. *Done when:* a bad update is caught by the canary wave and rolled back.
- **9.7** **Assurance pass** (§13): parser fuzzing in CI, **external protocol review** (of the 3.0 spec), gateway pentest, runbook tabletops (genesis + both break-glass), detection-fires validation. *Done when:* each is completed and findings triaged.
- **9.8** *(new)* **Load & scale testing.** Simulate fleet-scale **enrollment + renewal storms** (with 4.4 jitter), verify the Signer/circuit-breaker behave, and size **KMS API rate-limit headroom** (KMS Sign throttling is an availability risk distinct from the security ceiling). *Done when:* a 10k-host renewal cohort completes within SLO without tripping the breaker or throttling KMS.
- **9.9** *(new)* **Harbor deploy / upgrade / rollback.** The control plane's own release process: blue-green or rolling Core deploys, **schema-migration/code coordination** (expand-contract), and a tested rollback. *Done when:* a Harbor version can be deployed and rolled back on a live mesh with no enrollment/renewal outage.
- **9.10** *(new)* **DB backup / restore / DR drill.** PITR + tested restore of Harbor state; regional DR for Postgres; verify the WORM audit copy (2.13) survives a primary loss. *Done when:* a restore-from-backup drill rebuilds a working Harbor; RPO/RTO recorded.

> Demo: production cutover criteria met — laptops on the mesh, break-glass proven, detections live, update channel safe, a fleet-scale renewal storm rides out cleanly, and a DB-restore drill passes.

---

## Milestone 10 — Windows + macOS parity (circle back)

Goal: bring the non-Linux platforms up to the parity the Linux build already has. Everything here was deliberately deferred (see *Platform scope*) so the trust spine could be proven end-to-end on Linux first. By M10 the protocol (3.0), enrollment, lifecycle, policy, and rotation are settled — **this milestone is OS integration, not new control-plane design.** Each step revisits a stub the Linux build left behind.

- **10.1 — host-key-at-rest + file protection** *(was 1.3 Windows / 1.3a)*. Replace the `secure_windows.go` stub with a real **DACL** (owner = service account + SYSTEM, inherited ACEs removed) under `%ProgramData%`, and **DPAPI/CNG**-wrap the host key at rest (optionally TPM-backed); **macOS Keychain** for the laptop path. *Done when:* per-OS tests assert the host key is unreadable by other principals and is not plaintext on disk.
- **10.2 — Windows Service + installer** *(was 1.10)*. Service wrapper (SCM lifecycle, graceful stop) under a least-privilege account (virtual account / gMSA, **not** LocalSystem), holding only the Wintun rights it needs; ship an **MSI/MSIX** that registers the service, lays out `%ProgramData%` with the 10.1 DACLs, and installs signed binaries. *Done when:* the MSI installs on clean Windows Server + Windows 11 VMs, the service joins the mesh, uninstall is clean.
- **10.3 — Windows reload→restart validation** *(was 1.8 Windows half)*. The `internal/reconcile` matrix already degrades reload→supervised-restart where SIGHUP is absent; validate the bounded, measured blip on a real Windows node. *Done when:* a firewall-only change applies via supervised restart with a measured, bounded interruption; a cert swap is ≤ one restart.
- **10.4 — platform-native code signing** *(was 1.2w)*. **Authenticode** for Windows binaries + installer (clean SmartScreen on a fresh VM); **codesign + notarization** for macOS. Wire into the (Linux-built) release pipeline from 1.2. *Done when:* Windows artifacts are Authenticode-signed and pass SmartScreen; macOS artifacts notarize and run without Gatekeeper prompts.
- **10.5 — Windows + macOS CI runners** *(was 1.11 Win/mac half)*. Cross-compile and run the Pilot acceptance suite (perms 10.1, supervision, reload/restart 10.3, service 10.2) on native runners. *Done when:* the suite is green on Windows and macOS runners.
- **10.6 — macOS Pilot** *(was 1.12)*. launchd plist, Keychain-backed key (10.1), notarized package. *Done when:* `launchctl` brings up the mesh node on macOS.
- **10.7 — laptop OIDC on Windows/macOS** *(was the OS-integration parts of 9.1)*. The device→human binding, MFA, and offboarding hook from 9.1, now on real Windows/macOS laptops using 10.2/10.6 packaging. *Done when:* a Windows laptop and a macOS laptop each enroll via browser+MFA and join; disabling the user halts both.

> Demo: a Windows Server, a Windows 11 laptop, and a macOS laptop install the signed MSI/pkg, enroll, join the mesh, hot-apply policy via supervised restart, and renew — full parity with the Linux fleet.

---

## Cross-cutting (every milestone, not a phase)

- **Audit everything** from M2.2 onward — no action ships without an audit row, and it's exported to WORM (2.13).
- **Least privilege** for every new service/role at creation, not later.
- **Observability with the feature** — every new service/endpoint ships logs, metrics, and health from day one (2.9).
- **Tests as acceptance** — a step isn't done without its "Done when" automated where feasible.
- **No bespoke crypto** (§P11) — reach for sigv4/JWS/COSE/HKDF; flag any custom construct for the 9.7 review; build to the 3.0 spec.
- **Linux-first, Windows/macOS at M10** — until the M10 parity milestone, Pilot steps are accepted on **Linux alone**; keep cross-platform code compile-clean (`GOOS=windows`) with Windows behavior **stubbed**. Don't let a Linux stub silently become the Windows implementation — M10 must revisit every stub. Windows is still the majority of the fleet; it is sequenced last, not dropped.
- **Never assume atomic fleet upgrades** — mixed Pilot/Harbor versions coexist; honor the 4.8 compatibility policy.
- **Reuse the primitives** — dual-control/RBAC (2.11), device state (2.12), audit (2.2) are built once and reused, not re-implemented per feature.
- **Update the design doc** when a spike (M0) or reality contradicts an assumption.

## Deferred / optional (track, decide later)

- **Overlay DNS/naming** — Nebula's `lighthouse.dns` for name→overlay-IP resolution, if services need names not IPs.
- **Brownfield migration** — importing an existing Nebula mesh (and cert-v1→v2 migration, §12) into Harbor management.
- **Environment isolation** — staging vs prod as fully separate trust domains (separate CAs, KMS keys, meshes, Harbor instances) — likely a *should*, confirm.
- **Data residency** — where Harbor state (device records, audit) lives relative to the deployment's approved region set.

## Suggested first slice (if you want a concrete start)

M0.1 → M0.2 → **M0.3 (KMS-signed cert tunnel — the make-or-break feasibility test)** → M0.7 (underlay/MTU). Everything downstream assumes 0.3 works; prove it in week one before writing a line of Harbor. Then write the **3.0 protocol spec** before M3 code, and stand up the **2.9–2.11** plumbing before piling features on Harbor.
