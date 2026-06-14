---
title: "ADR 0008 — Client Install & Bootstrap"
created: 2026-06-14
status: accepted
tags: [nebula, adr, pilot, install, bootstrap, enrollment, multi-mesh, trust, supply-chain, systemd]
---

# ADR 0008 — Client Install & Bootstrap

**Status:** Accepted (direction; phased — systemd v1, multi-mesh designed-in)
**Date:** 2026-06-14
**Decision owners:** Chris Hyde (+ a future second approver, per dual-control)

## Context

Joining a host to the mesh today is a sequence of manual steps: install nebula, drop the
`pilot` binary, then run `pilot init` → `pilot enroll` → `pilot supervise` — and the
"service" is an ad-hoc `systemd-run` transient unit (see `deploy/scripts/bootstrap-genesis.sh`)
that doesn't survive a reboot as a real unit. There is **no install command**.

The goal: **drop one binary, run one command, done.** No package, no big install script, no
Ansible. The command checks the host for an existing install; if absent it does all the
service setup, then triggers enrollment; if present it's a no-op / status. This is the
**cold-start on-ramp** to **ADR 0003**'s steady state (single binary via `go:embed` nebula,
Harbor-distributed nebula versions, pilot self-update by re-exec/re-adopt). Together they
get a host as close to **zero-management** as possible.

The encouraging finding (consistent with the other ADRs): **most of the machinery already
exists.** `pilot` already has `init` (lay out the host dir + host key + config), `enroll`
(nonce → signed submit → poll → verify the bundle against the config-signing pin → write
files), `clock-check` (fail-closed clock-skew guard), and `supervise` (run nebula, restart
with backoff, SIGHUP hot-reload, digest check). So `install` is mostly **orchestration of
existing subcommands + one genuinely new primitive: a service installer** — plus the trust
and multi-mesh design below.

## Decision

**A single idempotent `pilot install` that pins an org trust anchor, fetches an
org-signed meshinfo from the gateway, enrolls, writes a persistent systemd service, and
hands off to `supervise` — per-mesh, additive, from a universal signed binary.**

- **Input = a console-generated, org-signed meshinfo artifact (token).** The **admin console**
  (mesh-only, authenticated) mints + signs the artifact and the admin distributes it; it
  carries only `{mesh id, config-signing pin, gateway enroll URL, accepted auth methods}`,
  **signed by an org-root key**. There is **no public `/v1/meshinfo` on the gateway** — the
  gateway stays enroll-only, so nothing pre-auth leaks the mesh's topology.
- **Trust anchor = an org-root key, pinned at install on a *universal* binary.** The org
  root's public half is a **pinned trust bundle** on the host (established once, on first
  install); its private half lives in **KMS** (ADR 0007) and the **admin console** uses it
  to sign meshinfo ("Generate installer"). The binary is **not customized per org** — the
  anchor is install-time data, not a compile-time embed (see the OS-signing rationale).
- **Per-mesh and additive.** Install once per mesh; each mesh gets its own namespace
  (state dir, nebula instance, `pilot@<mesh>` service). One pinned org root federates all of
  the org's meshes. Single-mesh is the common path; multi-mesh (a bridge host spanning, e.g.,
  dev + prod for Artifactory/GitLab GitOps) is designed in now.
- **systemd (Linux) + launchd (macOS).** pilot writes + enables the service itself (no external
  script): a systemd template unit on Linux, a per-mesh LaunchDaemon plist on macOS. Windows SCM
  is the remaining stub behind the same interface.
- **Hand off to ADR 0003.** After the first heartbeat, `supervise` + self-update take over.

## The trust model (the crux)

The config-signing **pin** is the client's root of trust: whoever controls it can feed the
host a malicious bundle and enroll it into an attacker-controlled "mesh." The risk is the
**first contact** only (after enroll the host holds the real CA + pin and verifies every
later bundle). So trust must be established from something the attacker can't forge.

**Chosen: an org-root key signs the meshinfo; the host pins the org root once.**

```
Admin console ──sign meshinfo (org key, KMS)──▶  org-signed meshinfo  (public; any channel)
pilot (universal binary) ──pin org root once (fingerprint-confirm)──▶  verifies meshinfo
                                                                   └▶ trusts the per-mesh pin
                                                                      └▶ enroll; verify bundle
```

Why this shape:

- **The meshinfo is not a secret.** It's public keys + a URL + an org signature, so it's
  freely distributable (email, CI var, MDM, paste, QR). Its integrity rides the **signature**,
  not the channel — a hostile channel can't tamper with it. Leaking it costs nothing:
  possessing it only lets someone *attempt* enrollment, which still hits the **auth gate**.
- **Minimal pre-auth disclosure; the console is the mint point.** The artifact is *generated
  and served by the admin console* (mesh-only, authenticated), then handed to the host — it is
  **not** exposed by a public gateway endpoint, so a scanner hitting the public edge learns
  nothing new. It carries only low-sensitivity fields (a public pin, the mesh id, the enroll
  URL, the auth methods); the **sensitive topology — overlay CIDR + group policy — is never
  pre-auth.** Those already arrive in the **post-enrollment signed bundle**, disclosed only
  after the host authenticates and is admitted. (A brand-new host can't reach the mesh-only
  console itself — the admin downloads the artifact from the console and distributes it.)
- **Auth is the separate, revocable gate.** aws-sigv4 / SSO / a join key actually decides
  admission — and is revocable (revoke the key, untrust the role) independently of the
  meshinfo.
- **One org root federates every mesh.** The per-mesh config-signing pin is *delivered via*
  the org-signed meshinfo, not pinned on the client — so a multi-mesh host trusts N meshes
  through **one** pinned org root. (This **refines ADR 0003**, which pinned the per-mesh
  config-signing key *in* pilot; the multi-mesh-correct anchor is the org root.)
- **Pin, don't embed → universal binary.** The org root is pinned at install rather than
  compiled in, so the binary stays **universal** — see below.

### Pin vs. embed, and OS code-signing

Embedding the org key at build time means a **per-org binary**, and on macOS (Gatekeeper /
notarization) and Windows (Authenticode) each distinct binary must be **separately
signed** — a signing pipeline per org. Pinning the anchor as install-time data keeps **one
universal binary** that is signed/notarized **once per platform**. (Linux/systemd — the v1
target — enforces neither, so v1 is unaffected either way; we design for pin now so adding
macOS/Windows later is "sign the one binary," not "un-bake the key.")

| Anchor delivery | Binary | OS code-signing | Trust established |
|---|---|---|---|
| Compile-time embed | per-org (custom) | **per-org** pipeline | none at install |
| **Pinned at install (chosen)** | **universal** | **sign once** / platform | one-time per-host pin (fingerprint-confirm) |
| Vendor-root chain | universal | sign once | none at install — *but needs a central CA; N/A for self-hosted* |

Establishing the pin: **fingerprint-confirm** (SSH-known-hosts model — operator eyeballs the
org-key fingerprint once) is the default; a **pre-shared trust file** (golden image / MDM) is
the hardened, hands-free option; pure-TOFU is acceptable only behind the HTTPS gateway for
low-security meshes. (Pragmatic aside: a curl/scp-delivered CLI typically escapes the
Gatekeeper/SmartScreen quarantine xattr, so an unsigned CLI often runs when not
browser-downloaded — real today, fragile long-term; signing the one universal binary is the
durable answer.)

### Org-root key lifecycle (management burden)

The org root is a **long-lived trust anchor** (years, like a root CA), **not** a per-deploy
artifact:

- **Private half** in KMS, used *only* when an admin generates an installer (rare,
  human-paced). KMS keys don't expire; least-priv IAM grants `kms:Sign` + `GetPublicKey` only.
- **Public half** pinned once per host (a **trust *bundle***, not a single key — so rotation
  can overlap), reused across every pilot self-update — a routine deploy never touches it.
- The keys that rotate *often* (CA, per-mesh config-signing) are **not** on clients — they
  ride the org-signed meshinfo, so rotating them needs **no client redeployment** (re-sign a
  fresh meshinfo).
- **Rotating the org root** (rare; compromise/policy) is graceful by design: ship a pilot
  release whose pinned bundle trusts {old, new} (with a `kid` on meshinfo to disambiguate),
  let the fleet **self-update** (ADR 0003, canary + auto-rollback), switch the console to the
  new key, drain the old — a once-in-years event that rides the self-update channel, no
  flag day, no host hand-touched.
- **Installer artifacts** carry a short **TTL** (a stale/leaked installer config expires
  quickly) — distinct from the key's long lifetime.

## Multi-mesh model

A bridge host runs **N nebula instances**, one per mesh — each its own TUN device, UDP port,
CA/cert/config, and overlay IP. Install is therefore **per-mesh, additive, namespaced**:

- **Namespacing:** per-mesh state dir (e.g. `/var/lib/pilot/<mesh-id>/`) + a templated
  **`pilot@<mesh>.service`**. `pilot install <dev-url>` then `pilot install <prod-url>` — each
  lands in its own namespace; re-running one is an idempotent update.
- **Collision guards** — three things must differ across the meshes a host joins:
  - **TUN device name + listen port — IMPLEMENTED, Harbor-side.** For enrolled hosts the
    config is rendered from Harbor's **signed bundle** (pilot's `enroll` writes it and drift
    control reverts local edits), so these are **mesh-wide bundle fields**, not pilot-local.
    Each mesh's Harbor is run with `-tun-dev <name> -listen-port <port>` (default
    `nebula1`/`4242`); the value rides every issued/renew/`/v1/config` bundle
    (`bundle.Bundle.TunDev`/`ListenPort` → `RenderNebulaConfig`, the choke point shared by
    enroll/renew/drift, so they stay byte-identical). Empty/zero falls back to the renderer's
    `nebula1`/`4242` (legacy/single-mesh bundles unaffected). So a host on dev+prod gets, e.g.,
    `nebula-dev`/`4242` and `nebula-prod`/`4243` — no collision. *(pilot's local renderer still
    governs standalone/pre-enroll configs like a lighthouse, via `pilotsetup`/`pilot init`.)*
  - **Disjoint overlay CIDRs** — a deployment constraint: each mesh's Harbor uses a distinct
    `-pool` (dev `10.44/16`, prod `10.45/16`); overlapping pools would make a bridge host's
    routes ambiguous (out of scope — no policy routing). A host-side overlap **warning** in
    `install` (compare the enrolled cert's networks against other installed meshes') is a small
    best-effort follow-up, not a functional blocker.
  - **State dir + service** — `install`-owned and already collision-free (`/var/lib/pilot/<mesh>`
    + `pilot@<mesh>`).
- **Per-mesh identity, one shared anchor:** each mesh has its own CA + config-signing pin
  (delivered via its org-signed meshinfo); the **one pinned org root** trusts them all.
- **Service model: N templated services** (independent lifecycle / self-update / failure
  isolation) over one-pilot-many-meshes — the supervise path stays unchanged per instance.

## The command in detail

`pilot install <token>` `[-join-key …] [-name …] [-groups …] [-mesh <id>]` — where `<token>`
is the console-generated, org-signed meshinfo artifact (a string or a file path):

1. **Pre-flight:** `clock-check` (fail-closed on skew — identity ops need a sane clock).
2. **Pin the org root** (first install only): fetch the org pubkey, fingerprint-confirm (or
   read a pre-shared trust file); add to the host's trust bundle.
3. **Verify the install artifact** (the console-generated org-signed meshinfo, passed to
   `install`) against the pinned org root → learn the mesh id, the config-signing pin, the
   gateway enroll URL, and accepted auth. (Overlay CIDR + groups are **not** here — they come
   post-auth in the enrollment bundle.)
4. **Detect state** for this mesh id: *fresh* → continue; *key-but-no-cert* → resume at
   enroll; *fully installed* → no-op / `status`. `init` never overwrites an existing host key.
5. **Set up the namespace:** state dir, render config, `init` the host key.
6. **Enroll:** the existing `enroll` flow (auth per meshinfo), verifying the bundle against
   the per-mesh config-signing pin.
7. **Install + enable the service:** pilot writes `pilot@<mesh>.service` (ExecStart =
   `pilot supervise …` for this mesh) and enables/starts it. The service is **keep-alive
   only** — pilot self-updates in place via re-exec (ADR 0003), so the service is never the
   thing that restarts pilot on update.
8. **Hand off:** `supervise` runs; the first heartbeat lands; ADR 0003 takes over.

Lifecycle siblings: `pilot status` (installed? enrolled? healthy? per mesh), `pilot uninstall`
(remove the service; optionally shred the identity). Privileges: **root** (TUN/CAP_NET_ADMIN
+ writing the unit); a `setcap` + dedicated-user hardening variant is noted, not the default.

## Considered options

| Decision | Options | Verdict |
|---|---|---|
| **Bootstrap input** | **console-generated signed artifact** · explicit flags · public gateway endpoint | **Console artifact** — minted/served by the (authenticated) console, distributed by the admin; flags = the underlying mechanism; a **public endpoint is rejected** (it leaks topology pre-auth). |
| **Anchor delivery** | compile-time embed · **pin at install** · vendor-root chain | **Pin at install** — universal binary, sign once per platform; embed forces per-org signing; vendor-chain needs a central CA we don't have. |
| **Pin establishment** | pure TOFU · **fingerprint-confirm** · pre-shared (MDM) | **Fingerprint-confirm** default; pre-shared for hands-free/hardened; pure-TOFU only behind HTTPS for low-security. |
| **Multi-mesh service** | **N templated `pilot@<mesh>`** · one pilot, many meshes | **N services** — independent lifecycle/self-update/isolation; supervise unchanged. |
| **Service install** | **pilot writes the unit** · external script/Ansible | **pilot writes it** — the whole point is no script/package/Ansible. |
| **Platforms** | systemd · **systemd + launchd** · +Windows SCM | **systemd (Linux) + launchd (macOS)** done behind one interface (`service_linux.go`/`service_darwin.go`); Windows SCM is the remaining `service_other.go` stub. |

## Phased plan

- **Phase 1 — `pilot install` (single-mesh, systemd).** Orchestrate clock-check → init →
  enroll → write+enable `pilot@<mesh>.service` → supervise; idempotent detection; `status` +
  `uninstall`. Per-mesh namespacing in the on-disk layout from the start (even though only one
  mesh is exercised).
- **Phase 2 — org-signed meshinfo + trust pinning.** The **console** "Generate installer"
  mints + serves the org-signed artifact (signs with the org KMS key) — no public gateway
  endpoint; pilot pins the org root (bundle + fingerprint-confirm) and verifies the artifact;
  the per-mesh pin comes from the artifact (supersede ADR 0003's in-pilot pin); topology +
  groups stay in the post-auth bundle. Add the org-root KMS key + IAM to `deploy/prod` (ADR 0007).
- **Phase 3 — multi-mesh.** ✅ The tun/port collision guard is **done** (mesh-wide
  `-tun-dev`/`-listen-port` on Harbor → every bundle, default `nebula1`/`4242`). Remaining:
  exercise additive `pilot install` for a 2nd mesh end-to-end, the best-effort disjoint-CIDR
  warning, and (with Phase 2) one org root federating N meshes.
- **Phase 4 — cross-platform.** ✅ **launchd (macOS)** done — `service_darwin.go` renders a
  per-mesh LaunchDaemon plist + drives `launchctl bootstrap/bootout/kickstart`
  (cross-compile-verified `GOOS=darwin`; not yet run on a Mac). Remaining: **Windows SCM**
  (still the `service_other.go` stub) and sign/notarize the universal binary per platform.

## Consequences

- **+** One universal, signed-once binary + one idempotent command = the "drop a binary"
  goal, and a clean on-ramp to ADR 0003's zero-management steady state.
- **+** Trust is anchored without per-org binaries: one pinned org root, established once,
  federates all meshes; the often-rotated keys stay off the clients.
- **+** Multi-mesh (bridge hosts) is first-class, not a bolt-on.
- **+** Almost entirely orchestration of existing `pilot` subcommands; the genuinely new code
  is the service installer, the per-mesh namespacing, the org-root pin/verify, and the console
  "Generate installer" action (mint + serve the signed artifact). The public gateway is
  untouched.
- **−** A one-time per-host trust step (the org-root pin) — mitigated by fingerprint-confirm /
  pre-shared trust files; not blind TOFU.
- **−** A new long-lived key to custody (the org root) — but in KMS, rarely used, rotated
  rarely and gracefully via the self-update channel.
- **−** Multi-mesh adds per-instance resource use (N nebula + N services) and the
  disjoint-CIDR constraint.
- **−** Cross-platform (Phase 4) means real per-platform service code + notarization/signing
  of the universal binary.

## Open questions to resolve before building

1. **Meshinfo format + signature envelope** — JWS reusing the config-signing `kid` pattern?
   Lock the **minimal** field set (pin + mesh id + enroll URL + auth methods only); confirm
   the console generation/download UX (the admin mints + distributes the artifact) and that
   topology/groups stay in the post-auth bundle. *(The "public gateway endpoint" option is
   rejected — resolved.)*
2. **Token envelope** — is the packed token just base64(JSON of url+join-key+pin), and does it
   carry its own org signature, or only wrap the (already-signed) meshinfo?
3. **Mesh identity** — is `<mesh-id>` the CA fingerprint, a console-assigned name, or both?
   It namespaces the state dir + the `pilot@` unit, so it must be stable + collision-free.
4. **Pre-shared trust files** — format + discovery path for the hands-free (MDM/golden-image)
   pin so fingerprint-confirm can be skipped non-interactively.
5. **Uninstall semantics** — shred identity by default or retain for re-enroll? Per-mesh vs
   all-meshes.
6. **Re-enroll / rotate-on-host** — when a host's cert is revoked or expires past renewal,
   does `install` detect + re-enroll, and how does that interact with ADR 0003's renew loop?

## Relationship to other work

- **ADR 0003 (self-update & distribution)** — the steady state this on-ramps to; `install`
  ends by handing off to `supervise`. **Refines** 0003's "config-signing key pinned in pilot"
  → the **org root** is what's pinned (multi-mesh-correct); the per-mesh pin rides meshinfo.
- **ADR 0005 (pull-based gateways)** — the gateway is **unchanged** (enroll-only:
  `/v1/nonce`, `/v1/enroll`, `/v1/enroll/{id}`). Meshinfo is generated + served by the
  **admin console**, *not* the public gateway, so pre-auth disclosure at the edge stays
  minimal (no overlay CIDR / group taxonomy exposed to the internet).
- **ADR 0007 (production deploy)** — the org-root key is a KMS `signer.Backend` key
  (reuses that work); the console signs meshinfo with it; `deploy/prod` provisions it.
- **ADR 0004 (SSO-driven user enrollment)** — `install`'s auth-method indirection (meshinfo's
  "accepted auth") is where an SSO enrollment method plugs in.
- **`pilot` subcommands** — `install` orchestrates the existing `init`/`enroll`/`clock-check`/
  `supervise`; the new primitive is the service installer (`pilotservice`) — systemd + launchd
  behind one interface, Windows SCM still a stub.
