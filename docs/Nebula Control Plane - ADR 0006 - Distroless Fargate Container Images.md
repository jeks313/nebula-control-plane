---
title: "ADR 0006 — Distroless Container Images for the Fargate Gateway & Lighthouse"
created: 2026-06-14
status: accepted
tags: [nebula, adr, fargate, containers, distroless, supply-chain, security, maintenance, deploy]
---

# ADR 0006 — Distroless Container Images for the Fargate Gateway & Lighthouse

**Status:** Accepted
**Status (2026-06-18):** SHIPPED & LIVE — Phases 1 + 2 (gateway + lighthouse distroless) are deployed on the poc/prod stack; both Fargate runtimes are now the terraform DEFAULT. Phase 3 (supply-chain hardening: digest pins / IMMUTABLE / lifecycle policy / platform_version) is the only PLANNED remainder.
**Date:** 2026-06-14
**Decision owners:** Chris Hyde

## Context

ADR 0005 moved the enrollment gateway off-mesh. The live-apply work (2026-06-14) then
made both the **gateway** and — initially as a spike — the **lighthouse** runnable as serverless
**Fargate** containers (`gateway_runtime` / `lighthouse_runtime = "fargate"`,
`deploy/fargate/`), proven end-to-end on real AWS. *(Update 2026-06-18: Fargate is now the
terraform **default** for both the gateway and the lighthouse — no longer a spike — and the
client-IP-preserving UDP NLB in front of the lighthouse is validated live; the distroless
images below run in the live poc/prod stack.)*

Both images today are **`alpine:3.20`** + a single static binary + a **`/bin/sh`
entrypoint**:

- **gateway** — `Dockerfile`: the static, CGO-free `cmd/gateway` binary + `entrypoint.sh`,
  which materializes the Secrets-Manager-injected env (`HMAC_KEY_B64`, `COLLECT_CERT_PEM`,
  …) into `/tmp` files, then `exec`s the gateway with `-hmac-key <file>` etc.
- **lighthouse** — `nebula.Dockerfile`: the pinned, sha-verified upstream
  `nebula-linux-amd64` binary + `nebula-entrypoint.sh`, which writes the injected
  `ca/cert/key` and **renders a `tun.disabled` `config.yml`** from a heredoc, then `exec`s
  nebula.

Both payloads are **static, CGO-free Go binaries** with no libc/distro dependency — they
run on an empty image. Alpine is therefore providing only two things: **a shell** (for the
entrypoints) and **`ca-certificates`**. For that we carry busybox, musl, apk, and the CA
bundle — all CVE-tracked, all of which force an image rebuild-and-redeploy to patch.

The maintenance framing makes the cost concrete: on Fargate there is **no host to patch**;
the only thing we maintain is the image. Every package in the base is something we must
rebuild to patch. The gateway, per ADR 0005, also **initiates nothing** and authenticates
collect mTLS by **leaf pin** (not system roots), so it almost certainly needs no CA bundle
at all; nebula authenticates against the **mesh CA in its config**, not system roots. So
the base is nearly pure overhead.

## Decision

**Move both Fargate images to a distroless, shell-less, nonroot base
(`gcr.io/distroless/static-debian12`, pinned by digest) and remove the shell entrypoints —
including the extra work to do this for the lighthouse.**

Distroless `static` is purpose-built for static binaries: it ships `ca-certificates`,
`/etc/passwd` (a `nonroot` user) and tzdata, but **no shell and no package manager**. The
static Go gateway and the static nebula binary both run on it directly.

We choose **distroless over `scratch` deliberately.** `scratch` is ~2 MB smaller and has
literally zero OS surface, but it hands us CA roots, a nonroot uid, `/tmp`, and tzdata to
manage by hand — and the lighthouse needs a shell-replacement shim either way. Distroless
gives those essentials for free while still being shell-less, so the security and
maintenance win (no OS packages, no shell) is the same without the papercuts. If we're
going distroless, go distroless — including the lighthouse, where it costs a little more.

Removing the shell entrypoints is the real work:

- **Gateway** — teach `cmd/gateway` to read its key/cert material directly from
  **environment variables** (the same Secrets-Manager values ECS injects today), instead
  of only `-flag <file>` paths; have it create its own ephemeral queue dir. The container
  then runs the **bare binary** as `ENTRYPOINT` — no `sh` to materialize files. (This is
  the "native env-var config path" already flagged as a clean follow-up in the Fargate
  README.)
- **Lighthouse** — nebula is a third-party binary we cannot teach to read env, and its
  entrypoint also *renders a config file*. So add a tiny **static Go boot shim**
  (`cmd/nebula-boot`): read the injected `ca/cert/key` + ports from env, write the cert
  files and render the `tun.disabled` lighthouse `config.yml` to a tmpdir, then
  `syscall.Exec` `/usr/local/bin/nebula -config …`. The shim + nebula both live in the
  distroless image; `ENTRYPOINT` is the shim. **This is the "extra work" — accepted,
  because a shell-less, OS-package-free lighthouse is worth it.**

## Considered options

| Base | Verdict | One-line |
|---|---|---|
| **alpine:3.20 + sh entrypoint (current)** | Replace | Tiny, but carries busybox/musl/apk/ca-certs (all CVE-tracked) + a shell, purely to materialize config — a standing rebuild-to-patch cost for no payload benefit. |
| **scratch** | Rejected | Smallest, zero OS surface — but we'd hand-manage CA roots, nonroot uid, `/tmp`, tzdata, and the lighthouse still needs a shim anyway. The papercuts aren't worth the ~2 MB. |
| **gcr.io/distroless/static-debian12** | **Chosen** | Shell-less + package-manager-less (same OS-CVE win as scratch) but ships ca-certs + a nonroot user + tzdata. Fits static Go binaries; ~2 MB over scratch. |

## Work

Phased. The image-hardening items previously tracked as standalone todos (#21–#25) are
folded in here as **Phase 3** — they are all "harden the Fargate image supply chain" and
belong with this decision.

**Implementation note (done; LIVE 2026-06-18):** Phases 1 + 2 landed in the **production** tree
(`deploy/prod/fargate/`) and are deployed on the live poc/prod stack — that tree IS the prod
stack — not the demo `deploy/fargate/`, which keeps its alpine + shell entrypoints for fast
iteration. The shared
binaries (`cmd/gateway`'s env-var config, the new `cmd/nebula-boot`) are backward-compatible,
so the demo tree's alpine + shell entrypoints keep working unchanged. The base uses the
`:nonroot` tag (uid 65532); `@sha256` digest-pinning is Phase 3 below.

- ✅ **Phase 1 — gateway → distroless (DONE).** `cmd/gateway` reads its material (HMAC + queue
  keys, collect cert/key, Harbor client cert) from `$NCP_GW_*` env, env-first with the
  `-flag <file>` paths kept as a fallback; operational flags arrive via the ECS `command`.
  `deploy/prod/fargate/Dockerfile`: `FROM gcr.io/distroless/static-debian12:nonroot`,
  `COPY gateway /gateway`, bare-binary `ENTRYPOINT`. `entrypoint.sh` deleted. The durable
  queue lives on `/tmp` (distroless ships a writable `/tmp`); the ACME cert cache is the
  EFS mount (ADR 0007 Phase 5), writable via the EFS access point's enforced uid 65532.
- ✅ **Phase 2 — lighthouse → distroless (DONE).** New static `cmd/nebula-boot` (`CGO_ENABLED=0`):
  reads `$NCP_LH_*` → writes cert files + renders the `tun.disabled` `config.yml` → `syscall.Exec`
  nebula. `nebula.Dockerfile` is distroless:nonroot (fetch stage stays alpine for curl/tar +
  sha-verify), carrying nebula + the shim; bare-shim `ENTRYPOINT`. `nebula-entrypoint.sh`
  deleted. Both bind only high ports (UDP 4242 + the TCP stats port) — no privilege without a TUN.
- **Phase 3 — supply-chain hardening** (PLANNED, not yet started — folds in former todos #21–#25;
  the live state as of 2026-06-18 is `:latest` tags, `MUTABLE` ECR repos, no lifecycle policy,
  no `platform_version` pin, and both Dockerfiles still carry `TODO (ADR 0006 Phase 3)` base-pin
  comments):
  - Pin both images by **digest** and set the ECR repos `image_tag_mutability = "IMMUTABLE"`
    (reproducibility + rollback vs today's `:latest` / `MUTABLE`). *(was #21)*
  - Add an **ECR lifecycle policy** to each repo (expire untagged / keep last K). *(was #22)*
  - **Digest-pin the distroless base** in both Dockerfiles — reproducible builds; bump the
    digest deliberately when refreshing the base. *(replaces the alpine-pin item #24)*
  - **Pin the ECS `platform_version`** on both services (optional; LATEST auto-patches
    today). *(was #23)*
  - Document the **rebuild/redeploy cadence** in `deploy/prod/fargate/README.md` — now much
    lighter: rebuild only on a Go-stdlib (gateway) or nebula (bump `NEBULA_VERSION` +
    `NEBULA_SHA256`) advisory, **not** on every Alpine CVE; review ECR scan-on-push
    findings; `build-push.sh <component> && aws ecs update-service --force-new-deployment`.
    *(was #25)*

`deploy/prod/fargate/build-push.sh` builds the static gateway and downloads + sha-verifies
nebula; as of Phases 1 + 2 it **also builds the `cmd/nebula-boot` shim** and uses the distroless
`--platform linux/amd64` build context (done — no longer pending).

## Consequences

- **+** Near-zero OS attack surface **and** maintenance: no busybox / musl / apk / shell to
  CVE-track. Rebuilds are driven by the **payload** (Go stdlib / nebula), not the base
  distro — this collapses most of the "rebuild on an Alpine advisory" treadmill that
  motivated the question.
- **+** **Shell-less + nonroot**: an attacker with code-exec in the container has no
  `/bin/sh` and no root.
- **+** Config no longer round-trips through a shell — the gateway reads env directly; the
  lighthouse shim is a small, single-purpose, auditable Go program. Secrets still come from
  Secrets Manager and are never baked into the image.
- **+** With digest pins + IMMUTABLE tags + a lifecycle policy, image provenance is
  reproducible and rollback-able.
- **−** Real code work: env-var config in `cmd/gateway`, and a new `cmd/nebula-boot` shim
  (the lighthouse "extra work").
- **−** No shell in the image → no `exec`-in to debug; rely on CloudWatch logs + local
  reproduction. (Acceptable — arguably a feature.)
- **−** Distroless base updates are a manual digest bump (the cost of reproducibility).

## Relationship to other work

- **ADR 0005 (Pull-Based Enrollment Gateways)** — created the off-mesh gateway + the pull
  model; the Fargate runtimes (and these images) are how that gateway, and the lighthouse
  (now the default runtime, no longer a spike), run serverless. This ADR hardened those images.
- **`deploy/prod/fargate/`** (the live prod tree) — `Dockerfile`, `nebula.Dockerfile`,
  `build-push.sh`. Both shell entrypoints have been **removed** (the distroless images run
  bare binaries); `build-push.sh` does the static builds + nebula sha-verify + the shim build.
  The demo `deploy/fargate/` still keeps its alpine + `entrypoint.sh` / `nebula-entrypoint.sh`.
- **`cmd/gateway`** — reads its key/cert material from `$NCP_GW_*` env (done). **`cmd/nebula-boot`**
  — the lighthouse config-injector shim, reads `$NCP_LH_*` env (done).
- **Lighthouse on Fargate** — only feasible because a dedicated lighthouse runs
  `tun.disabled` (no TUN, no privilege); a `nonroot` distroless image is consistent with
  that (no privileged needs at all). This is now the live default behind a client-IP-preserving
  UDP NLB (validated 2026-06-18).
- **Live-apply findings (2026-06-14)** — proving the both-Fargate topology surfaced the
  maintenance question that drove this decision; the supply-chain hardening (Phase 3) was
  first captured as standalone todos and is folded in here (still PLANNED).
