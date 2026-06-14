---
title: "ADR 0006 — Distroless Container Images for the Fargate Gateway & Lighthouse"
created: 2026-06-14
status: accepted
tags: [nebula, adr, fargate, containers, distroless, supply-chain, security, maintenance, deploy]
---

# ADR 0006 — Distroless Container Images for the Fargate Gateway & Lighthouse

**Status:** Accepted
**Date:** 2026-06-14
**Decision owners:** Chris Hyde

## Context

ADR 0005 moved the enrollment gateway off-mesh. The live-apply work (2026-06-14) then
made both the **gateway** and — as a spike — the **lighthouse** runnable as serverless
**Fargate** containers (`gateway_runtime` / `lighthouse_runtime = "fargate"`,
`deploy/fargate/`), proven end-to-end on real AWS.

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

- **Phase 1 — gateway → distroless.** Add env-var config to `cmd/gateway` (HMAC + queue
  keys, collect cert/key, Harbor client cert from env; create the ephemeral queue dir
  in-process). Rewrite `deploy/fargate/Dockerfile`: `FROM gcr.io/distroless/static-debian12`
  (digest-pinned), `COPY gateway /gateway`, `USER nonroot`, `ENTRYPOINT ["/gateway"]`.
  Delete `entrypoint.sh`. Verify the image builds and that public enroll + the leaf-pinned
  collect mTLS still work.
- **Phase 2 — lighthouse → distroless (the extra work).** Add `cmd/nebula-boot` (static,
  `CGO_ENABLED=0`): env → cert files + rendered `config.yml` → `exec` nebula. Rewrite
  `nebula.Dockerfile` to distroless: `COPY` the sha-verified nebula binary **and** the
  shim, `USER nonroot`, `ENTRYPOINT ["/nebula-boot"]`. Delete `nebula-entrypoint.sh`.
  Confirm a `nonroot`, `tun.disabled` lighthouse still binds `:4242` + the stats port (no
  privilege is needed without a TUN).
- **Phase 3 — supply-chain hardening** (folds in former todos #21–#25):
  - Pin both images by **digest** and set the ECR repos `image_tag_mutability = "IMMUTABLE"`
    (reproducibility + rollback vs today's `:latest` / `MUTABLE`). *(was #21)*
  - Add an **ECR lifecycle policy** to each repo (expire untagged / keep last K). *(was #22)*
  - **Digest-pin the distroless base** in both Dockerfiles — reproducible builds; bump the
    digest deliberately when refreshing the base. *(replaces the alpine-pin item #24)*
  - **Pin the ECS `platform_version`** on both services (optional; LATEST auto-patches
    today). *(was #23)*
  - Document the **rebuild/redeploy cadence** in `deploy/fargate/README.md` — now much
    lighter: rebuild only on a Go-stdlib (gateway) or nebula (bump `NEBULA_VERSION` +
    `NEBULA_SHA256`) advisory, **not** on every Alpine CVE; review ECR scan-on-push
    findings; `build-push.sh <component> && aws ecs update-service --force-new-deployment`.
    *(was #25)*

`deploy/fargate/build-push.sh` already builds the static gateway and downloads + sha-verifies
nebula; it gains the `cmd/nebula-boot` build and the distroless `--platform linux/amd64`
build context.

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
  spike, run serverless. This ADR hardens those images.
- **`deploy/fargate/`** — `Dockerfile`, `nebula.Dockerfile`, `build-push.sh`, and the two
  entrypoints (to be removed). `build-push.sh` already does the static builds + nebula
  sha-verify; it gains the shim.
- **`cmd/gateway`** — gains env-var config. **`cmd/nebula-boot`** — new, the lighthouse
  config-injector shim.
- **Lighthouse on Fargate** — only feasible because a dedicated lighthouse runs
  `tun.disabled` (no TUN, no privilege); a `nonroot` distroless image is consistent with
  that (no privileged needs at all).
- **Live-apply findings (2026-06-14)** — proving the both-Fargate topology surfaced the
  maintenance question that drove this decision; the supply-chain hardening (Phase 3) was
  first captured as standalone todos and is folded in here.
