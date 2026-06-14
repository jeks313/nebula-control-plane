# Production deploy (scaffold)

This tree is the **production** deployment of the Nebula Control Plane. It starts as a
**verbatim copy of the proven demo** (`deploy/terraform` + `deploy/fargate` +
`deploy/scripts/bootstrap-genesis.sh`, as of the 2026-06-14 live both-Fargate proof),
repointed to be self-contained under `deploy/prod/`:

- `deploy/prod/terraform/` — the terraform (copied from `deploy/terraform`)
- `deploy/prod/fargate/` — the container build context (copied from `deploy/fargate`)
- `deploy/prod/bootstrap-genesis.sh` — the genesis bootstrap (copied; `TFDIR` + the
  `build-push.sh` path point at this tree, so it never touches the demo)

**The demo (`deploy/terraform`) is left untouched for ongoing demo/iteration work.** This
copy is where production-grade changes land, so the two evolve independently.

## ⚠️ This is the demo baseline, NOT yet production-grade

As copied, this is functionally identical to the demo: a **single-AZ** VPC, the **CA +
config-signing keys as `0600` files** on the harbor node, **SQLite** `harbor.db`, the **dev
mock-IdP** for the console, **plain-HTTP** public enroll behind the NLB, and **alpine**
images. Do **not** treat it as production until the work in the ADR below is done.

## What brings it to production grade

See **`docs/Nebula Control Plane - ADR 0007 - Production Deploy.md`** for the design +
phased plan. The headline gaps it closes:

- **CA + config-signing keys → AWS KMS** (keys never leave KMS; harbor signs via KMS) —
  vs today's `0600` files.
- **Aurora PostgreSQL** for `harbor.db` (+ the queue) — vs SQLite.
- **Real SSO IdP — Azure AD / Entra ID via SAML** for the admin console — vs the dev
  mock-IdP. Step-by-step wiring (Entra side + harbor side) is in the companion runbook
  **`docs/Nebula Control Plane - Runbook - Entra ID SAML SSO for the Console.md`**.
- **HA / multi-AZ** for harbor, the lighthouse, and the gateway.
- **Real TLS at the edge** (ACM) for public enroll — vs `-insecure`.
- **Distroless container images** (see ADR 0006) — vs alpine.
- **Observability + backups/DR** for the CA material + the database.

Until those land, prefer the demo tree for experiments.
