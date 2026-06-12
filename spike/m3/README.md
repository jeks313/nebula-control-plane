# M3 end-to-end harness (implementation-plan 3.8)

`demo.sh` (`make m3-demo`) spins the **whole enrollment path as real separate
processes** and asserts it works — a one-command, zero-setup regression harness
for the join flow.

## What it does

1. **genesis** — creates the CA + config-signing key + the first lighthouse cert
   (software backend, SQLite).
2. starts the **gateway** (public, credential-less) and a **`harbor enroll worker`**
   (Core consumer) as background processes, talking only through the durable queue.
3. **auto-issue join key** → `pilot enroll` joins straight away.
4. **default join key** → `pilot enroll` lands **PENDING** (manual approval).
5. **`harbor enroll approve`** → issues the pending host.
6. `pilot enroll` **resumes its saved ticket** → joins.
7. asserts the **audit chain** is intact and (if `nebula` is installed) the
   enrolled node config passes `nebula -test`.

Everything runs in throwaway temp dirs and is cleaned up on exit. Exit 0 = PASS.

```bash
make m3-demo            # or: bash spike/m3/demo.sh
NCP_GW_PORT=18500 make m3-demo   # override the gateway port
```

## Local vs faithful

This is the **local-first** variant: SQLite (not Postgres), software CA (not
KMS), processes (not VMs) — suitable for CI/nightly with no external deps. The
faithful Postgres + KMS + multi-VM scenario belongs with the infrastructure plan
(the same binaries, different `-driver`/`-backend`/queue backend).
