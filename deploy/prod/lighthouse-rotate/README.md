# Lighthouse certificate rotation (Option A)

The lighthouse runs as a Fargate container with its cert/key/CA injected from the
`<prefix>-lighthouse-config` Secrets Manager secret. Unlike a `pilot`-supervised VM, it
**cannot self-renew**:

- core-api's host-renew is authenticated by the caller's *source overlay IP*, so renewal must
  come from a host already on the mesh — a re-mint happens off-box, before the new cert is on
  the mesh, so the lighthouse can't do it itself.
- The cert must therefore be re-minted **operator-side against the CA** (KMS), then re-injected
  into the secret and the container restarted.

This directory is that rotation, run from the **harbor box** (the only host with the CA backend
via its instance-role KMS grant, the `harbor` binary, and Aurora access).

## Pieces

| File | Role |
|------|------|
| `rotate-lighthouse-cert.sh` | Orchestrator: `harbor lighthouse rotate-cert` → patch secret → force ECS redeploy. Idempotent. |
| `harbor-lighthouse-rotate.service` | `oneshot` that runs the script against `/etc/nebula/lighthouse-rotate.env`. |
| `harbor-lighthouse-rotate.timer` | Monthly (`*-*-01`), jittered, `Persistent=true`. |

`bootstrap-genesis.sh` installs all three on the harbor box and writes the env file.

## How a rotation runs

1. `harbor lighthouse rotate-cert -rotate-if-within $WITHIN` re-signs the lighthouse's cert
   **in place** — same overlay IP, same groups, **same key** (cert-only) — reading identity
   strictly from the lighthouse's issued enrollment row (fail-closed if it isn't in the
   `lighthouse` group). With `-rotate-if-within` it prints the new cert *only* if the current
   one expires within the window; otherwise it prints nothing and exits 0.
2. If a new cert came back, the script merges it into the secret's `host_crt_pem` (preserving
   `ca_crt_pem` + `host_key_pem`) and runs `aws ecs update-service --force-new-deployment`.

No new cert ⇒ no secret write, no redeploy. So the monthly timer is a no-op until the cert
enters its rotation window, then rotates once and goes quiet again.

## Config (`/etc/nebula/lighthouse-rotate.env`)

```sh
REGION=ca-central-1
CA_CERT=/etc/nebula/ca.crt                    # public CA cert (root-readable, installed at genesis)
# harbor CA backend (matches genesis): KMS in prod, or software for a local CA key.
BACKEND_FLAGS="-backend kms -kms-key-id arn:aws:kms:...:key/... -kms-region ca-central-1"
POOL=10.44.0.0/16
LIFETIME=8760h                                # new cert validity (~1y)
WITHIN=2160h                                  # rotate if expiring within ~90d
HARBOR_DB_FLAGS="-driver postgres -dsn postgres://.../harbor?sslmode=require -db-secret-arn arn:... -db-secret-region ca-central-1"
# space/newline-separated  name:secret:cluster:service  tuples (one per lighthouse)
LIGHTHOUSES="lighthouse-1:ncp-lighthouse-config:ncp-lighthouse:ncp-lighthouse"
```

`rotate-cert` re-signs via the CA backend (`-kms-key-id` for KMS — note that's the *single*
key flag from `addBackendFlags`, not genesis's `-kms-ca-key-id`). The harbor instance role's
existing `core_kms_sign` grant (`kms:Sign` on the CA key) already covers it.

When multiple lighthouses run (HA, blip-free rotation), add one tuple per lighthouse to
`LIGHTHOUSES`. The timer staggers naturally — each is re-signed + redeployed independently,
so the others keep serving discovery while one restarts.

## IAM

The harbor instance role needs, scoped to the lighthouse secret + service:

- `secretsmanager:GetSecretValue`, `secretsmanager:PutSecretValue` on `<prefix>-lighthouse-config`
- `ecs:UpdateService`, `ecs:DescribeServices` on the `<prefix>-lighthouse` service
- (KMS `kms:Sign` on the CA key is already granted for genesis/core signing.)
