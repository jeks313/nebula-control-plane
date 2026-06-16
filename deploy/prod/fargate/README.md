# Fargate runtimes (serverless gateway + lighthouse spike)

Two of the three cloud roles can run as **serverless Fargate containers** instead of
EC2 VMs, because what makes a node need a VM is a **TUN device** (`nebula`'s data
plane needs `/dev/net/tun` + `CAP_NET_ADMIN`, which Fargate doesn't grant):

| Role | Runs `nebula`? | Needs a TUN? | Fargate? |
|------|----------------|--------------|----------|
| **gateway** | no (ADR 0005 — credential-less HTTP/mTLS) | no | ✅ **default** |
| **lighthouse** | yes, but `tun.disabled` (control-plane only) | **no** | ⚠️ spike |
| **harbor (Core)** | yes — routes core-api over the overlay | **yes** | ❌ EC2 |

Toggle each independently: `gateway_runtime = "fargate" | "ec2"` (default **fargate**)
and `lighthouse_runtime = "ec2" | "fargate"` (default **ec2** — the lighthouse path is
an unproven spike).

---

## Gateway — `gateway_runtime = "fargate"` (the default)

The off-mesh enrollment gateway runs **no `nebula`** (no TUN) — per ADR 0005 it's a
credential-less HTTP/mTLS service that initiates nothing — so it's the natural fit for
serverless, and the example deploy uses it by default.

`gateway_runtime = "fargate"` gives you:

- an **ECS Fargate service** in the `edge` subnet running `cmd/gateway` (a **distroless,
  shell-less, nonroot** image — ADR 0006: `gcr.io/distroless/static-debian12:nonroot` + the
  bare static binary, no entrypoint shell; `Dockerfile`). The binary reads its key/cert
  **material from env vars** (`NCP_GW_*`, injected from Secrets Manager) and its operational
  flags from the ECS `command`,
- **two network load balancers** for stable addresses (Fargate task IPs are ephemeral) —
  this split is required because an *internet-facing* NLB is **not reachable from inside
  the VPC** by DNS, so in-VPC consumers (Harbor pulling collect; the cloud client
  enrolling) need a private path:
  - a **public (internet-facing) NLB** carrying **`:8443` enroll only** — for off-cloud
    clients (the iMac),
  - an **internal NLB** carrying **`:8443` enroll + `:9443` collect** — for in-VPC
    consumers. The ADR-0005 posture holds: **collect is reachable only from Harbor's SG**
    (on the internal NLB); enroll is public on the internet-facing NLB,
- config (nonce key + leaf-pinned mTLS certs) injected from **Secrets Manager**,
- CloudWatch logs, a least-privilege task execution role.

Outputs: `gateway_url` (public enroll, off-cloud), `gateway_url_internal` (in-VPC enroll),
`gateway_collect_addr` (internal collect) resolve to the right NLB automatically. The
**genesis bootstrap does the gateway Fargate wiring for you** — build/push the image,
populate the secret, force the deploy, register + verify the gateway (see "Run it").

`gateway_runtime = "ec2"` puts it back on a VM (the original ADR-0005 path) — unchanged.

---

## Lighthouse — `lighthouse_runtime = "fargate"` (spike)

A dedicated lighthouse does **only control-plane work** — discovery (overlay→underlay
registration + queries) and NAT hole-punch coordination, all over UDP — and passes
**no data-plane traffic to/from itself**, so it can run `nebula` with **`tun.disabled`**:
no TUN, no `CAP_NET_ADMIN`, no privilege. It's still a full Nebula **protocol**
participant (cert + Noise handshake + the lighthouse message types), so this is
**VM-free, not off-mesh** — it can't be replaced by a generic service the way the
gateway can.

`lighthouse_runtime = "fargate"` gives you (`lighthouse_fargate.tf`):

- an **ECS Fargate service** in the `mesh` subnet running the **`nebula.Dockerfile`**
  image (**distroless, shell-less, nonroot** — ADR 0006: the pinned, sha-verified `nebula`
  release + the static **`cmd/nebula-boot`** shim, which reads the injected identity from
  `NCP_LH_*` env, renders a `tun.disabled` lighthouse `config.yml`, and `exec`s nebula —
  replacing the old shell entrypoint),
- a **UDP network load balancer with a pinned Elastic IP** — the lighthouse's underlay
  address is baked into every host's `static_host_map`, so it must be stable,
- the nebula identity (CA + genesis-issued cert + host key) injected from **Secrets
  Manager**, CloudWatch logs, a least-privilege role.

### ⚠️ The key spike unknown — client address preservation

A lighthouse learns each host's **post-NAT underlay address from the source of the UDP
packet** it receives. So the UDP NLB **must preserve the client address**
(`preserve_client_ip = true`, set on the target group) — otherwise every host would
register the NLB's address and **hole-punching would break**. This is configured but
**unverified on a live apply** — it's the first thing to confirm. (Direct host↔host
tunnels never traverse the NLB; only discovery/coordination does.)

### Health check wrinkle

NLB **UDP** target groups can't be health-checked over UDP, so the image enables
`nebula`'s **prometheus stats listener on a TCP port** (`lighthouse_stats_port`, default
8080) purely as the health-check target. It's reachable from the NLB only (SG), never
public.

### Bootstrap (manual — not auto-wired)

The genesis bootstrap **aborts** if `lighthouse_runtime = "fargate"` (its genesis steps
differ: the host key is generated on the box for EC2, but must be generated off-box and
injected for Fargate). To run the spike by hand after `terraform apply`:

```bash
# 1. generate the lighthouse keypair + have harbor's genesis sign it for the LH overlay IP
#    (pilot init -am-lighthouse locally; feed host.pub to `harbor genesis -lighthouse-pub`)
# 2. push the image (builds the nebula-boot shim + the distroless lighthouse image):
deploy/prod/fargate/build-push.sh lighthouse
# 3. populate the secret with ca.crt / the signed host.crt / host.key:
aws secretsmanager put-secret-value --secret-id ncp-lighthouse-config \
  --secret-string "$(jq -n --rawfile ca ca.crt --rawfile c host.crt --rawfile k host.key \
     '{ca_crt_pem:$ca, host_crt_pem:$c, host_key_pem:$k}')" --region <region>
# 4. force the deploy; static_host_map uses `terraform output -raw lighthouse_addr` (the NLB EIP)
aws ecs update-service --cluster ncp-lighthouse --service ncp-lighthouse --force-new-deployment --region <region>
```

---

## Run it

```bash
cd deploy/prod/terraform/app
terraform apply                                     # gateway=fargate by default: ECR repo, NLB, ECS service, empty secret
# the genesis bootstrap builds/pushes the gateway image, populates the secret, and
# forces the deploy — run it under the same AWS creds you used for terraform:
aws-vault exec nebula -- bash ../../bootstrap-genesis.sh
```

To build/push an image by hand: `deploy/prod/fargate/build-push.sh [gateway|lighthouse]`
(needs `go` — both images now carry a static Go binary).

**Status: spike.** `terraform validate` is clean in every runtime combination; `go
build`/`test`/`vet`/`golangci-lint` pass (incl. the `cmd/nebula-boot` test). **Not**
live-applied (no AWS creds / no docker in the dev env). Expect first-run iteration on a
real apply.

## Caveats (spike)

- The gateway's **local queue is ephemeral** (`/tmp` task storage) — a task restart loses
  in-flight enrollments; tolerable (Core re-verifies; devices retry), or mount EFS.
- Public enroll TLS terminates **in the gateway**: with `gateway_domain` set it obtains +
  renews its **own Let's Encrypt cert via ACME DNS-01** (Cloudflare) and serves HTTPS end to
  end (the NLB is L4 passthrough), persisting the cert cache on EFS (ADR 0007 TLS pivot);
  without a domain it falls back to `-insecure` (plain HTTP behind the NLB). The **collect
  port is mTLS regardless** (leaf-pinned, the gateway terminates it).
- Both images are **distroless + nonroot** (uid 65532, ADR 0006): no shell, no package
  manager — an attacker with code-exec has neither `/bin/sh` nor root, and rebuilds track the
  Go/nebula payload, not an OS-distro CVE treadmill.
- The Fargate lighthouse's **host key is generated off-box and injected** (vs the EC2
  lighthouse, where it never leaves the node) — a deliberate spike trade-off.
- Single AZ / `desired_count = 1` for the spike; the NLB + ECS make scaling to N tasks
  / multi-AZ a config change, not a redesign.
