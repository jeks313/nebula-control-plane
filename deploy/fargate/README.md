# Fargate gateway (spike)

Run the off-mesh enrollment gateway as a **serverless Fargate container** instead of
an EC2 VM. It's feasible precisely because the gateway runs **no `nebula`** (no TUN)
— per ADR 0005 it's a credential-less HTTP/mTLS service that initiates nothing. The
lighthouse + Core still need EC2 (they run `nebula` → need a TUN device).

**Status: spike.** `terraform validate` clean in both runtimes; **not** live-applied
(no AWS creds / no docker in the dev env). Expect first-run iteration on a real apply.

## What it gives you

`gateway_runtime = "fargate"` (vs the default `"ec2"`) swaps the gateway EC2 node for:

- an **ECS Fargate service** in the `edge` subnet running `cmd/gateway` (a tiny
  alpine image: the static binary + an entrypoint that materializes config),
- a **network load balancer** for a stable address (Fargate task IPs are ephemeral),
  with the ADR-0005 posture enforced at the NLB's security group: **`:8443` (enroll)
  public, `:9443` (collect) from Harbor's SG only**,
- config (nonce key + leaf-pinned mTLS certs) injected from **Secrets Manager**,
- CloudWatch logs, a least-privilege task execution role.

The EC2 lighthouse + harbor + client are unchanged. `gateway_url` /
`gateway_collect_addr` outputs resolve to the NLB DNS name automatically.

## Run it

```bash
cd deploy/terraform
terraform apply -var gateway_runtime=fargate        # creates the ECR repo, NLB, ECS service, secret (empty)
deploy/fargate/build-push.sh                        # build the image -> push to the ECR repo
# populate the config secret (<prefix>-gateway-config) with the genesis keys/certs —
# the genesis bootstrap does this; then force a new deployment:
aws ecs update-service --cluster ncp-gateway --service ncp-gateway --force-new-deployment --region <region>
# register it with Harbor (uses the NLB collect URL from the output):
harbor gateway add -name gw1 -url "$(terraform output -raw gateway_collect_addr)" -cert <gw-collect.crt>
```

## Caveats (spike)

- The gateway's **local queue is ephemeral** (task storage) — a task restart loses
  in-flight enrollments; tolerable (Core re-verifies; devices retry), or mount EFS
  for durability.
- Public enroll is **plain HTTP behind the NLB** (`-insecure`, TCP passthrough) here;
  production terminates TLS at the NLB (ACM) or in the gateway. The **collect port is
  mTLS regardless** (the gateway terminates it, leaf-pinned).
- Secrets are written to a tmp dir inside the (ephemeral) container — no more exposed
  than the injected env vars; a native env-var config path in the gateway would avoid
  even that (a clean follow-up).
- Single AZ / `desired_count = 1` for the spike; the NLB + ECS make scaling to N tasks
  / multi-AZ a config change, not a redesign.
