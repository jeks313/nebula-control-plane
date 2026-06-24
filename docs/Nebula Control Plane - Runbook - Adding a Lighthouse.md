---
title: "Runbook — Add a lighthouse to a running mesh (HA / blip-free rotation)"
created: 2026-06-24
source: claude-chat
status: active
project: nebula-control-plane
tags: [nebula, runbook, lighthouse, ha, fargate, terraform, ipam, production]
---

# Runbook — Add a lighthouse to a running mesh

**Status (2026-06-24): LIVE — this exact flow added `lighthouse-2` (`10.44.0.6` @ `15.222.142.254:4242`) to the `poc`/prod stack.** lighthouse-1 was untouched; both `ncp-lighthouse` and `ncp-lighthouse-2` ECS services run `1/1 ACTIVE`.

This is the **day-2** procedure for adding a second (or Nth) lighthouse to a mesh that has **already
been genesis'd** (see the [[Genesis Runbook]] for the first-time standup). A fresh genesis mints
lighthouse-1 automatically; this runbook is for scaling lighthouses **after** the mesh is live and
carrying clients.

## Why add a lighthouse

A lighthouse is the node hosts use to find each other (peer discovery + NAT hole-punch
coordination). With **one** lighthouse, rotating its certificate — which forces an ECS redeploy and
a ~30–60s container restart — is a **discovery outage**. Nebula lighthouses don't share state, so
HA is **N independent identities** (each its own cert, overlay IP, and underlay address), all listed
in every host's `static_host_map`. Hosts register with and query *all* of them, so while one
restarts, the others keep serving → **rotation becomes blip-free** (the rotation timer redeploys one
at a time; see the cert-rotation design). This is **not** `desired_count=2` behind one load
balancer — two tasks sharing one identity would each hold half the discovery state and break it.

## Prerequisites

- The mesh is genesis'd and live (`deploy/prod/`, S3 remote state, Fargate lighthouse runtime).
- AWS creds for the account (e.g. `set -a; eval "$(gpg -q -d ~/aws-key-*.env.gpg)"; set +a`).
- SSH-over-SSM access to the harbor box (the genesis SSH key + the `session-manager-plugin`).
- A checkout of the repo **at or after the multi-lighthouse-HA change** (the `harbor lighthouse mint`
  command + the `for_each` lighthouse terraform with `var.lighthouse_count`).

## The two gotchas that will bite you (read first)

1. **NEVER run an untargeted `terraform apply` against the live stack to do this.** The AL2023 AMI
   data source drifts, so a full apply wants to **replace `aws_instance.node["harbor"]`** (and
   client/monitoring) — which **destroys the live control-plane VM** (wipes `/etc/nebula`,
   `~/ncp/genesis`, the running Core). You must `-target` only the lighthouse resources. Step 2
   shows the exact targets and a 0-to-destroy gate.
2. **The lighthouse's overlay IP must be a FREE address.** On a running mesh the central reserved
   `/27` may already have clients in it (on `poc`, `aws-client` took `.3`, and `.4`/`.5` were also
   taken). There is no `ipam list`, so **probe** for a free reserved IP — `harbor lighthouse mint`
   fails cleanly (no side effect) on an already-allocated IP, so a failed probe is safe. Step 4 does
   this automatically.

## What gets created

Per added lighthouse, `terraform` (with `lighthouse_count` raised) stands up — keyed by name, e.g.
`lighthouse-2`, named `ncp-lighthouse-2*`:

- a dedicated **Elastic IP + Network Load Balancer** (the stable underlay address for
  `static_host_map`; Fargate task IPs are ephemeral),
- a target group + UDP listener, a CloudWatch log group, a **Secrets Manager secret**
  (`ncp-lighthouse-2-config`, created empty), an ECS **task definition + service**
  (`ncp-lighthouse-2`, `desired_count=1`).

The ECS **cluster** (`ncp-lighthouse`), ECR repo, task-execution role, and security groups are
**shared** across all lighthouses. The existing lighthouse-1 keeps its legacy `ncp-lighthouse`
names via `moved` blocks, so enabling HA does **not** recreate it.

---

## Steps

All commands assume creds are loaded and you're at the repo root. Substitute the harbor instance ID
(`terraform output instance_ids`), region, and `name_prefix` for your stack. The `poc` values used
below: region `ca-central-1`, prefix `ncp`, harbor `i-0dfc8bfb6d0873954`.

### 1. Raise `lighthouse_count` and plan

Set the count in the app stack's tfvars (default is already `2`):

```hcl
# deploy/prod/terraform/app/terraform.tfvars
lighthouse_count = 2     # number of lighthouse identities you want, total
```

```bash
cd deploy/prod/terraform/app
terraform init -input=false
terraform plan -no-color -out=/tmp/lh.tfplan
```

**Inspect the plan.** A full apply will likely show unrelated **AMI-driven instance replacements**
(`aws_instance.node[...]` "must be replaced") — that is the trap. Do **not** apply the full plan.

### 2. Apply ONLY the lighthouse resources (targeted)

Target the lighthouse resources (whole resources, not per-key — `moved` blocks require this), plus
the rotation IAM and the exec-role secret policy. Verify the targeted plan is **`0 to destroy`** and
touches **no instances**, then apply the saved plan:

```bash
TGT=(
  -target=aws_cloudwatch_log_group.lighthouse
  -target=aws_secretsmanager_secret.lighthouse
  -target=aws_secretsmanager_secret_version.lighthouse
  -target=aws_eip.lighthouse_nlb
  -target=aws_lb.lighthouse
  -target=aws_lb_target_group.lighthouse
  -target=aws_lb_listener.lighthouse
  -target=aws_ecs_task_definition.lighthouse
  -target=aws_ecs_service.lighthouse
  -target=aws_iam_role_policy.lighthouse_secret
  -target=aws_iam_role_policy.core_lighthouse_rotate
)
terraform plan -no-color "${TGT[@]}" -out=/tmp/lh.tfplan
# GATE: confirm "Plan: N to add, M to change, 0 to destroy" and NO aws_instance/gateway lines.
terraform apply /tmp/lh.tfplan
```

Grab the new lighthouse's underlay address (its EIP) for later:

```bash
terraform output -json lighthouse_addrs    # {"lighthouse-1":"...","lighthouse-2":"15.222.142.254:4242"}
terraform output -raw  ca_key_arn           # KMS CA key — mint signs with this
```

After this, the new ECS service exists but **crash-loops** (its secret is empty). That's fine — the
mesh can't see it yet (it isn't in the registry), so there's no client impact.

### 3. Ship a mint-capable `harbor` binary to the box

`harbor lighthouse mint` is the command that creates a lighthouse identity; it must run **on the
harbor box** (only there can it reach Aurora + sign with the CA via the instance role). Build it and
copy it to the box (run it from `/tmp`; you do **not** need to swap `/usr/local/bin/harbor` or
recreate any service):

```bash
GOOS=linux GOARCH=amd64 go build -o /tmp/harbor-lh ./cmd/harbor
HB=i-0dfc8bfb6d0873954
PROXY="ProxyCommand=aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p --region ca-central-1"
scp -o "$PROXY" -i ~/.ssh/<genesis-key> /tmp/harbor-lh ec2-user@$HB:/tmp/harbor-lh
ssh -o "$PROXY" -i ~/.ssh/<genesis-key> ec2-user@$HB 'chmod +x /tmp/harbor-lh && /tmp/harbor-lh lighthouse'  # should list "mint"
```

### 4. Mint the lighthouse identity (pin a free reserved IP)

On the box: generate a keypair, then probe the central reserved `/27` for a free address and mint.
`mint` **pins** the IP (`AllocateSpecific`), issues the cert **in group `lighthouse`** from the new
key, and **records the issued enrollment** (so the revocation guard protects it *and*
`rotate-cert` can later re-sign it). It writes the cert to `-out`:

```bash
ssh -o "$PROXY" -i ~/.ssh/<genesis-key> ec2-user@$HB 'bash -s' <<'BOX'
. /etc/profile.d/harbor-cli.sh                       # HARBOR_DB_* → Aurora
CA_KEY_ARN="arn:aws:kms:ca-central-1:...:key/..."    # from `terraform output -raw ca_key_arn`
pilot init -am-lighthouse -dir /tmp/lhk >/dev/null   # keypair (host.key never leaves the box)
for n in 4 5 6 7 8 9 10 11 12; do
  IP="10.44.0.$n"
  if /tmp/harbor-lh lighthouse mint -backend kms -kms-key-id "$CA_KEY_ARN" -kms-region ca-central-1 \
       -ca-cert ~/ncp/genesis/ca.crt -name lighthouse-2 -ip "$IP" -in-pub /tmp/lhk/host.pub \
       -pool 10.44.0.0/16 -out /tmp/lh.crt 2>/tmp/mint.err; then
    echo "MINTED lighthouse-2 @ $IP"; break
  fi
  grep -q "already allocated" /tmp/mint.err && { echo "$IP taken"; continue; }
  echo "mint error:"; cat /tmp/mint.err; exit 1
done
BOX
```

Note the chosen IP (on `poc` it landed on `10.44.0.6`). `-name` must be unique and match the
terraform key (`lighthouse-2`, `lighthouse-3`, …) so the rotation tuple lines up.

### 5. Inject the secret + force the ECS deploy

Assemble `{ca_crt_pem, host_crt_pem, host_key_pem}` **on the box** (so the private key never leaves
it), write it to the lighthouse's secret, and force a new ECS deployment so the task restarts onto
the populated secret:

```bash
ssh -o "$PROXY" -i ~/.ssh/<genesis-key> ec2-user@$HB 'bash -s' <<'BOX'
SJSON=$(jq -n --rawfile ca ~/ncp/genesis/ca.crt --rawfile crt /tmp/lh.crt --rawfile key /tmp/lhk/host.key \
  '{ca_crt_pem:$ca,host_crt_pem:$crt,host_key_pem:$key}')
aws secretsmanager put-secret-value --region ca-central-1 --secret-id ncp-lighthouse-2-config --secret-string "$SJSON" >/dev/null
aws ecs update-service --region ca-central-1 --cluster ncp-lighthouse --service ncp-lighthouse-2 --force-new-deployment >/dev/null
rm -f /tmp/lh.crt /tmp/lhk/host.key                  # the key now lives only in the secret
echo done
BOX
```

### 6. Wait for steady state — BEFORE registering

```bash
aws ecs wait services-stable --region ca-central-1 --cluster ncp-lighthouse --services ncp-lighthouse-2
aws ecs describe-services --region ca-central-1 --cluster ncp-lighthouse --services ncp-lighthouse-2 \
  --query 'services[0].{desired:desiredCount,running:runningCount,status:status}'
```

Register **only after** it's `running: 1` — otherwise clients would get a `static_host_map` entry
for a lighthouse that isn't serving yet.

### 7. Register in the discovery registry

Core (`-lighthouse-db`) serves the registry into every signed bundle's `static_host_map`, so this is
what makes clients learn about the new lighthouse (on their next bundle poll). Use the EIP from
step 2:

```bash
ssh -o "$PROXY" -i ~/.ssh/<genesis-key> ec2-user@$HB \
  '. /etc/profile.d/harbor-cli.sh; /tmp/harbor-lh lighthouse add -ip 10.44.0.6 -addrs 15.222.142.254:4242 -name lighthouse-2 -actor <you>'
```

### 8. Verify

```bash
ssh ... ec2-user@$HB '. /etc/profile.d/harbor-cli.sh; harbor lighthouse list'   # both lighthouses, state=active
aws ecs describe-services --region ca-central-1 --cluster ncp-lighthouse \
  --services ncp-lighthouse ncp-lighthouse-2 --query 'services[].{n:serviceName,running:runningCount,status:status}' --output table
# Container health (CloudWatch /ncp/lighthouse-2): expect "listening on 0.0.0.0:4242" +
# "Nebula interface is active ... networks=[10.44.0.6/16] ... interface=disabled" (tun.disabled).
```

A healthy add looks like: registry lists both (active), both ECS services `1/1 ACTIVE`, and the new
container is `listening on :4242` with its cert loaded. Lighthouses **do not** appear in
`harbor fleet` — they're Fargate nebula (not `pilot`-supervised), tracked via `harbor lighthouse
list`, which is exactly why their certs rotate operator-side (`harbor lighthouse rotate-cert`).

Clean up the box: `ssh ... ec2-user@$HB 'rm -rf /tmp/harbor-lh /tmp/lhk /tmp/lh.crt /tmp/mint.err'`.

---

## Rotation (the payoff)

With ≥2 lighthouses registered, `deploy/prod/lighthouse-rotate/` rotates **blip-free**: the timer
runs `harbor lighthouse rotate-cert` per lighthouse and **health-gates between redeploys**
(`aws ecs wait services-stable`), so only one lighthouse restarts at a time — and it **stops** if one
doesn't come back, rather than risk restarting two at once. Add a tuple per lighthouse to
`/etc/nebula/lighthouse-rotate.env`'s `LIGHTHOUSES`
(`lighthouse-2:ncp-lighthouse-2-config:ncp-lighthouse:ncp-lighthouse-2`) if the rotation timer is
installed on the box.

## Removing a lighthouse

1. `harbor lighthouse remove -ip <overlay-ip> -actor <you>` (drops it from `static_host_map`; the
   registry keeps ≥1 active). Wait for clients to re-poll their bundles.
2. Lower `lighthouse_count` (or remove the entry) and **targeted-apply** the lighthouse resources to
   tear down its ECS service/NLB/EIP/secret — same `-target` discipline as step 2 (never untargeted).
3. Optionally `harbor ipam release -ip <overlay-ip>` to free the reserved address.

## Notes

- **Genesis vs day-2.** At genesis the bootstrap mints lighthouse-2..N automatically (clean mesh, IPs
  `10.44.0.1`, `.3`, … are free). This runbook is the day-2 path; the only real differences are the
  **targeted apply** and **probing for a free IP** (a populated mesh may have leaked clients into the
  central block).
- **Why on the box.** `mint`/`add` need Aurora reachability and (for `mint`) `kms:Sign` on the CA key
  — both come from the harbor instance role, so they run on the box, not your laptop.
- **One image, N identities.** All lighthouses share the `ncp-lighthouse` ECR image + ECS cluster;
  only the cert/key/IP/underlay-address differ per identity.

Conceptual background: the multi-lighthouse HA design + the cert-rotation rationale (the Fargate
lighthouse can't self-renew because Core's host-renew is authed by source overlay IP). See also the
[[Genesis Runbook]] and [[Chaos and Outage Runbook]].
