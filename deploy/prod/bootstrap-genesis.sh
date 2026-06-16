#!/usr/bin/env bash
# Genesis bootstrap for the test topology (deploy/terraform). Run from your own
# machine (the iMac) after `terraform apply`. It is an SSH orchestrator — it does
# NOT need to run on any node. It stands up the FULL control plane + data plane:
#
#   0. build harbor/pilot/gateway/nebula bits + scp them to the 3 nodes
#   1. lighthouse: pilot init -am-lighthouse  (host key stays on the lighthouse)
#   2. harbor:     pilot init (its OWN mesh key, with the lighthouse in static_host_map)
#   3. harbor:     migrate + genesis (CA + config-signing + lighthouse cert + HARBOR's
#                  control-plane cert, so Harbor is a real mesh node — ADR/baseline:
#                  the firewall routes every host to group:control-plane)
#   4. lighthouse: install ca + lighthouse cert; start nebula
#   5. harbor:     install ca + control-plane cert; start nebula (Harbor joins the mesh)
#   6. harbor:     publish a cloud-trust config (this AWS account -> groups, auto-issue)
#   7. gateway:    the OFF-MESH enrollment gateway (ADR 0005) — public enroll + a
#                  Harbor-only mTLS collect port over a local queue; Harbor registers it
#                  (`harbor gateway add`) + runs `harbor collect` to PULL + issue + push
#                  results back (no shared queue, no mesh identity on the gateway). Runs
#                  as a serverless FARGATE container by default (gateway_runtime=fargate:
#                  build/push the image + populate the config secret + force the ECS
#                  deploy), or on an EC2 node (gateway_runtime=ec2). Plus the imac join
#                  key (manual approval).
#   8. harbor:     core-api (renew/heartbeat, -host-cert verified) + admin console
#                  (mock-IdP), both bound to Harbor's OVERLAY IP (mesh-only)
#
# It then prints the gateway URL, the config-signing pin, the imac join secret, and
# the exact enroll commands: the CLOUD client joins KEYLESS via aws-sigv4 attestation
# (its IAM role); the off-cloud iMac joins via a join key with manual approval.
#
# Requires locally: terraform, jq, go, ssh, scp, openssl  (+ aws & a container engine
# [podman or docker], and AWS creds in the env, when gateway_runtime=fargate).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TFDIR="$ROOT/deploy/prod/terraform/app" # the app stack (foundation/ is layer 0, applied separately)
SSH_KEY="${SSH_KEY:-$HOME/.ssh/absolute.pub}"   # public key selecting the agent identity (private may be passphrase-locked in the agent)
SSH_USER="${SSH_USER:-ec2-user}"
SKIP_BUILD=0
[[ "${1:-}" == "--skip-build" ]] && SKIP_BUILD=1

# Overlay pool + reserved overlay IPs. IMPORTANT: do NOT use 100.64.0.0/10 (CGNAT)
# if any host also runs Tailscale — its nftables anti-spoof rule silently drops that
# range on non-tailscale0 interfaces, killing the nebula data plane. Default to a
# private range that won't collide.
POOL="${POOL:-10.44.0.0/16}"
LH_OVERLAY="${LH_OVERLAY:-10.44.0.1}"
HARBOR_OVERLAY="${HARBOR_OVERLAY:-10.44.0.2}"   # Harbor's own mesh address (control-plane node)
CORE_PORT="${CORE_PORT:-8444}"                   # core-api (renew/heartbeat), mesh-only
ADMIN_PORT="${ADMIN_PORT:-8445}"                 # admin console, mesh-only
MOCK_IDP_PORT="${MOCK_IDP_PORT:-8446}"           # dev mock-IdP for the console login

for t in terraform jq go ssh scp openssl; do command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }; done
[[ -f "$SSH_KEY" ]] || { echo "ssh private key not found: $SSH_KEY (set SSH_KEY=...)" >&2; exit 1; }

SSH_OPTS=(-i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes)
rsh() { local host="$1"; shift; ssh "${SSH_OPTS[@]}" "$SSH_USER@$host" "$@"; }
rcp() { scp "${SSH_OPTS[@]}" "$@"; }

echo "==> reading terraform outputs"
OUT="$(terraform -chdir="$TFDIR" output -json)"
val() { jq -r "$1 // \"\"" <<<"$OUT"; }
LH_IP="$(val '.public_ips.value.lighthouse')"
HB_IP="$(val '.public_ips.value.harbor')"
GW_IP="$(val '.public_ips.value.gateway')"          # off-mesh gateway EC2 node (empty when gateway_runtime=fargate)
CL_IP="$(val '.public_ips.value.client')"
LH_ADDR="$(val '.lighthouse_addr.value')"
GW_URL="$(val '.gateway_url.value')"                # PUBLIC enroll URL (off-cloud clients; public NLB DNS / node IP)
GW_URL_INTERNAL="$(val '.gateway_url_internal.value')" # IN-VPC enroll URL (cloud client; internal NLB DNS / node IP)
GW_COLLECT="$(val '.gateway_collect_addr.value')"   # gateway's Harbor-facing collect URL (in-VPC; internal NLB / node IP)
[[ -n "$GW_URL_INTERNAL" ]] || GW_URL_INTERNAL="$GW_URL" # older state without the internal output
GATEWAY_RUNTIME="$(val '.gateway_runtime.value')"; GATEWAY_RUNTIME="${GATEWAY_RUNTIME:-ec2}"
LIGHTHOUSE_RUNTIME="$(val '.lighthouse_runtime.value')"; LIGHTHOUSE_RUNTIME="${LIGHTHOUSE_RUNTIME:-ec2}"
NAME_PREFIX="$(val '.name_prefix.value')"; NAME_PREFIX="${NAME_PREFIX:-ncp}"
TF_REGION="$(val '.region.value')"
# Trust-root signing backend (ADR 0007 Phase 2): the foundation stack provisions two ECC_NIST_P256
# KMS keys (CA + config-signing) and re-exports their ARNs. When present (always, in the prod app
# stack), genesis + Core sign via AWS KMS and the CA/config-signing PRIVATE KEYS NEVER TOUCH DISK;
# empty ARNs fall back to the software backend (genesis writes ca.key/config-signing.key into
# ~/ncp/genesis). The harbor node's IAM role grants kms:Sign + kms:GetPublicKey on exactly these two
# keys (foundation core_kms_sign), and AWS creds reach KMS via that instance role.
CA_KEY_ARN="$(val '.ca_key_arn.value')"
CFG_KEY_ARN="$(val '.config_signing_key_arn.value')"
if [[ -n "$CA_KEY_ARN" && -n "$CFG_KEY_ARN" ]]; then
  KMS_FLAGS="-backend kms -kms-ca-key-id $CA_KEY_ARN -kms-config-key-id $CFG_KEY_ARN"
  [[ -n "$TF_REGION" ]] && KMS_FLAGS="$KMS_FLAGS -kms-region $TF_REGION"
  GENESIS_BACKEND="$KMS_FLAGS"  # genesis selects KMS; it then writes only PUBLIC ca.crt + config-signing.pub
  SIGN_BACKEND="$KMS_FLAGS"     # core-api/admin-api/collect: same KMS flags (the public -ca-cert is kept alongside)
  APPROVE_BACKEND="$KMS_FLAGS"  # the printed manual enroll-approve hint
  TRUST_BACKEND_DESC="AWS KMS (CA + config-signing private keys never on disk)"
else
  GENESIS_BACKEND=""                                                     # software: genesis GENERATES + writes the keys to -out
  SIGN_BACKEND="-ca-key \$G/ca.key -config-key \$G/config-signing.key"   # software: read the genesis-written keys (\$G expands remotely)
  APPROVE_BACKEND="-ca-key ~/ncp/genesis/ca.key -config-key ~/ncp/genesis/config-signing.key"
  TRUST_BACKEND_DESC="software (keys in ~/ncp/genesis on the harbor node)"
fi
# Harbor edge TLS (ADR 0007 Phase 5): when harbor_domain is set, core-api + the console obtain
# their OWN Let's Encrypt cert via ACME DNS-01 and serve HTTPS; clients then reach Harbor by
# that hostname (operators must resolve it to Harbor's overlay IP for mesh members). Empty =
# plain HTTP on the overlay IP (unchanged default).
HARBOR_DOMAIN="$(val '.harbor_domain.value')"
ACME_EMAIL="$(val '.acme_email.value')"
ACME_STAGING="$(val '.acme_staging.value')"          # "true" when staging; else "" (jq's // collapses bool false to empty)
CF_SECRET_ARN="$(val '.cloudflare_token_secret_arn.value')"
if [[ -n "$HARBOR_DOMAIN" ]]; then
  CORE_URL="https://$HARBOR_DOMAIN:$CORE_PORT"; ADMIN_URL="https://$HARBOR_DOMAIN:$ADMIN_PORT"
else
  CORE_URL="http://$HARBOR_OVERLAY:$CORE_PORT"; ADMIN_URL="http://$HARBOR_OVERLAY:$ADMIN_PORT"
fi
echo "    lighthouse=$LH_IP  harbor=$HB_IP  gateway=${GW_IP:-<fargate>}  client=$CL_IP"
echo "    lighthouse underlay=$LH_ADDR  enroll=$GW_URL  collect=$GW_COLLECT  harbor-overlay=$HARBOR_OVERLAY"
echo "    runtimes: gateway=$GATEWAY_RUNTIME  lighthouse=$LIGHTHOUSE_RUNTIME  harbor-tls=${HARBOR_DOMAIN:+ACME:$HARBOR_DOMAIN}${HARBOR_DOMAIN:-plain-http}"
echo "    trust-root signing: $TRUST_BACKEND_DESC"

# Any Fargate component (gateway and/or the SPIKE lighthouse) needs the AWS CLI + a
# container engine locally (build/push the image, populate the config secret, force the
# ECS deploy). Run the bootstrap under the same AWS creds you used for terraform
# (e.g. `aws-vault exec nebula -- bash ...`).
if [[ "$GATEWAY_RUNTIME" == "fargate" || "$LIGHTHOUSE_RUNTIME" == "fargate" ]]; then
  command -v aws >/dev/null || { echo "missing tool (a *_runtime=fargate): aws" >&2; exit 1; }
  command -v "${CONTAINER_ENGINE:-podman}" >/dev/null || command -v docker >/dev/null || {
    echo "missing container engine (a *_runtime=fargate): install podman or docker, or set CONTAINER_ENGINE" >&2; exit 1; }
fi
# harbor_domain set => we fetch the scoped Cloudflare token from Secrets Manager to wire
# harbor's ACME, which needs aws + a populated (non-placeholder) token secret.
if [[ -n "$HARBOR_DOMAIN" ]]; then
  command -v aws >/dev/null || { echo "missing tool (harbor_domain set, fetches the Cloudflare DNS token): aws" >&2; exit 1; }
  [[ -n "$CF_SECRET_ARN" ]] || { echo "harbor_domain set but the cloudflare_token_secret_arn output is empty — re-apply the app stack" >&2; exit 1; }
fi
# SPIKE: lighthouse_runtime=fargate generates the lighthouse host key OFF-box (here) and
# injects it via Secrets Manager (vs the EC2 path where it never leaves the node). The
# UDP-NLB preserve_client_ip behaviour is the thing this spike proves on a live apply.
[[ "$LIGHTHOUSE_RUNTIME" == "fargate" ]] && echo "    NOTE: lighthouse on Fargate (spike) — host key generated off-box + injected"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
LH="$LH_OVERLAY=$LH_ADDR"

# ── 0. build + distribute binaries ──────────────────────────────────────────
if [[ "$SKIP_BUILD" -eq 0 ]]; then
  echo "==> building harbor/pilot/gateway (linux/amd64, cgo-free)"
  ( cd "$ROOT" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$WORK/harbor" ./cmd/harbor \
    && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$WORK/pilot" ./cmd/pilot \
    && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$WORK/gateway" ./cmd/gateway )
  # harbor/client are always EC2; the lighthouse + gateway are EC2 nodes only under their
  # "ec2" runtime (under fargate each is a container — no VM to scp to).
  NODE_IPS=("$HB_IP" "$CL_IP")
  [[ "$LIGHTHOUSE_RUNTIME" == "ec2" && -n "$LH_IP" ]] && NODE_IPS+=("$LH_IP")
  [[ "$GATEWAY_RUNTIME" == "ec2" && -n "$GW_IP" ]] && NODE_IPS+=("$GW_IP")
  for ip in "${NODE_IPS[@]}"; do
    echo "    -> $ip"
    rcp "$WORK/harbor" "$WORK/pilot" "$WORK/gateway" "$SSH_USER@$ip:/tmp/"
    rsh "$ip" 'sudo install -m0755 /tmp/harbor /tmp/pilot /tmp/gateway /usr/local/bin/ && rm -f /tmp/harbor /tmp/pilot /tmp/gateway'
  done
fi

# ── 1. lighthouse: init ──────────────────────────────────────────────────────
# EC2: init on the box (host key never leaves it). Fargate (spike): generate the keypair
# HERE (off-box) — there is no node — and inject it via Secrets Manager in step 4.
if [[ "$LIGHTHOUSE_RUNTIME" == "ec2" ]]; then
  echo "==> [lighthouse/ec2] pilot init -am-lighthouse"
  rsh "$LH_IP" 'sudo pilot init -am-lighthouse -dir /etc/nebula >/dev/null && sudo cat /etc/nebula/host.pub' > "$WORK/lh-host.pub"
else
  echo "==> [lighthouse/fargate] generate lighthouse keypair off-box"
  "$WORK/pilot" init -am-lighthouse -dir "$WORK/lhkeys" >/dev/null
  cp "$WORK/lhkeys/host.pub" "$WORK/lh-host.pub"
fi
echo "    got lighthouse host pubkey"

# ── 2. harbor: init its OWN mesh key, with the lighthouse in static_host_map ─
echo "==> [harbor] pilot init (control-plane node key)"
rsh "$HB_IP" "set -e
  sudo tee /etc/nebula-values.yml >/dev/null <<YAML
lighthouses:
  - overlay_ip: $LH_OVERLAY
    public_addrs: [\"$LH_ADDR\"]
YAML
  sudo pilot init -dir /etc/nebula -values /etc/nebula-values.yml >/dev/null
  sudo cat /etc/nebula/host.pub" > "$WORK/hb-host.pub"
echo "    got harbor host pubkey"

# pilot init's default nebula firewall allows inbound ICMP only — fine for a data-plane
# member, but harbor SERVES core-api (8444) + the console (8445) over the overlay, so the
# mesh must be allowed to reach those TCP ports inbound (otherwise heartbeat/renew time
# out: ping works, the HTTP call is dropped). Patch the firewall BEFORE nebula starts.
echo "==> [harbor] open nebula firewall for control-plane ports (core-api 8444 + console 8445)"
rsh "$HB_IP" 'sudo python3 - /etc/nebula/config.yml <<PY
import sys
p = sys.argv[1]
lines = open(p).read().splitlines()
out, i, done = [], 0, False
while i < len(lines):
    out.append(lines[i])
    if (not done and lines[i].strip() == "proto: icmp"
            and i + 1 < len(lines) and lines[i + 1].strip().startswith("host:")):
        out.append(lines[i + 1])
        for port in (8444, 8445):
            out += ["    - port: %d" % port, "      proto: tcp", "      host: any"]
        done = True
        i += 2
        continue
    i += 1
open(p, "w").write("\n".join(out) + "\n")
print("firewall: added inbound tcp 8444+8445" if done else "firewall: PATTERN NOT FOUND (left unchanged)")
PY'

# ── 3. harbor: migrate + genesis (lighthouse + HARBOR control-plane certs) ───
echo "==> [harbor] migrate + genesis (incl. -core-pub for Harbor's control-plane cert)"
rcp "$WORK/lh-host.pub" "$SSH_USER@$HB_IP:/tmp/lh-host.pub"
rcp "$WORK/hb-host.pub" "$SSH_USER@$HB_IP:/tmp/hb-host.pub"
rsh "$HB_IP" "set -e
  mkdir -p ~/ncp
  DSN=~/ncp/harbor.db
  harbor migrate up -dsn \$DSN >/dev/null
  harbor genesis -dsn \$DSN -out ~/ncp/genesis${GENESIS_BACKEND:+ $GENESIS_BACKEND} \
    -operator-a alice -operator-b bob -pool '$POOL' \
    -lighthouse-pub /tmp/lh-host.pub -lighthouse-ip '$LH_OVERLAY' -lighthouse-addr '$LH_ADDR' \
    -core-pub /tmp/hb-host.pub -core-ip '$HARBOR_OVERLAY' -core-name harbor-core >/dev/null
  echo ok"
rcp "$SSH_USER@$HB_IP:ncp/genesis/ca.crt"             "$WORK/ca.crt"
rcp "$SSH_USER@$HB_IP:ncp/genesis/lighthouse-1.crt"   "$WORK/lighthouse-1.crt"
rcp "$SSH_USER@$HB_IP:ncp/genesis/harbor-core.crt"    "$WORK/harbor-core.crt"
rcp "$SSH_USER@$HB_IP:ncp/genesis/config-signing.pub" "$WORK/config-signing.pub"
echo "    genesis done; pulled ca.crt + lighthouse + harbor-core certs + config-signing pin"

# ── 4. lighthouse: install issued cert + start ──────────────────────────────
if [[ "$LIGHTHOUSE_RUNTIME" == "ec2" ]]; then
  echo "==> [lighthouse/ec2] install cert + start nebula"
  rcp "$WORK/ca.crt"           "$SSH_USER@$LH_IP:/tmp/ca.crt"
  rcp "$WORK/lighthouse-1.crt" "$SSH_USER@$LH_IP:/tmp/host.crt"
  rsh "$LH_IP" 'set -e
    sudo install -m0644 /tmp/ca.crt   /etc/nebula/ca.crt
    sudo install -m0644 /tmp/host.crt /etc/nebula/host.crt
    rm -f /tmp/ca.crt /tmp/host.crt
    sudo systemd-run --unit ncp-nebula --collect /usr/local/bin/nebula -config /etc/nebula/config.yml >/dev/null
    echo started'
  echo "    lighthouse nebula running (EC2)"
else
  # Fargate (spike): build/push the tun.disabled nebula image, inject ca+cert+key via
  # Secrets Manager, force the ECS deploy. The lighthouse keypair was generated in step 1.
  echo "==> [lighthouse/fargate] build+push nebula image + populate ${NAME_PREFIX}-lighthouse-config + deploy"
  bash "$ROOT/deploy/prod/fargate/build-push.sh" lighthouse
  LH_SECRET_JSON="$(jq -n \
    --rawfile ca "$WORK/ca.crt" \
    --rawfile crt "$WORK/lighthouse-1.crt" \
    --rawfile key "$WORK/lhkeys/host.key" \
    '{ca_crt_pem:$ca, host_crt_pem:$crt, host_key_pem:$key}')"
  aws secretsmanager put-secret-value --region "$TF_REGION" \
    --secret-id "${NAME_PREFIX}-lighthouse-config" --secret-string "$LH_SECRET_JSON" >/dev/null
  aws ecs update-service --region "$TF_REGION" \
    --cluster "${NAME_PREFIX}-lighthouse" --service "${NAME_PREFIX}-lighthouse" --force-new-deployment >/dev/null
  echo "    lighthouse image pushed, secret populated, ECS deployment forced (tun.disabled nebula behind the UDP NLB)"
fi

# ── 5. harbor: install control-plane cert + join the mesh ───────────────────
echo "==> [harbor] install control-plane cert + start nebula (joins the mesh at $HARBOR_OVERLAY)"
rcp "$WORK/ca.crt"          "$SSH_USER@$HB_IP:/tmp/ca.crt"
rcp "$WORK/harbor-core.crt" "$SSH_USER@$HB_IP:/tmp/host.crt"
rsh "$HB_IP" 'set -e
  sudo install -m0644 /tmp/ca.crt   /etc/nebula/ca.crt
  sudo install -m0644 /tmp/host.crt /etc/nebula/host.crt
  rm -f /tmp/ca.crt /tmp/host.crt
  sudo systemd-run --unit ncp-nebula --collect /usr/local/bin/nebula -config /etc/nebula/config.yml >/dev/null
  echo started'
echo "    harbor nebula running (control-plane node)"

# ── 6. derive this account from the client's IMDS + publish cloud-trust ──────
echo "==> deriving AWS account/role/region from the client IMDS + publishing cloud-trust"
IMDS="$(rsh "$CL_IP" 'set -e
  T=$(curl -sX PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
  DOC=$(curl -s -H "X-aws-ec2-metadata-token: $T" http://169.254.169.254/latest/dynamic/instance-identity/document)
  ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $T" http://169.254.169.254/latest/meta-data/iam/security-credentials/)
  echo "$DOC" | tr -d "\n"; echo; echo "$ROLE"')"
ACCOUNT="$(jq -r .accountId <<<"$(head -n1 <<<"$IMDS")")"
REGION="$(jq -r .region    <<<"$(head -n1 <<<"$IMDS")")"
ROLE="$(tail -n1 <<<"$IMDS")"
echo "    account=$ACCOUNT region=$REGION role=$ROLE"
rsh "$HB_IP" "set -e
  cat > ~/ncp/cloudtrust.json <<JSON
{
  \"default_groups\": [\"fleet\"],
  \"aws\": [
    { \"account\": \"$ACCOUNT\",
      \"arn_patterns\": [\"arn:aws:sts::$ACCOUNT:assumed-role/$ROLE/*\"],
      \"groups\": [\"workloads\"],
      \"auto_issue\": true }
  ]
}
JSON
  harbor cloudtrust publish -dsn ~/ncp/harbor.db -config ~/ncp/cloudtrust.json \
    -operator-a alice -operator-b bob >/dev/null
  echo ok"
echo "    cloud-trust published (account $ACCOUNT -> [workloads], auto-issue)"

# ── 7. enrollment plane: OFF-MESH gateway node + Harbor's pull collector (ADR 0005) ─
# The gateway is now a SEPARATE, off-mesh node: it serves the public enroll port and
# a Harbor-only mTLS collect port over its LOCAL queue, and initiates nothing. Harbor
# PULLS from it (re-verifying every candidate), issues, and pushes results back. mTLS
# is leaf-pinned: each side self-signs, the peer pins the leaf (no CA).
GW_PORT="${GW_URL##*:}"
COLLECT_PORT="${GW_COLLECT##*:}"

echo "==> [harbor] mint the collector's client identity + the shared nonce key"
rsh "$HB_IP" "set -e
  cd ~/ncp; umask 077
  [ -f hmac.b64 ] || openssl rand 32 | basenc --base64url | tr -d '=' > hmac.b64
  [ -f harbor-collect.key ] || gateway collect-keygen -cn harbor-collector \
    -cert-out harbor-collect.crt -key-out harbor-collect.key >/dev/null
  echo ok"
rcp "$SSH_USER@$HB_IP:ncp/harbor-collect.crt" "$WORK/harbor-collect.crt"  # Harbor's pinned client cert
rcp "$SSH_USER@$HB_IP:ncp/hmac.b64"           "$WORK/hmac.b64"            # shared nonce key (gateway mints, Core verifies)

if [[ "$GATEWAY_RUNTIME" == "ec2" ]]; then
  echo "==> [gateway/ec2] mint server identity + start the off-mesh gateway (enroll :$GW_PORT, collect :$COLLECT_PORT)"
  rcp "$WORK/harbor-collect.crt" "$SSH_USER@$GW_IP:/tmp/harbor-collect.crt"
  rcp "$WORK/hmac.b64"           "$SSH_USER@$GW_IP:/tmp/hmac.b64"
  rsh "$GW_IP" "set -e
    sudo install -d -o $SSH_USER -g $SSH_USER -m0750 /opt/ncp-gw
    cd /opt/ncp-gw; umask 077
    [ -f gw-collect.key ] || gateway collect-keygen -cn gateway-1 -cert-out gw-collect.crt -key-out gw-collect.key >/dev/null
    [ -f qkey.b64 ] || openssl rand 32 | basenc --base64url | tr -d '=' > qkey.b64
    install -m0644 /tmp/harbor-collect.crt harbor-collect.crt
    install -m0644 /tmp/hmac.b64 hmac.b64; rm -f /tmp/harbor-collect.crt /tmp/hmac.b64
    sudo systemctl reset-failed ncp-gateway 2>/dev/null || true
    sudo systemd-run --uid=$SSH_USER --gid=$SSH_USER --unit ncp-gateway --collect --working-directory=/opt/ncp-gw /usr/local/bin/gateway \
      -insecure -addr 0.0.0.0:$GW_PORT -hmac-key /opt/ncp-gw/hmac.b64 \
      -queue-dsn /opt/ncp-gw/queue.db -queue-key /opt/ncp-gw/qkey.b64 \
      -collect-addr 0.0.0.0:$COLLECT_PORT -collect-cert /opt/ncp-gw/gw-collect.crt \
      -collect-key /opt/ncp-gw/gw-collect.key -harbor-client-cert /opt/ncp-gw/harbor-collect.crt >/dev/null
    cat gw-collect.crt" > "$WORK/gw-collect.crt"
  echo "    gateway up (off-mesh EC2 node; public enroll + Harbor-only collect)"
else
  # Fargate: no node to start. Mint the gateway's server identity + queue key (on
  # harbor — it has the gateway binary), build/push the image, populate the config
  # secret with the genesis material, and roll the ECS service onto it.
  echo "==> [gateway/fargate] mint server identity + queue key (on harbor)"
  rsh "$HB_IP" "set -e
    cd ~/ncp; umask 077
    [ -f gw-collect.key ] || gateway collect-keygen -cn gateway-1 -cert-out gw-collect.crt -key-out gw-collect.key >/dev/null
    [ -f gw-qkey.b64 ] || openssl rand 32 | basenc --base64url | tr -d '=' > gw-qkey.b64
    echo ok"
  rcp "$SSH_USER@$HB_IP:ncp/gw-collect.crt" "$WORK/gw-collect.crt"
  rcp "$SSH_USER@$HB_IP:ncp/gw-collect.key" "$WORK/gw-collect.key"
  rcp "$SSH_USER@$HB_IP:ncp/gw-qkey.b64"    "$WORK/gw-qkey.b64"

  echo "==> [gateway/fargate] build + push the gateway image to ECR"
  bash "$ROOT/deploy/prod/fargate/build-push.sh" gateway

  echo "==> [gateway/fargate] populate the config secret ${NAME_PREFIX}-gateway-config + force the ECS deploy"
  SECRET_JSON="$(jq -n \
    --rawfile hmac "$WORK/hmac.b64" \
    --rawfile qkey "$WORK/gw-qkey.b64" \
    --rawfile cert "$WORK/gw-collect.crt" \
    --rawfile key  "$WORK/gw-collect.key" \
    --rawfile hcli "$WORK/harbor-collect.crt" \
    '{hmac_key_b64:($hmac|rtrimstr("\n")), queue_key_b64:($qkey|rtrimstr("\n")),
      collect_cert_pem:$cert, collect_key_pem:$key, harbor_client_pem:$hcli}')"
  aws secretsmanager put-secret-value --region "$TF_REGION" \
    --secret-id "${NAME_PREFIX}-gateway-config" --secret-string "$SECRET_JSON" >/dev/null
  aws ecs update-service --region "$TF_REGION" \
    --cluster "${NAME_PREFIX}-gateway" --service "${NAME_PREFIX}-gateway" --force-new-deployment >/dev/null
  echo "    gateway image pushed, secret populated, ECS deployment forced (off-mesh Fargate; NLB enroll + Harbor-only collect)"
fi

echo "==> [harbor] register the gateway + start the pull collector"
rcp "$WORK/gw-collect.crt" "$SSH_USER@$HB_IP:/tmp/gw-collect.crt"
rsh "$HB_IP" "set -e
  cd ~/ncp
  DSN=~/ncp/harbor.db; G=~/ncp/genesis
  install -m0644 /tmp/gw-collect.crt gw-collect.crt; rm -f /tmp/gw-collect.crt
  # Idempotent register: add only if this URL isn't already listed, then VERIFY it is —
  # do NOT swallow a failed registration (a collector with zero gateways drains nothing).
  if ! harbor gateway list -dsn \$DSN 2>/dev/null | grep -Fq '$GW_COLLECT'; then
    harbor gateway add -dsn \$DSN -name gw1 -url '$GW_COLLECT' -cert ~/ncp/gw-collect.crt -actor alice
  fi
  harbor gateway list -dsn \$DSN 2>/dev/null | grep -Fq '$GW_COLLECT' \
    || { echo 'FATAL: gateway gw1 ($GW_COLLECT) not registered with harbor — the collector would pull nothing' >&2; exit 1; }
  sudo systemctl reset-failed ncp-collect ncp-core ncp-admin 2>/dev/null || true
  # Run AS ec2-user so harbor.db stays ec2-user-owned (CLI/console can write results).
  sudo systemd-run --uid=$SSH_USER --gid=$SSH_USER --unit ncp-collect --collect /usr/local/bin/harbor collect -pool '$POOL' \
    -dsn \$DSN -ca-cert \$G/ca.crt $SIGN_BACKEND \
    -hmac-key ~/ncp/hmac.b64 -lighthouse '$LH' -cloudtrust-db \
    -client-cert ~/ncp/harbor-collect.crt -client-key ~/ncp/harbor-collect.key >/dev/null
  echo registered"
echo "    gateway registered + collector pulling (attestation enabled)"

# imac (off-cloud, no AWS identity) joins via a join key with manual approval.
echo "==> [harbor] create the imac join key"
IMAC_KEY="$(rsh "$HB_IP" "harbor joinkey create -dsn ~/ncp/harbor.db -name imac -groups laptops 2>/dev/null | grep -o 'njk_[A-Za-z0-9_-]*' || true")"

# ── 8. harbor: core-api (renew/heartbeat) + admin console (SAML or mock-IdP) ─
# Edge TLS: when harbor_domain is set, fetch the scoped Cloudflare token (Secrets Manager)
# and deliver it to the box as a 0600 file (piped over ssh stdin — never on a command line),
# prep the ACME cert cache (~/ncp/acme, on the CMK-encrypted root EBS so it survives reboots),
# and build the shared -acme-* flags for core-api + admin-api. Both processes share the cache
# dir + domain; certmagic coordinates issuance/renewal across them via storage locks.
ACME_FLAGS=""
if [[ -n "$HARBOR_DOMAIN" ]]; then
  echo "==> [harbor] deliver the Cloudflare DNS token + prep the ACME cert cache (~/ncp/acme)"
  CF_TOKEN="$(aws secretsmanager get-secret-value --region "$TF_REGION" --secret-id "$CF_SECRET_ARN" --query SecretString --output text)"
  [[ -n "$CF_TOKEN" && "$CF_TOKEN" != "REPLACE_WITH_SCOPED_CLOUDFLARE_DNS_TOKEN" ]] \
    || { echo "FATAL: Cloudflare token secret is empty/placeholder — populate it first: aws secretsmanager put-secret-value --region $TF_REGION --secret-id $CF_SECRET_ARN --secret-string <scoped-Zone.DNS:Edit-token>" >&2; exit 1; }
  # Write to the SAME literal path the -acme-cloudflare-token-file flag uses (so they can't
  # diverge), and chmod 600 explicitly — `cat >` truncates but does not re-permission an
  # existing file, so a re-run must not leave a looser mode on this credential.
  printf '%s' "$CF_TOKEN" | rsh "$HB_IP" "umask 077; mkdir -p /home/$SSH_USER/ncp/acme; cat > /home/$SSH_USER/ncp/cf-token && chmod 600 /home/$SSH_USER/ncp/cf-token"
  ACME_FLAGS="-acme-domain $HARBOR_DOMAIN -acme-cloudflare-token-file /home/$SSH_USER/ncp/cf-token -acme-cache /home/$SSH_USER/ncp/acme"
  [[ -n "$ACME_EMAIL" ]] && ACME_FLAGS="$ACME_FLAGS -acme-email $ACME_EMAIL"
  [[ "$ACME_STAGING" == "true" ]] && ACME_FLAGS="$ACME_FLAGS -acme-staging"
  echo "    harbor will serve HTTPS for $HARBOR_DOMAIN (core-api :$CORE_PORT + console :$ADMIN_PORT) via Let's Encrypt$( [[ "$ACME_STAGING" == "true" ]] && echo ' [STAGING CA]')"
fi
# Console IdP (ADR 0007 Phase 3): default to the in-process DEV mock IdP so a PoC without an IdP
# still works. When the operator supplies real Entra SAML inputs (env vars), authenticate admins
# against the real SAML IdP in PRODUCTION posture instead, delivering the SP signing keypair as
# 0600/0644 files over ssh stdin (never on argv), mirroring the Cloudflare token. Set:
#   SAML_METADATA_URL   (or SAML_METADATA_FILE)  — Entra App Federation Metadata
#   SAML_SP_KEY_FILE  +  SAML_SP_CERT_FILE        — the STABLE SP signing keypair (local PEM paths)
#   SAML_ROLE_MAP                                 — e.g. '<entra-admin-group-guid>=admin;<ops-guid>=operator' (';' between groups)
#   SAML_ENTITY_ID      (optional)                — SP entity id (defaults to the SP metadata URL)
#   SAML_GROUPS_ATTR    (optional)                — IdP group-claim name (defaults to the Entra claim URI)
IDP_FLAGS="-mock-idp -mock-idp-addr $HARBOR_OVERLAY:$MOCK_IDP_PORT -environment development"
if [[ -n "${SAML_METADATA_URL:-}" || -n "${SAML_METADATA_FILE:-}" ]]; then
  echo "==> [harbor] wire the console to real Entra SAML (production posture)"
  # SAML needs HTTPS: the cross-site ACS cookie is SameSite=None => Secure (set by -environment
  # production), so a plain-HTTP overlay console can never complete login. base-url ($ADMIN_URL) is
  # HTTPS only when the mesh domain (ACME) is set — refuse rather than launch a silently-broken SSO.
  [[ -n "$HARBOR_DOMAIN" ]] || { echo "FATAL: SAML requires HTTPS, but the console would serve plain HTTP at $ADMIN_URL (mesh_name/mesh_domain unset). Set mesh_name + mesh_domain so harbor serves HTTPS via ACME, then re-run." >&2; exit 1; }
  [[ -n "${SAML_SP_KEY_FILE:-}"  && -f "${SAML_SP_KEY_FILE:-}"  ]] || { echo "FATAL: SAML requested but SAML_SP_KEY_FILE is unset/missing (the STABLE SP signing key PEM)" >&2; exit 1; }
  [[ -n "${SAML_SP_CERT_FILE:-}" && -f "${SAML_SP_CERT_FILE:-}" ]] || { echo "FATAL: SAML requested but SAML_SP_CERT_FILE is unset/missing (the SP signing cert PEM)" >&2; exit 1; }
  [[ -n "${SAML_ROLE_MAP:-}" ]] || { echo "FATAL: SAML requested but SAML_ROLE_MAP is unset (e.g. '<entra-admin-group-guid>=admin') — without it every SSO user lands as viewer" >&2; exit 1; }
  # Deliver the SP keypair (key 0600, cert 0644) — bytes preserved via ssh stdin, never argv.
  rsh "$HB_IP" "umask 077; mkdir -p /home/$SSH_USER/ncp/saml; cat > /home/$SSH_USER/ncp/saml/sp.key && chmod 600 /home/$SSH_USER/ncp/saml/sp.key" < "$SAML_SP_KEY_FILE"
  rsh "$HB_IP" "cat > /home/$SSH_USER/ncp/saml/sp.crt && chmod 644 /home/$SSH_USER/ncp/saml/sp.crt" < "$SAML_SP_CERT_FILE"
  # URLs/role-map are single-quoted so the remote shell keeps ';', '&', '?' literal (not command/glob).
  IDP_FLAGS="-saml-sp-key /home/$SSH_USER/ncp/saml/sp.key -saml-sp-cert /home/$SSH_USER/ncp/saml/sp.crt -role-map '$SAML_ROLE_MAP' -environment production"
  if [[ -n "${SAML_METADATA_URL:-}" ]]; then
    IDP_FLAGS="$IDP_FLAGS -saml-idp-metadata-url '$SAML_METADATA_URL'"
  else
    rsh "$HB_IP" "cat > /home/$SSH_USER/ncp/saml/idp-metadata.xml && chmod 644 /home/$SSH_USER/ncp/saml/idp-metadata.xml" < "$SAML_METADATA_FILE"
    IDP_FLAGS="$IDP_FLAGS -saml-idp-metadata-file /home/$SSH_USER/ncp/saml/idp-metadata.xml"
  fi
  [[ -n "${SAML_ENTITY_ID:-}" ]] && IDP_FLAGS="$IDP_FLAGS -saml-entity-id '$SAML_ENTITY_ID'"
  # Entra emits the group claim under its long URI name, but harbor's -saml-groups-attr defaults to
  # "groups" — mismatch => NO group matches the role-map => every SSO user lands as viewer. Default
  # to the Entra claim name (override SAML_GROUPS_ATTR for a different IdP or a renamed claim).
  SAML_GROUPS_ATTR="${SAML_GROUPS_ATTR:-http://schemas.microsoft.com/ws/2008/06/identity/claims/groups}"
  IDP_FLAGS="$IDP_FLAGS -saml-groups-attr '$SAML_GROUPS_ATTR'"
  # The SP advertises ACS/metadata/entity-id derived from base-url ($ADMIN_URL); print the EXACT
  # values (incl. the :$ADMIN_PORT port) the operator must register in the Entra Enterprise App so
  # they can't drift. Entity ID is the -saml-entity-id override if set, else the SP metadata URL.
  SAML_ENTITY="${SAML_ENTITY_ID:-$ADMIN_URL/admin/v1/auth/saml/metadata}"
  echo "    console IdP: Entra SAML [production]; SP keypair delivered (0600); role-map=$SAML_ROLE_MAP"
  echo "    register these EXACT values in the Entra Enterprise App (match them — note the :$ADMIN_PORT port):"
  echo "      Identifier (Entity ID):  $SAML_ENTITY"
  echo "      Reply URL (ACS):         $ADMIN_URL/admin/v1/auth/saml/acs"
  echo "      SP metadata (reference): $ADMIN_URL/admin/v1/auth/saml/metadata"
  echo "      browser must reach $HARBOR_DOMAIN (mesh-only console) — be an enrolled mesh member resolving it to $HARBOR_OVERLAY"
else
  echo "    console IdP: DEV mock-IdP (export SAML_METADATA_URL + SAML_SP_KEY_FILE + SAML_SP_CERT_FILE + SAML_ROLE_MAP for real Entra SAML)"
fi
# The console-access hints printed at the end adapt to the IdP actually wired above: the mock IdP
# needs its port tunnelled too, real SAML redirects the browser to Entra instead.
if [[ "$IDP_FLAGS" == *"-mock-idp"* ]]; then
  CONSOLE_LOGIN_NOTE="mock-IdP login"; IDP_TUNNEL=" -L $MOCK_IDP_PORT:$HARBOR_OVERLAY:$MOCK_IDP_PORT"
else
  CONSOLE_LOGIN_NOTE="Entra SAML login (browser redirects to Entra; base-url/ACS must be reachable — see the SAML runbook)"; IDP_TUNNEL=""
fi
echo "==> [harbor] start core-api + admin console on the overlay ($HARBOR_OVERLAY, mesh-only)"
rsh "$HB_IP" "set -e
  cd ~/ncp
  DSN=~/ncp/harbor.db; QDSN=~/ncp/queue.db; G=~/ncp/genesis
  # core-api runs as $SSH_USER but -host-cert lives in /etc/nebula (root, mode 0700 from
  # pilot init); make the dir traversable so it can read the 0644 host.crt (host.key
  # stays 0600 root). Without this core-api crashes at boot with 'permission denied'.
  sudo chmod o+rx /etc/nebula
  # admin-api needs a local queue key (issuance/approval queue); the bootstrap never minted
  # it, so ncp-admin (the console + its IdP) crashed at boot. Mint it here, like hmac.b64.
  umask 077; [ -f ~/ncp/queue.b64 ] || openssl rand 32 | basenc --base64url | tr -d '=' > ~/ncp/queue.b64
  # core-api: renew + heartbeat over the mesh, verifying its own control-plane cert at boot.
  sudo systemd-run --uid=$SSH_USER --gid=$SSH_USER --unit ncp-core --collect /usr/local/bin/harbor core-api \
    -dsn \$DSN -ca-cert \$G/ca.crt $SIGN_BACKEND \
    -pool '$POOL' -lighthouse '$LH' -host-cert /etc/nebula/host.crt \
    -addr $HARBOR_OVERLAY:$CORE_PORT${ACME_FLAGS:+ $ACME_FLAGS} >/dev/null
  # admin console: issuance mode (so it can approve enrollments) + dev mock-IdP login.
  sudo systemd-run --uid=$SSH_USER --gid=$SSH_USER --unit ncp-admin --collect /usr/local/bin/harbor admin-api \
    -dsn \$DSN -ca-cert \$G/ca.crt $SIGN_BACKEND \
    -hmac-key ~/ncp/hmac.b64 -queue-dsn \$QDSN -queue-key ~/ncp/queue.b64 -pool '$POOL' \
    -addr $HARBOR_OVERLAY:$ADMIN_PORT -base-url $ADMIN_URL \
    $IDP_FLAGS${ACME_FLAGS:+ $ACME_FLAGS} >/dev/null
  echo ok"
cp "$WORK/config-signing.pub" "$ROOT/deploy/prod/terraform/app/config-signing.pub"  # gitignored; the pin for clients
echo "    core-api + admin console up"

# Client-facing hints adapt to harbor's TLS posture (computed CORE_URL/ADMIN_URL above).
if [[ -n "$HARBOR_DOMAIN" ]]; then
  HARBOR_TLS_NOTE="  [HTTPS via Let's Encrypt for $HARBOR_DOMAIN — operators must resolve it to $HARBOR_OVERLAY for mesh members]"
  TUNNEL_NOTE="   NOTE: harbor serves the LE cert for $HARBOR_DOMAIN, so map it to 127.0.0.1 (e.g. /etc/hosts) and browse $ADMIN_URL through the tunnel (the cert won't match the raw overlay IP)."
  # Leading newline so the DEFAULT (empty) path leaves the cloud-client block byte-identical.
  CLIENT_DNS_NOTE="
   # NOTE: -core is https://$HARBOR_DOMAIN — the client must resolve $HARBOR_DOMAIN to $HARBOR_OVERLAY first
   #       (DNS, or: echo '$HARBOR_OVERLAY $HARBOR_DOMAIN' | sudo tee -a /etc/hosts) or supervise can't renew over HTTPS."
else
  HARBOR_TLS_NOTE=""
  TUNNEL_NOTE="   then browse $ADMIN_URL through the tunnel."
  CLIENT_DNS_NOTE=""
fi

cat <<EOF

────────────────────────────────────────────────────────────────────────────
 GENESIS BOOTSTRAP COMPLETE  (control plane + data plane)
────────────────────────────────────────────────────────────────────────────
 Gateway (off-mesh): enroll(public) $GW_URL  ·  enroll(in-VPC) $GW_URL_INTERNAL
                     collect $GW_COLLECT  (Harbor-only, mTLS) — Harbor PULLS it, gateway
                     initiates nothing, no mesh identity (ADR 0005). In-VPC clients use the
                     INTERNAL enroll URL (a public NLB isn't reachable from inside the VPC).
 Lighthouse        : $LH_OVERLAY @ $LH_ADDR  (pool $POOL)
 Harbor (mesh)     : $HARBOR_OVERLAY  — core-api :$CORE_PORT, console :$ADMIN_PORT (mesh-only)$HARBOR_TLS_NOTE
 Config-signing pin: deploy/prod/terraform/app/config-signing.pub  (give this to clients)
 Cloud-trust       : account $ACCOUNT / role $ROLE -> groups [workloads], auto-issue

 Enroll the CLOUD CLIENT — KEYLESS via aws-sigv4 attestation (its IAM role). It's IN the
 VPC, so it enrolls via the INTERNAL gateway URL:
   scp -i $SSH_KEY deploy/prod/terraform/app/config-signing.pub $SSH_USER@$CL_IP:/tmp/
   ssh -i $SSH_KEY $SSH_USER@$CL_IP \\
     'sudo pilot enroll -dir /etc/nebula -gateway $GW_URL_INTERNAL -aws-sigv4 -region $REGION \\
        -config-pub /tmp/config-signing.pub -name aws-client && \\
      sudo systemd-run --unit ncp-nebula --collect pilot supervise -dir /etc/nebula \\
        -config /etc/nebula/config.yml -core $CORE_URL -config-pub /tmp/config-signing.pub'
   # auto-issued (account is trusted, auto_issue=true) — no join key involved.$CLIENT_DNS_NOTE

 Enroll the OFF-CLOUD iMac — join key, MANUAL approval (uses the PUBLIC enroll URL):
   imac join secret: ${IMAC_KEY:-<existed already; re-create with: harbor joinkey create -name imac -groups laptops>}
   pilot enroll -dir ~/.nebula -gateway $GW_URL -join-key ${IMAC_KEY:-<imac-key>} \\
     -config-pub deploy/prod/terraform/app/config-signing.pub -name imac
   # approve it in the CONSOLE (below) or via CLI:
   ssh -i $SSH_KEY $SSH_USER@$HB_IP \\
     'EID=\$(harbor enroll pending -dsn ~/ncp/harbor.db | awk "/imac/{print \\\$1}"); \\
      harbor enroll approve \$EID -approver alice -dsn ~/ncp/harbor.db \\
        -ca-cert ~/ncp/genesis/ca.crt $APPROVE_BACKEND \\
        -hmac-key ~/ncp/hmac.b64 -queue-dsn ~/ncp/queue.db -queue-key ~/ncp/queue.b64 \\
        -pool $POOL -lighthouse "$LH"'
   # then re-run the iMac enroll to fetch the bundle; supervise with -core as above.

 Open the ADMIN CONSOLE (mesh-only — reach it from an enrolled mesh member, e.g.
 the iMac once it has joined, in a browser):
     $ADMIN_URL    ($CONSOLE_LOGIN_NOTE; approve enrollments, see
                                            fleet health, policy, cloud-trust, etc.)
   Off-mesh convenience (out-of-band admin path): SSH-tunnel the console —
     ssh -i $SSH_KEY -L $ADMIN_PORT:$HARBOR_OVERLAY:$ADMIN_PORT$IDP_TUNNEL $SSH_USER@$HB_IP
$TUNNEL_NOTE

 Verify: from any joined node,  ping $LH_OVERLAY  and  ping $HARBOR_OVERLAY ;
         the cloud client should appear in the console's fleet dashboard (heartbeat).
────────────────────────────────────────────────────────────────────────────
EOF
