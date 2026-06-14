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
# Requires locally: terraform, jq, go, ssh, scp, openssl  (+ aws & docker, and AWS creds
# in the env — e.g. `aws-vault exec ... -- bash ...` — when gateway_runtime=fargate).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TFDIR="$ROOT/deploy/terraform"
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
GW_URL="$(val '.gateway_url.value')"                # public enroll URL (node IP or NLB DNS)
GW_COLLECT="$(val '.gateway_collect_addr.value')"   # gateway's Harbor-facing collect URL
GATEWAY_RUNTIME="$(val '.gateway_runtime.value')"; GATEWAY_RUNTIME="${GATEWAY_RUNTIME:-ec2}"
LIGHTHOUSE_RUNTIME="$(val '.lighthouse_runtime.value')"; LIGHTHOUSE_RUNTIME="${LIGHTHOUSE_RUNTIME:-ec2}"
NAME_PREFIX="$(val '.name_prefix.value')"; NAME_PREFIX="${NAME_PREFIX:-ncp}"
TF_REGION="$(val '.region.value')"
echo "    lighthouse=$LH_IP  harbor=$HB_IP  gateway=${GW_IP:-<fargate>}  client=$CL_IP"
echo "    lighthouse underlay=$LH_ADDR  enroll=$GW_URL  collect=$GW_COLLECT  harbor-overlay=$HARBOR_OVERLAY"
echo "    runtimes: gateway=$GATEWAY_RUNTIME  lighthouse=$LIGHTHOUSE_RUNTIME"

# The EC2 lighthouse path (default) is what this orchestrator wires. The Fargate
# lighthouse is a spike whose genesis steps differ (host key generated off-box +
# injected via Secrets Manager) and aren't automated here — see deploy/fargate/README.md.
if [[ "$LIGHTHOUSE_RUNTIME" == "fargate" ]]; then
  echo "ERROR: lighthouse_runtime=fargate is not wired into this bootstrap yet (spike)." >&2
  echo "       Use lighthouse_runtime=ec2 here, or follow the lighthouse section of deploy/fargate/README.md." >&2
  exit 2
fi

# The Fargate gateway path needs the AWS CLI + docker locally (build/push the image,
# populate the config secret, force the ECS deploy). Run the bootstrap under the same
# AWS creds you used for terraform (e.g. `aws-vault exec nebula -- bash ...`).
if [[ "$GATEWAY_RUNTIME" == "fargate" ]]; then
  for t in aws docker; do command -v "$t" >/dev/null || { echo "missing tool (gateway_runtime=fargate): $t" >&2; exit 1; }; done
fi

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
LH="$LH_OVERLAY=$LH_ADDR"

# ── 0. build + distribute binaries ──────────────────────────────────────────
if [[ "$SKIP_BUILD" -eq 0 ]]; then
  echo "==> building harbor/pilot/gateway (linux/amd64, cgo-free)"
  ( cd "$ROOT" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$WORK/harbor" ./cmd/harbor \
    && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$WORK/pilot" ./cmd/pilot \
    && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$WORK/gateway" ./cmd/gateway )
  # lighthouse/harbor/client are always EC2 here; the gateway is an EC2 node only when
  # gateway_runtime=ec2 (under fargate it's a container — no VM to scp to).
  NODE_IPS=("$LH_IP" "$HB_IP" "$CL_IP")
  [[ "$GATEWAY_RUNTIME" == "ec2" && -n "$GW_IP" ]] && NODE_IPS+=("$GW_IP")
  for ip in "${NODE_IPS[@]}"; do
    echo "    -> $ip"
    rcp "$WORK/harbor" "$WORK/pilot" "$WORK/gateway" "$SSH_USER@$ip:/tmp/"
    rsh "$ip" 'sudo install -m0755 /tmp/harbor /tmp/pilot /tmp/gateway /usr/local/bin/ && rm -f /tmp/harbor /tmp/pilot /tmp/gateway'
  done
fi

# ── 1. lighthouse: init (host key never leaves the box) ─────────────────────
echo "==> [lighthouse] pilot init -am-lighthouse"
rsh "$LH_IP" 'sudo pilot init -am-lighthouse -dir /etc/nebula >/dev/null && sudo cat /etc/nebula/host.pub' > "$WORK/lh-host.pub"
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

# ── 3. harbor: migrate + genesis (lighthouse + HARBOR control-plane certs) ───
echo "==> [harbor] migrate + genesis (incl. -core-pub for Harbor's control-plane cert)"
rcp "$WORK/lh-host.pub" "$SSH_USER@$HB_IP:/tmp/lh-host.pub"
rcp "$WORK/hb-host.pub" "$SSH_USER@$HB_IP:/tmp/hb-host.pub"
rsh "$HB_IP" "set -e
  mkdir -p ~/ncp
  DSN=~/ncp/harbor.db
  harbor migrate up -dsn \$DSN >/dev/null
  harbor genesis -dsn \$DSN -out ~/ncp/genesis \
    -operator-a alice -operator-b bob -pool '$POOL' \
    -lighthouse-pub /tmp/lh-host.pub -lighthouse-ip '$LH_OVERLAY' -lighthouse-addr '$LH_ADDR' \
    -core-pub /tmp/hb-host.pub -core-ip '$HARBOR_OVERLAY' -core-name harbor-core >/dev/null
  echo ok"
rcp "$SSH_USER@$HB_IP:ncp/genesis/ca.crt"             "$WORK/ca.crt"
rcp "$SSH_USER@$HB_IP:ncp/genesis/lighthouse-1.crt"   "$WORK/lighthouse-1.crt"
rcp "$SSH_USER@$HB_IP:ncp/genesis/harbor-core.crt"    "$WORK/harbor-core.crt"
rcp "$SSH_USER@$HB_IP:ncp/genesis/config-signing.pub" "$WORK/config-signing.pub"
echo "    genesis done; pulled ca.crt + lighthouse + harbor-core certs + config-signing pin"

# ── 4. lighthouse: install issued cert + start nebula ───────────────────────
echo "==> [lighthouse] install cert + start nebula"
rcp "$WORK/ca.crt"           "$SSH_USER@$LH_IP:/tmp/ca.crt"
rcp "$WORK/lighthouse-1.crt" "$SSH_USER@$LH_IP:/tmp/host.crt"
rsh "$LH_IP" 'set -e
  sudo install -m0644 /tmp/ca.crt   /etc/nebula/ca.crt
  sudo install -m0644 /tmp/host.crt /etc/nebula/host.crt
  rm -f /tmp/ca.crt /tmp/host.crt
  sudo systemd-run --unit ncp-nebula --collect /usr/local/bin/nebula -config /etc/nebula/config.yml >/dev/null
  echo started'
echo "    lighthouse nebula running"

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
  bash "$ROOT/deploy/fargate/build-push.sh" gateway

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

echo "==> [harbor] register the gateway + start the pull collector + imac join key"
rcp "$WORK/gw-collect.crt" "$SSH_USER@$HB_IP:/tmp/gw-collect.crt"
IMAC_KEY="$(rsh "$HB_IP" "set -e
  cd ~/ncp
  DSN=~/ncp/harbor.db; G=~/ncp/genesis
  install -m0644 /tmp/gw-collect.crt gw-collect.crt; rm -f /tmp/gw-collect.crt
  harbor gateway add -dsn \$DSN -name gw1 -url '$GW_COLLECT' -cert ~/ncp/gw-collect.crt -actor alice >/dev/null 2>&1 || true
  sudo systemctl reset-failed ncp-collect ncp-core ncp-admin 2>/dev/null || true
  # Run AS ec2-user so harbor.db stays ec2-user-owned (CLI/console can write results).
  sudo systemd-run --uid=$SSH_USER --gid=$SSH_USER --unit ncp-collect --collect /usr/local/bin/harbor collect -pool '$POOL' \
    -dsn \$DSN -ca-cert \$G/ca.crt -ca-key \$G/ca.key -config-key \$G/config-signing.key \
    -hmac-key ~/ncp/hmac.b64 -lighthouse '$LH' -cloudtrust-db \
    -client-cert ~/ncp/harbor-collect.crt -client-key ~/ncp/harbor-collect.key >/dev/null
  # imac (off-cloud, no AWS identity) joins via a join key with manual approval.
  harbor joinkey create -dsn \$DSN -name imac -groups laptops 2>/dev/null | grep -o 'njk_[A-Za-z0-9_-]*' || true")"
echo "    gateway registered + collector pulling (attestation enabled)"

# ── 8. harbor: core-api (renew/heartbeat) + admin console (mock-IdP) ─────────
echo "==> [harbor] start core-api + admin console on the overlay ($HARBOR_OVERLAY, mesh-only)"
rsh "$HB_IP" "set -e
  cd ~/ncp
  DSN=~/ncp/harbor.db; QDSN=~/ncp/queue.db; G=~/ncp/genesis
  # core-api: renew + heartbeat over the mesh, verifying its own control-plane cert at boot.
  sudo systemd-run --uid=$SSH_USER --gid=$SSH_USER --unit ncp-core --collect /usr/local/bin/harbor core-api \
    -dsn \$DSN -ca-cert \$G/ca.crt -ca-key \$G/ca.key -config-key \$G/config-signing.key \
    -pool '$POOL' -lighthouse '$LH' -host-cert /etc/nebula/host.crt \
    -addr $HARBOR_OVERLAY:$CORE_PORT >/dev/null
  # admin console: issuance mode (so it can approve enrollments) + dev mock-IdP login.
  sudo systemd-run --uid=$SSH_USER --gid=$SSH_USER --unit ncp-admin --collect /usr/local/bin/harbor admin-api \
    -dsn \$DSN -ca-cert \$G/ca.crt -ca-key \$G/ca.key -config-key \$G/config-signing.key \
    -hmac-key ~/ncp/hmac.b64 -queue-dsn \$QDSN -queue-key ~/ncp/queue.b64 -pool '$POOL' \
    -addr $HARBOR_OVERLAY:$ADMIN_PORT -mock-idp -mock-idp-addr $HARBOR_OVERLAY:$MOCK_IDP_PORT \
    -base-url http://$HARBOR_OVERLAY:$ADMIN_PORT -environment development >/dev/null
  echo ok"
cp "$WORK/config-signing.pub" "$ROOT/deploy/terraform/config-signing.pub"  # gitignored; the pin for clients
echo "    core-api + admin console up"

cat <<EOF

────────────────────────────────────────────────────────────────────────────
 GENESIS BOOTSTRAP COMPLETE  (control plane + data plane)
────────────────────────────────────────────────────────────────────────────
 Gateway (off-mesh): $GW_URL  (enroll)  ·  collect $GW_COLLECT  (Harbor-only, mTLS)
                     Harbor PULLS it — the gateway initiates nothing, no mesh identity (ADR 0005)
 Lighthouse        : $LH_OVERLAY @ $LH_ADDR  (pool $POOL)
 Harbor (mesh)     : $HARBOR_OVERLAY  — core-api :$CORE_PORT, console :$ADMIN_PORT (mesh-only)
 Config-signing pin: deploy/terraform/config-signing.pub  (give this to clients)
 Cloud-trust       : account $ACCOUNT / role $ROLE -> groups [workloads], auto-issue

 Enroll the CLOUD CLIENT — KEYLESS via aws-sigv4 attestation (its IAM role):
   scp -i $SSH_KEY deploy/terraform/config-signing.pub $SSH_USER@$CL_IP:/tmp/
   ssh -i $SSH_KEY $SSH_USER@$CL_IP \\
     'sudo pilot enroll -dir /etc/nebula -gateway $GW_URL -aws-sigv4 -region $REGION \\
        -config-pub /tmp/config-signing.pub -name aws-client && \\
      sudo systemd-run --unit ncp-nebula --collect pilot supervise -dir /etc/nebula \\
        -config /etc/nebula/config.yml -core http://$HARBOR_OVERLAY:$CORE_PORT -config-pub /tmp/config-signing.pub'
   # auto-issued (account is trusted, auto_issue=true) — no join key involved.

 Enroll the OFF-CLOUD iMac — join key, MANUAL approval:
   imac join secret: ${IMAC_KEY:-<existed already; re-create with: harbor joinkey create -name imac -groups laptops>}
   pilot enroll -dir ~/.nebula -gateway $GW_URL -join-key ${IMAC_KEY:-<imac-key>} \\
     -config-pub deploy/terraform/config-signing.pub -name imac
   # approve it in the CONSOLE (below) or via CLI:
   ssh -i $SSH_KEY $SSH_USER@$HB_IP \\
     'EID=\$(harbor enroll pending -dsn ~/ncp/harbor.db | awk "/imac/{print \\\$1}"); \\
      harbor enroll approve \$EID -approver alice -dsn ~/ncp/harbor.db \\
        -ca-cert ~/ncp/genesis/ca.crt -ca-key ~/ncp/genesis/ca.key \\
        -config-key ~/ncp/genesis/config-signing.key \\
        -hmac-key ~/ncp/hmac.b64 -queue-dsn ~/ncp/queue.db -queue-key ~/ncp/queue.b64 \\
        -pool $POOL -lighthouse "$LH"'
   # then re-run the iMac enroll to fetch the bundle; supervise with -core as above.

 Open the ADMIN CONSOLE (mesh-only — reach it from an enrolled mesh member, e.g.
 the iMac once it has joined, in a browser):
     http://$HARBOR_OVERLAY:$ADMIN_PORT    (mock-IdP login; approve enrollments, see
                                            fleet health, policy, cloud-trust, etc.)
   Off-mesh convenience (out-of-band admin path): SSH-tunnel both ports —
     ssh -i $SSH_KEY -L $ADMIN_PORT:$HARBOR_OVERLAY:$ADMIN_PORT -L $MOCK_IDP_PORT:$HARBOR_OVERLAY:$MOCK_IDP_PORT $SSH_USER@$HB_IP
   then browse http://$HARBOR_OVERLAY:$ADMIN_PORT through the tunnel.

 Verify: from any joined node,  ping $LH_OVERLAY  and  ping $HARBOR_OVERLAY ;
         the cloud client should appear in the console's fleet dashboard (heartbeat).
────────────────────────────────────────────────────────────────────────────
EOF
