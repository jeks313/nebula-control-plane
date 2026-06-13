#!/usr/bin/env bash
# Genesis bootstrap for the test topology (deploy/terraform). Run from your own
# machine (the iMac) after `terraform apply`. It is an SSH orchestrator — it does
# NOT need to run on any node. Steps:
#
#   0. build harbor/pilot/gateway for linux/amd64 and scp them to the 3 nodes
#   1. lighthouse: pilot init -am-lighthouse  (host key stays on the lighthouse)
#   2. harbor:     migrate + genesis (CA + config-signing key + lighthouse cert)
#   3. lighthouse: install the issued ca.crt + lighthouse cert; start nebula
#   4. harbor:     start the enrollment plane (gateway + enroll worker) and create
#                  the join keys (aws-client = auto-issue, imac = manual approval)
#
# It then prints the gateway URL, the config-signing public key (the pin clients
# verify bundles against), and the join secrets, plus the exact enroll commands
# for the cloud client and the off-cloud iMac.
#
# Scope: this stands up the ENROLLMENT plane. Bringing Harbor itself onto the mesh
# and running core-api (renew/heartbeat) over the overlay is the lifecycle follow-
# on (see the note at the end) — not needed to enroll + ping.
#
# Requires locally: terraform, jq, go, ssh, scp, openssl.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TFDIR="$ROOT/deploy/terraform"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/absolute.pub}"   # public key selecting the agent identity (private may be passphrase-locked in the agent)
SSH_USER="${SSH_USER:-ec2-user}"
SKIP_BUILD=0
[[ "${1:-}" == "--skip-build" ]] && SKIP_BUILD=1

# Overlay pool + lighthouse overlay IP. IMPORTANT: do NOT use 100.64.0.0/10
# (CGNAT) if any host also runs Tailscale — Tailscale installs an nftables rule
# that drops 100.64.0.0/10 traffic on non-tailscale0 interfaces, which silently
# kills the nebula data plane. Default to a private range that won't collide.
POOL="${POOL:-10.44.0.0/16}"
LH_OVERLAY="${LH_OVERLAY:-10.44.0.1}"

for t in terraform jq go ssh scp openssl; do command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }; done
[[ -f "$SSH_KEY" ]] || { echo "ssh private key not found: $SSH_KEY (set SSH_KEY=...)" >&2; exit 1; }

SSH_OPTS=(-i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes)
rsh() { local host="$1"; shift; ssh "${SSH_OPTS[@]}" "$SSH_USER@$host" "$@"; }
rcp() { scp "${SSH_OPTS[@]}" "$@"; }

echo "==> reading terraform outputs"
OUT="$(terraform -chdir="$TFDIR" output -json)"
LH_IP="$(jq -r '.public_ips.value.lighthouse' <<<"$OUT")"
HB_IP="$(jq -r '.public_ips.value.harbor' <<<"$OUT")"
CL_IP="$(jq -r '.public_ips.value.client' <<<"$OUT")"
LH_ADDR="$(jq -r '.lighthouse_addr.value' <<<"$OUT")"
GW_URL="$(jq -r '.gateway_url.value' <<<"$OUT")"
echo "    lighthouse=$LH_IP  harbor=$HB_IP  client=$CL_IP"
echo "    lighthouse underlay=$LH_ADDR  gateway=$GW_URL"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# ── 0. build + distribute binaries ──────────────────────────────────────────
if [[ "$SKIP_BUILD" -eq 0 ]]; then
  echo "==> building harbor/pilot/gateway (linux/amd64, cgo-free)"
  ( cd "$ROOT" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$WORK/harbor" ./cmd/harbor \
    && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$WORK/pilot" ./cmd/pilot \
    && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$WORK/gateway" ./cmd/gateway )
  for ip in "$LH_IP" "$HB_IP" "$CL_IP"; do
    echo "    -> $ip"
    rcp "$WORK/harbor" "$WORK/pilot" "$WORK/gateway" "$SSH_USER@$ip:/tmp/"
    rsh "$ip" 'sudo install -m0755 /tmp/harbor /tmp/pilot /tmp/gateway /usr/local/bin/ && rm -f /tmp/harbor /tmp/pilot /tmp/gateway'
  done
fi

# ── 1. lighthouse: init (host key never leaves the box) ─────────────────────
echo "==> [lighthouse] pilot init -am-lighthouse"
rsh "$LH_IP" 'sudo pilot init -am-lighthouse -dir /etc/nebula >/dev/null && sudo cat /etc/nebula/host.pub' > "$WORK/lh-host.pub"
echo "    got lighthouse host pubkey"

# ── 2. harbor: migrate + genesis ────────────────────────────────────────────
echo "==> [harbor] migrate + genesis"
rcp "$WORK/lh-host.pub" "$SSH_USER@$HB_IP:/tmp/lh-host.pub"
rsh "$HB_IP" "set -e
  mkdir -p ~/ncp
  DSN=~/ncp/harbor.db
  harbor migrate up -dsn \$DSN >/dev/null
  harbor genesis -dsn \$DSN -out ~/ncp/genesis \
    -operator-a alice -operator-b bob \
    -pool '$POOL' -lighthouse-pub /tmp/lh-host.pub -lighthouse-ip '$LH_OVERLAY' -lighthouse-addr '$LH_ADDR' >/dev/null
  echo ok"
# pull the trust artifacts we need to distribute
rcp "$SSH_USER@$HB_IP:ncp/genesis/ca.crt"              "$WORK/ca.crt"
rcp "$SSH_USER@$HB_IP:ncp/genesis/lighthouse-1.crt"    "$WORK/lighthouse-1.crt"
rcp "$SSH_USER@$HB_IP:ncp/genesis/config-signing.pub"  "$WORK/config-signing.pub"
echo "    genesis done; pulled ca.crt + lighthouse cert + config-signing pin"

# ── 3. lighthouse: install issued cert + start nebula ───────────────────────
echo "==> [lighthouse] install cert + start nebula"
rcp "$WORK/ca.crt"           "$SSH_USER@$LH_IP:/tmp/ca.crt"
rcp "$WORK/lighthouse-1.crt" "$SSH_USER@$LH_IP:/tmp/host.crt"
rsh "$LH_IP" 'set -e
  sudo install -m0644 /tmp/ca.crt   /etc/nebula/ca.crt
  sudo install -m0644 /tmp/host.crt /etc/nebula/host.crt
  rm -f /tmp/ca.crt /tmp/host.crt
  sudo systemd-run --unit ncp-nebula --collect /usr/local/bin/nebula -config /etc/nebula/config.yml >/dev/null
  echo started'
echo "    lighthouse nebula running (systemd unit ncp-nebula)"

# ── 4. harbor: enrollment plane + join keys ─────────────────────────────────
echo "==> [harbor] start gateway + enroll worker, create join keys"
JOIN="$(rsh "$HB_IP" "set -e
  cd ~/ncp
  DSN=~/ncp/harbor.db
  QDSN=~/ncp/queue.db
  G=~/ncp/genesis
  umask 077
  [ -f hmac.b64 ]  || openssl rand 32 | basenc --base64url | tr -d '=' > hmac.b64
  [ -f queue.b64 ] || openssl rand 32 | basenc --base64url | tr -d '=' > queue.b64
  LH="$LH_OVERLAY=$LH_ADDR"
  # (re)start the enrollment plane as transient systemd units, running AS
  # ec2-user (neither gateway nor worker needs root). This keeps harbor.db +
  # queue.db ec2-user-owned, so a plain (non-sudo) 'harbor enroll approve' can
  # write the issued-bundle result. --uid/--gid set the process user; sudo is
  # only to create the system transient unit.
  sudo systemctl reset-failed ncp-gateway ncp-worker 2>/dev/null || true
  sudo systemd-run --uid=$SSH_USER --gid=$SSH_USER --unit ncp-gateway --collect /usr/local/bin/gateway \
    -addr 0.0.0.0:${GW_URL##*:} -hmac-key ~/ncp/hmac.b64 -queue-dsn \$QDSN -queue-key ~/ncp/queue.b64 >/dev/null
  sudo systemd-run --uid=$SSH_USER --gid=$SSH_USER --unit ncp-worker --collect /usr/local/bin/harbor enroll worker -pool '$POOL' \
    -dsn \$DSN -ca-cert \$G/ca.crt -ca-key \$G/ca.key -config-key \$G/config-signing.key \
    -hmac-key ~/ncp/hmac.b64 -queue-dsn \$QDSN -queue-key ~/ncp/queue.b64 -lighthouse \"\$LH\" >/dev/null
  # join keys (idempotent-ish: ignore 'already exists')
  AWS=\$(harbor joinkey create -dsn \$DSN -name aws-client -groups workloads -auto-issue -quota 100 2>/dev/null | grep -o 'njk_[A-Za-z0-9_-]*' || true)
  IMAC=\$(harbor joinkey create -dsn \$DSN -name imac -groups laptops 2>/dev/null | grep -o 'njk_[A-Za-z0-9_-]*' || true)
  echo \"AWS=\$AWS\"; echo \"IMAC=\$IMAC\"")"
AWS_KEY="$(grep -o 'AWS=njk_[A-Za-z0-9_-]*' <<<"$JOIN" | cut -d= -f2 || true)"
IMAC_KEY="$(grep -o 'IMAC=njk_[A-Za-z0-9_-]*' <<<"$JOIN" | cut -d= -f2 || true)"
cp "$WORK/config-signing.pub" "$ROOT/deploy/terraform/config-signing.pub"  # gitignored; the pin for clients

cat <<EOF

────────────────────────────────────────────────────────────────────────────
 GENESIS BOOTSTRAP COMPLETE
────────────────────────────────────────────────────────────────────────────
 Gateway URL      : $GW_URL
 Lighthouse       : $LH_OVERLAY @ $LH_ADDR  (pool $POOL)
 Config-signing pin: deploy/terraform/config-signing.pub  (give this to clients)

 Join secrets (SENSITIVE — shown only here, on your terminal):
   aws-client (auto-issue): ${AWS_KEY:-<existed already; re-create to see it>}
   imac       (manual approval): ${IMAC_KEY:-<existed already; re-create to see it>}

 Enroll the CLOUD CLIENT (auto-issues):
   scp -i $SSH_KEY deploy/terraform/config-signing.pub $SSH_USER@$CL_IP:/tmp/
   ssh -i $SSH_KEY $SSH_USER@$CL_IP \\
     'sudo pilot enroll -dir /etc/nebula -gateway $GW_URL \\
        -join-key ${AWS_KEY:-<aws-key>} -config-pub /tmp/config-signing.pub -name aws-client && \\
      sudo systemd-run --unit ncp-nebula --collect pilot supervise -config /etc/nebula/config.yml'

 Enroll the OFF-CLOUD iMac (waits for manual approval):
   pilot enroll -dir ~/.nebula -gateway $GW_URL \\
     -join-key ${IMAC_KEY:-<imac-key>} -config-pub deploy/terraform/config-signing.pub -name imac
   # then APPROVE it on harbor (plain ec2-user; the worker runs as ec2-user so
   # queue.db is ec2-user-owned and the issued-bundle result writes cleanly):
   ssh -i $SSH_KEY $SSH_USER@$HB_IP \\
     'EID=\$(harbor enroll pending -dsn ~/ncp/harbor.db | awk "/imac/{print \\\$1}"); \\
      harbor enroll approve \$EID -approver alice -dsn ~/ncp/harbor.db \\
        -ca-cert ~/ncp/genesis/ca.crt -ca-key ~/ncp/genesis/ca.key \\
        -config-key ~/ncp/genesis/config-signing.key \\
        -hmac-key ~/ncp/hmac.b64 -queue-dsn ~/ncp/queue.db -queue-key ~/ncp/queue.b64 \\
        -pool $POOL -lighthouse "$LH_OVERLAY=$LH_ADDR"'
   # the iMac re-runs the same enroll to fetch the bundle, then: sudo nebula -config /etc/nebula/config.yml

 Verify: from any joined node,  ping $LH_OVERLAY   (lighthouse) and ping the others.

 Lifecycle follow-on (not done here): bring Harbor onto the mesh and run
   'harbor core-api -addr <harbor-overlay-ip>:8444 ...' so clients can renew +
   heartbeat (pilot supervise -core). The enrollment plane above is enough to
   join and ping.
────────────────────────────────────────────────────────────────────────────
EOF
