#!/usr/bin/env bash
# Stand up the control-plane monitoring stack (ADR 0007 Phase 7b) on the dedicated
# mesh-member monitoring node: enroll it into the mesh (keyless aws-sigv4, exactly like the
# cloud client), then deploy Prometheus + Alertmanager + Grafana (this dir's config) via
# podman-compose. The node scrapes the mesh-only core-api/admin-api over the OVERLAY plus the
# lighthouse; the UIs are reached by SSH tunnel (not exposed).
#
# Run AFTER deploy/prod/bootstrap-genesis.sh (which creates the genesis CA + the
# config-signing pin) and `terraform apply` (which now includes the monitoring node). Reads
# the app stack's outputs. NOT live-tested (no AWS here) — `bash -n` clean; expect first-run
# iteration like the genesis bootstrap.
#
# DNS note (auto-TLS / mesh domain set): this script maps <harbor_domain> -> the harbor
# overlay IP on the node so pilot supervise can reach core-api by name. The gateway is
# reached via gateway_url_internal; with a mesh domain that is https://<gateway_domain>, which
# must resolve to the internal gateway for THIS node (operator split-horizon DNS, as the
# genesis bootstrap notes) — the dynamic internal-NLB IP can't be pinned here. Without a mesh
# domain everything resolves automatically (NLB DNS + overlay IP), no operator DNS needed.
#
# Reach the UIs after deploy — the node is PRIVATE (no public IP), so SSH rides SSM Session Manager
# (forward its localhost ports through the tunnel):
#   ssh -o ProxyCommand='aws ssm start-session --target <id> --document-name AWS-StartSSHSession --parameters portNumber=%p' \
#       -i <key> -L 3000:localhost:3000 -L 9090:localhost:9090 -L 9093:localhost:9093 ec2-user@<monitoring-instance-id>
# Set a real Grafana password: export GF_ADMIN_PASSWORD=… before running (else "changeme").
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)" # deploy/prod/monitoring -> repo root
TFDIR="$ROOT/deploy/prod/terraform/app"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/absolute.pub}"
SSH_USER="${SSH_USER:-ec2-user}"
PIN="$TFDIR/config-signing.pub" # written by bootstrap-genesis.sh (gitignored)

# Overlay addresses + ports (defaults match the bootstrap's default pool; override if you changed POOL).
HARBOR_OVERLAY="${HARBOR_OVERLAY:-10.44.0.2}"
LH_OVERLAY="${LH_OVERLAY:-10.44.0.1}"
CORE_PORT="${CORE_PORT:-8444}"
ADMIN_PORT="${ADMIN_PORT:-443}" # MUST match bootstrap-genesis.sh's ADMIN_PORT default (the console moved to 443); else the admin-api scrape target is a dead port
LH_STATS_PORT="${LH_STATS_PORT:-8080}"

for t in terraform jq go ssh scp aws session-manager-plugin; do command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }; done
[[ -f "$SSH_KEY" ]] || { echo "ssh key not found: $SSH_KEY (set SSH_KEY=...)" >&2; exit 1; }
[[ -f "$PIN" ]] || { echo "config-signing pin not found: $PIN — run deploy/prod/bootstrap-genesis.sh first" >&2; exit 1; }
[[ "${GF_ADMIN_PASSWORD:-changeme}" != "changeme" ]] || echo "WARNING: GF_ADMIN_PASSWORD not set — Grafana admin password will be 'changeme'. Set it + re-run for production." >&2

SSH_OPTS=(-i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=30 -o ServerAliveInterval=15 -o BatchMode=yes)
rsh() { local h="$1"; shift; ssh "${SSH_OPTS[@]}" "$SSH_USER@$h" "$@"; }
rcp() { scp "${SSH_OPTS[@]}" "$@"; }

echo "==> reading terraform outputs"
OUT="$(terraform -chdir="$TFDIR" output -json)"
val() { jq -r "$1 // \"\"" <<<"$OUT"; }
MON_ID="$(val '.instance_ids.value.monitoring')" # SSH/scp target over SSM (the node is private, no public IP)
MON_PRIV="$(val '.monitoring_private_ip.value')"
HB_ID="$(val '.instance_ids.value.harbor')"
GW_URL_INTERNAL="$(val '.gateway_url_internal.value')"
TF_REGION="$(val '.region.value')"
# SSH/scp to the (now private) monitoring + harbor nodes ride SSM Session Manager — append the
# ProxyCommand now that the region is known; rsh/rcp target INSTANCE IDs (MON_ID/HB_ID).
SSM_PROXY="ProxyCommand=aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p${TF_REGION:+ --region $TF_REGION}"
SSH_OPTS+=(-o "$SSM_PROXY")
HARBOR_DOMAIN="$(val '.harbor_domain.value')"
ALLOY_VERSION="${ALLOY_VERSION:-1.5.1}" # Grafana Alloy (promtail's supported successor); bump at github.com/grafana/alloy/releases
[[ -n "$MON_ID" ]] || { echo "no monitoring node instance ID in outputs — apply the app stack (it includes the monitoring node)" >&2; exit 1; }
[[ -n "$GW_URL_INTERNAL" ]] || { echo "no gateway_url_internal output — apply the app stack first" >&2; exit 1; }

# Harbor serves HTTPS for its mesh domain when auto-TLS is on; then pilot reaches it by name
# (resolved via /etc/hosts below), and Prometheus targets the overlay IP but validates the LE
# cert by SNI (tls_config.server_name) — so the container needs no DNS. Else plain http.
if [[ -n "$HARBOR_DOMAIN" ]]; then
  SCHEME="https"
  CORE_URL_HOST="$HARBOR_DOMAIN" # pilot supervise -core, by name (cert validates)
  TLS_BLOCK=$'\n    tls_config:\n      server_name: '"$HARBOR_DOMAIN"
else
  SCHEME="http"
  CORE_URL_HOST="$HARBOR_OVERLAY"
  TLS_BLOCK=""
fi
echo "    monitoring=$MON_ID region=$TF_REGION  scrape: $SCHEME harbor=$HARBOR_OVERLAY (core :$CORE_PORT, admin :$ADMIN_PORT) lighthouse=$LH_OVERLAY:$LH_STATS_PORT"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# ── 1. install pilot on the monitoring node ─────────────────────────────────
echo "==> building pilot (linux/amd64) + installing on the monitoring node"
(cd "$ROOT" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$WORK/pilot" ./cmd/pilot)
rcp "$WORK/pilot" "$SSH_USER@$MON_ID:/tmp/pilot"
rcp "$PIN" "$SSH_USER@$MON_ID:/tmp/config-signing.pub"
rsh "$MON_ID" 'sudo install -m0755 /tmp/pilot /usr/local/bin/pilot && rm -f /tmp/pilot'

# Map the harbor name -> its (fixed) overlay IP so pilot supervise can reach core-api by name
# when auto-TLS is on. (Prometheus validates by SNI instead, so it needs no entry.)
if [[ -n "$HARBOR_DOMAIN" ]]; then
  rsh "$MON_ID" "grep -qF '$HARBOR_OVERLAY $HARBOR_DOMAIN' /etc/hosts || echo '$HARBOR_OVERLAY $HARBOR_DOMAIN' | sudo tee -a /etc/hosts >/dev/null"
fi

# ── 2. enroll (keyless aws-sigv4, auto-issued via cloud-trust) + supervise ──
echo "==> enrolling the monitoring node + supervising nebula"
rsh "$MON_ID" "set -e
  sudo pilot enroll -dir /etc/nebula -gateway '$GW_URL_INTERNAL' -aws-sigv4 -region '$TF_REGION' \
    -config-pub /tmp/config-signing.pub -name monitoring
  sudo systemctl reset-failed ncp-nebula 2>/dev/null || true
  sudo systemd-run --unit ncp-nebula --collect pilot supervise -dir /etc/nebula \
    -config /etc/nebula/config.yml -core '$SCHEME://$CORE_URL_HOST:$CORE_PORT' -config-pub /tmp/config-signing.pub >/dev/null
  echo enrolled"

# ── 3. render prometheus.yml for this deploy (overlay-IP targets + SNI when TLS) ─
echo "==> rendering prometheus.yml"
cat > "$WORK/prometheus.yml" <<YAML
global:
  scrape_interval: 30s
  scrape_timeout: 10s
rule_files:
  - /etc/prometheus/alerts.yml
alerting:
  alertmanagers:
    - static_configs:
        - targets: ["alertmanager:9093"]
scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ["localhost:9090"]
  - job_name: core-api
    scheme: $SCHEME$TLS_BLOCK
    static_configs:
      - targets: ["$HARBOR_OVERLAY:$CORE_PORT"]
  - job_name: admin-api
    scheme: $SCHEME$TLS_BLOCK
    static_configs:
      - targets: ["$HARBOR_OVERLAY:$ADMIN_PORT"]
  - job_name: lighthouse
    static_configs:
      - targets: ["$LH_OVERLAY:$LH_STATS_PORT"]
YAML

# ── 4. deploy the stack (podman-compose) ────────────────────────────────────
echo "==> installing podman + bringing up Prometheus/Alertmanager/Grafana"
rcp "$HERE/alerts.yml" "$HERE/alertmanager.yml" "$HERE/loki-config.yml" "$HERE/compose.yml" "$WORK/prometheus.yml" "$SSH_USER@$MON_ID:/tmp/"
rcp -r "$HERE/grafana" "$SSH_USER@$MON_ID:/tmp/grafana"
rsh "$MON_ID" "set -e
  sudo dnf install -y podman python3-pip >/dev/null
  command -v podman-compose >/dev/null 2>&1 || sudo pip3 install --quiet podman-compose
  sudo install -d -o $SSH_USER -g $SSH_USER /opt/ncp-monitoring
  install -m0644 /tmp/alerts.yml /tmp/alertmanager.yml /tmp/loki-config.yml /tmp/compose.yml /tmp/prometheus.yml /opt/ncp-monitoring/
  rm -rf /opt/ncp-monitoring/grafana && cp -r /tmp/grafana /opt/ncp-monitoring/grafana
  echo staged"
# Grafana admin password as a 0600 .env (podman-compose substitutes \${GF_ADMIN_PASSWORD} from
# it) — piped over ssh stdin so the secret never lands on a command line / in the node's ps.
printf 'GF_ADMIN_PASSWORD=%s\n' "${GF_ADMIN_PASSWORD:-changeme}" | rsh "$MON_ID" 'umask 077; cat > /opt/ncp-monitoring/.env'
rsh "$MON_ID" 'cd /opt/ncp-monitoring && podman-compose up -d && echo up'

# ── 5. ship harbor's journald logs to Loki (Grafana Alloy on the harbor node, Phase 7c) ──
# Alloy (promtail's supported successor) tails the systemd journal (core-api/admin-api/collect/
# nebula run via systemd-run --collect) and pushes to Loki over the VPC (SG-locked). The Fargate
# components already ship via awslogs. Skipped if the harbor node isn't an output.
if [[ -n "$HB_ID" && -n "$MON_PRIV" ]]; then
  echo "==> installing Grafana Alloy on harbor -> Loki ($MON_PRIV:3100)"
  sed "s#http://MONITORING_PRIVATE_IP:3100#http://$MON_PRIV:3100#" "$HERE/config.alloy" > "$WORK/config.alloy"
  rcp "$WORK/config.alloy" "$SSH_USER@$HB_ID:/tmp/config.alloy"
  rsh "$HB_ID" "set -e
    # persistent journal so Alloy reads more than the current boot
    sudo mkdir -p /var/log/journal && sudo systemctl restart systemd-journald
    if ! command -v alloy >/dev/null; then
      cd /tmp
      curl -fsSL -o alloy.zip 'https://github.com/grafana/alloy/releases/download/v$ALLOY_VERSION/alloy-linux-amd64.zip'
      command -v unzip >/dev/null || sudo dnf install -y unzip >/dev/null
      unzip -o alloy.zip >/dev/null && sudo install -m0755 alloy-linux-amd64 /usr/local/bin/alloy && rm -f alloy.zip alloy-linux-amd64
    fi
    sudo install -d /etc/alloy /var/lib/alloy
    sudo install -m0644 /tmp/config.alloy /etc/alloy/config.alloy && rm -f /tmp/config.alloy
    sudo systemctl reset-failed ncp-alloy 2>/dev/null || true
    # Bind the Alloy UI to localhost (not exposed); --storage.path persists its WAL.
    sudo systemd-run --unit ncp-alloy --collect /usr/local/bin/alloy run \
      --server.http.listen-addr=127.0.0.1:12345 --storage.path=/var/lib/alloy /etc/alloy/config.alloy >/dev/null
    echo alloy-up"
else
  echo "==> skipping harbor log shipping (no harbor / monitoring-private-ip output)"
fi

cat <<EOF

────────────────────────────────────────────────────────────────────────────
 MONITORING STACK UP (Prometheus + Alertmanager + Grafana)
────────────────────────────────────────────────────────────────────────────
 Node            : $MON_ID (${MON_PRIV:-private}; mesh member, group:workloads)
 Scrapes         : core-api/admin-api $SCHEME at $HARBOR_OVERLAY:{$CORE_PORT,$ADMIN_PORT}, lighthouse $LH_OVERLAY:$LH_STATS_PORT (over the overlay)
 Logs            : harbor journald -> Grafana Alloy -> Loki ($MON_PRIV:3100). Query in Grafana (Loki datasource); the Fargate gateway/lighthouse ship via awslogs.
 Reach the UIs   : ssh -i $SSH_KEY -o "$SSM_PROXY" -L 3000:localhost:3000 -L 9090:localhost:9090 -L 9093:localhost:9093 $SSH_USER@$MON_ID
                   then http://localhost:3000 (Grafana), :9090 (Prometheus), :9093 (Alertmanager)
 Alert delivery  : PLACEHOLDER (null receiver) — wire a real Slack/email/PagerDuty receiver in
                   /opt/ncp-monitoring/alertmanager.yml on the node, then: podman-compose restart alertmanager
────────────────────────────────────────────────────────────────────────────
EOF
