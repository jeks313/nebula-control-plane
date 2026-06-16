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
# Reach the UIs after deploy (SSH to the node, forward to its localhost where the containers bind):
#   ssh -i <key> -L 3000:localhost:3000 -L 9090:localhost:9090 -L 9093:localhost:9093 ec2-user@<monitoring-ip>
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
ADMIN_PORT="${ADMIN_PORT:-8445}"
LH_STATS_PORT="${LH_STATS_PORT:-8080}"

for t in terraform jq go ssh scp; do command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }; done
[[ -f "$SSH_KEY" ]] || { echo "ssh key not found: $SSH_KEY (set SSH_KEY=...)" >&2; exit 1; }
[[ -f "$PIN" ]] || { echo "config-signing pin not found: $PIN — run deploy/prod/bootstrap-genesis.sh first" >&2; exit 1; }
[[ "${GF_ADMIN_PASSWORD:-changeme}" != "changeme" ]] || echo "WARNING: GF_ADMIN_PASSWORD not set — Grafana admin password will be 'changeme'. Set it + re-run for production." >&2

SSH_OPTS=(-i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes)
rsh() { local h="$1"; shift; ssh "${SSH_OPTS[@]}" "$SSH_USER@$h" "$@"; }
rcp() { scp "${SSH_OPTS[@]}" "$@"; }

echo "==> reading terraform outputs"
OUT="$(terraform -chdir="$TFDIR" output -json)"
val() { jq -r "$1 // \"\"" <<<"$OUT"; }
MON_IP="$(val '.public_ips.value.monitoring')"
GW_URL_INTERNAL="$(val '.gateway_url_internal.value')"
TF_REGION="$(val '.region.value')"
HARBOR_DOMAIN="$(val '.harbor_domain.value')"
[[ -n "$MON_IP" ]] || { echo "no monitoring node IP in outputs — apply the app stack (it now includes the monitoring node)" >&2; exit 1; }
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
echo "    monitoring=$MON_IP region=$TF_REGION  scrape: $SCHEME harbor=$HARBOR_OVERLAY (core :$CORE_PORT, admin :$ADMIN_PORT) lighthouse=$LH_OVERLAY:$LH_STATS_PORT"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# ── 1. install pilot on the monitoring node ─────────────────────────────────
echo "==> building pilot (linux/amd64) + installing on the monitoring node"
(cd "$ROOT" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$WORK/pilot" ./cmd/pilot)
rcp "$WORK/pilot" "$SSH_USER@$MON_IP:/tmp/pilot"
rcp "$PIN" "$SSH_USER@$MON_IP:/tmp/config-signing.pub"
rsh "$MON_IP" 'sudo install -m0755 /tmp/pilot /usr/local/bin/pilot && rm -f /tmp/pilot'

# Map the harbor name -> its (fixed) overlay IP so pilot supervise can reach core-api by name
# when auto-TLS is on. (Prometheus validates by SNI instead, so it needs no entry.)
if [[ -n "$HARBOR_DOMAIN" ]]; then
  rsh "$MON_IP" "grep -qF '$HARBOR_OVERLAY $HARBOR_DOMAIN' /etc/hosts || echo '$HARBOR_OVERLAY $HARBOR_DOMAIN' | sudo tee -a /etc/hosts >/dev/null"
fi

# ── 2. enroll (keyless aws-sigv4, auto-issued via cloud-trust) + supervise ──
echo "==> enrolling the monitoring node + supervising nebula"
rsh "$MON_IP" "set -e
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
rcp "$HERE/alerts.yml" "$HERE/alertmanager.yml" "$HERE/compose.yml" "$WORK/prometheus.yml" "$SSH_USER@$MON_IP:/tmp/"
rcp -r "$HERE/grafana" "$SSH_USER@$MON_IP:/tmp/grafana"
rsh "$MON_IP" "set -e
  sudo dnf install -y podman python3-pip >/dev/null
  command -v podman-compose >/dev/null 2>&1 || sudo pip3 install --quiet podman-compose
  sudo install -d -o $SSH_USER -g $SSH_USER /opt/ncp-monitoring
  install -m0644 /tmp/alerts.yml /tmp/alertmanager.yml /tmp/compose.yml /tmp/prometheus.yml /opt/ncp-monitoring/
  rm -rf /opt/ncp-monitoring/grafana && cp -r /tmp/grafana /opt/ncp-monitoring/grafana
  echo staged"
# Grafana admin password as a 0600 .env (podman-compose substitutes \${GF_ADMIN_PASSWORD} from
# it) — piped over ssh stdin so the secret never lands on a command line / in the node's ps.
printf 'GF_ADMIN_PASSWORD=%s\n' "${GF_ADMIN_PASSWORD:-changeme}" | rsh "$MON_IP" 'umask 077; cat > /opt/ncp-monitoring/.env'
rsh "$MON_IP" 'cd /opt/ncp-monitoring && podman-compose up -d && echo up'

cat <<EOF

────────────────────────────────────────────────────────────────────────────
 MONITORING STACK UP (Prometheus + Alertmanager + Grafana)
────────────────────────────────────────────────────────────────────────────
 Node            : $MON_IP (mesh member, group:workloads)
 Scrapes         : core-api/admin-api $SCHEME at $HARBOR_OVERLAY:{$CORE_PORT,$ADMIN_PORT}, lighthouse $LH_OVERLAY:$LH_STATS_PORT (over the overlay)
 Reach the UIs   : ssh -i $SSH_KEY -L 3000:localhost:3000 -L 9090:localhost:9090 -L 9093:localhost:9093 $SSH_USER@$MON_IP
                   then http://localhost:3000 (Grafana), :9090 (Prometheus), :9093 (Alertmanager)
 Alert delivery  : PLACEHOLDER (null receiver) — wire a real Slack/email/PagerDuty receiver in
                   /opt/ncp-monitoring/alertmanager.yml on the node, then: podman-compose restart alertmanager
────────────────────────────────────────────────────────────────────────────
EOF
