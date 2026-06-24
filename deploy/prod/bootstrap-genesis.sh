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
#   5. harbor:     install ca + control-plane cert; start nebula UNDER PILOT (managed mesh member:
#                  heartbeats into the fleet + auto-renews; firewall comes from the signed bundle's
#                  control-plane invariant, so drift/renew can't close its API ports — see PR #7)
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
# Requires locally: terraform, jq, go, ssh, scp, openssl, aws, session-manager-plugin, and AWS
# creds in the env (SSH/scp to the now-private nodes ride SSM Session Manager). Plus a container
# engine [podman or docker] when gateway_runtime=fargate (build/push the Fargate image).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TFDIR="$ROOT/deploy/prod/terraform/app" # the app stack (foundation/ is layer 0, applied separately)
SSH_KEY="${SSH_KEY:-$HOME/.ssh/absolute.pub}"   # public key selecting the agent identity (private may be passphrase-locked in the agent)
SSH_USER="${SSH_USER:-ec2-user}"
SAML_DIR="/home/$SSH_USER/ncp/saml" # on the box: console SAML SP keypair + idp-metadata + saml.env (durable; snapshotted)
SKIP_BUILD=0
[[ "${1:-}" == "--skip-build" ]] && SKIP_BUILD=1
# MODE: genesis (default — the full first-time ceremony) | recover (a destroyed/recreated harbor:
# skip the non-idempotent genesis + minting, RESTORE harbor's identity + config from the
# ncp-harbor-config bundle in Secrets Manager, then start its services). In recover the lighthouse
# + gateway are NOT touched — they keep running with config that still matches the restored harbor.
MODE="${MODE:-genesis}"
case "$MODE" in genesis | recover) ;; *) echo "MODE must be genesis|recover (got '$MODE')" >&2; exit 1 ;; esac

# Overlay pool + reserved overlay IPs. IMPORTANT: do NOT use 100.64.0.0/10 (CGNAT)
# if any host also runs Tailscale — its nftables anti-spoof rule silently drops that
# range on non-tailscale0 interfaces, killing the nebula data plane. Default to a
# private range that won't collide.
POOL="${POOL:-10.44.0.0/16}"
LH_OVERLAY="${LH_OVERLAY:-10.44.0.1}"
HARBOR_OVERLAY="${HARBOR_OVERLAY:-10.44.0.2}"   # Harbor's own mesh address (control-plane node)
CORE_PORT="${CORE_PORT:-8444}"                   # core-api (renew/heartbeat), mesh-only (machine-facing; stays off 443)
ADMIN_PORT="${ADMIN_PORT:-443}"                  # admin console, mesh-only (default 443 => clean https URLs over the overlay; still NOT public)
MOCK_IDP_PORT="${MOCK_IDP_PORT:-8446}"           # dev mock-IdP for the console login
COLLECT_OBS_PORT="${COLLECT_OBS_PORT:-9445}"     # harbor collect /metrics + /healthz (Phase 7b), mesh-only on the overlay
DB_BACKEND="${DB_BACKEND:-}"                     # sqlite (local file on harbor) | aurora (managed Postgres; rotating creds via Secrets Manager, no static password). Empty => DERIVED from the durable layer below (Aurora if the app stack provisioned it), so a recover/replace never silently falls back to an empty local SQLite.

# ── SSO enrollment portal (ADR 0004, OPTIONAL — default OFF) ──────────────────
# SSO is wired into the SAME off-mesh gateway (ADR 0009: no new tier). It is DISABLED unless
# the operator sets SSO_ACS_URL — exactly mirroring the gateway's own fail-closed-disabled
# trigger (cmd/gateway/sso.go: nil Config.SSO when -sso-acs-url/$NCP_GW_SSO_ACS_URL is empty).
# When SSO_ACS_URL is empty, NONE of the SSO threading below fires: the gateway secret's SSO
# fields stay empty, no -sso-assert-pub/-usertrust-db is added to Core, and the recover bundle
# gains only empty SSO fields — so genesis/recover/gateway/Core are byte-for-behavior unchanged.
#
# To ENABLE (after registering a SECOND SAML app in the IdP whose Reply URL = SSO_ACS_URL —
# see ADR 0004 "Operator setup"):
#   SSO_ACS_URL          PUBLIC gateway ACS, e.g. https://<gateway-domain>/v1/sso/acs  (the TRIGGER)
#   SSO_ENTITY_ID        the SP entity id (the enrollment-portal app's Identifier; DISTINCT from the console's)
#   SSO_ISSUER           the assertion realm (iss), fed to Core's usertrust.Match (the IdP's issuer)
#   SSO_GROUPS_ATTR      (optional) the SAML group-claim attribute (default: the gateway's "groups")
#   SSO_IDP_METADATA_URL or SSO_IDP_METADATA_FILE   the enrollment-portal app's IdP SAML metadata
# The genesis-minted assertion keypair + a genesis-minted STABLE SP keypair are distributed
# automatically (no operator input). A user-trust config (harbor usertrust publish / the console)
# is still required for SSO to reach issuance — that is a separate operator step.
SSO_ACS_URL="${SSO_ACS_URL:-}"
SSO_ENTITY_ID="${SSO_ENTITY_ID:-}"
SSO_ISSUER="${SSO_ISSUER:-}"
SSO_GROUPS_ATTR="${SSO_GROUPS_ATTR:-}"
SSO_IDP_METADATA_URL="${SSO_IDP_METADATA_URL:-}"
SSO_IDP_METADATA_FILE="${SSO_IDP_METADATA_FILE:-}"
# SSO_ENABLED is computed AFTER the terraform-output fallback below (see "SSO knobs"), so the 5
# static knobs can come durably from tfvars (var.sso_* -> outputs.tf) with env taking precedence —
# a fresh bootstrap then reproduces the live enrollment-portal SSO without re-typing them.

for t in terraform jq go npm ssh scp openssl aws session-manager-plugin; do command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }; done
[[ -f "$SSH_KEY" ]] || { echo "ssh private key not found: $SSH_KEY (set SSH_KEY=...)" >&2; exit 1; }

SSH_OPTS=(-i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=30 -o ServerAliveInterval=15 -o BatchMode=yes)
rsh() { local host="$1"; shift; ssh "${SSH_OPTS[@]}" "$SSH_USER@$host" "$@"; }
rcp() { scp "${SSH_OPTS[@]}" "$@"; }
# url_for SCHEME HOST PORT — build a URL, omitting the port when it's the scheme default (https:443,
# http:80). The console on 443 thus advertises a clean https://<host> base-url, which matters for
# SAML: the SP entity-id/ACS are derived from base-url, and a stray ":443" would mismatch the IdP.
url_for() {
  local scheme="$1" host="$2" port="$3"
  if [[ "$scheme" == https && "$port" == 443 ]] || [[ "$scheme" == http && "$port" == 80 ]]; then
    printf '%s://%s' "$scheme" "$host"
  else
    printf '%s://%s:%s' "$scheme" "$host" "$port"
  fi
}

echo "==> reading terraform outputs"
OUT="$(terraform -chdir="$TFDIR" output -json)"
val() { jq -r "$1 // \"\"" <<<"$OUT"; }
# SSO knobs: env wins, else fall back to the durable terraform values (var.sso_* -> outputs.tf), so a
# fresh bootstrap reproduces the live enrollment-portal SSO config without re-typing it. The 3 PEMs
# (assertion + SP keypairs) are genesis-generated, never sourced here. SSO_IDP_METADATA_URL stays
# env-only (no tf output). Presence of an ACS URL is the enable trigger (mirrors the gateway).
SSO_ACS_URL="${SSO_ACS_URL:-$(val '.sso_acs_url.value')}"
SSO_ENTITY_ID="${SSO_ENTITY_ID:-$(val '.sso_entity_id.value')}"
SSO_ISSUER="${SSO_ISSUER:-$(val '.sso_issuer.value')}"
SSO_GROUPS_ATTR="${SSO_GROUPS_ATTR:-$(val '.sso_groups_attr.value')}"
SSO_IDP_METADATA_FILE="${SSO_IDP_METADATA_FILE:-$(val '.sso_idp_metadata_file.value')}"
SSO_ENABLED=0
[[ -n "$SSO_ACS_URL" ]] && SSO_ENABLED=1
LH_IP="$(val '.public_ips.value.lighthouse')"
HB_IP="$(val '.public_ips.value.harbor')"
GW_IP="$(val '.public_ips.value.gateway')"          # off-mesh gateway EC2 node (empty when gateway_runtime=fargate)
CL_IP="$(val '.public_ips.value.client')"
# Instance IDs — SSH/scp target these over SSM (the private nodes have no usable public IP).
HB_ID="$(val '.instance_ids.value.harbor')"
CL_ID="$(val '.instance_ids.value.client')"
LH_ID="$(val '.instance_ids.value.lighthouse')" # empty when lighthouse_runtime=fargate
GW_ID="$(val '.instance_ids.value.gateway')"     # empty when gateway_runtime=fargate
LH_ADDR="$(val '.lighthouse_addr.value')"
GW_URL="$(val '.gateway_url.value')"                # PUBLIC enroll URL (off-cloud clients; public NLB DNS / node IP)
GW_URL_INTERNAL="$(val '.gateway_url_internal.value')" # IN-VPC enroll URL (cloud client; internal NLB DNS / node IP)
GW_COLLECT="$(val '.gateway_collect_addr.value')"   # gateway's Harbor-facing collect URL (in-VPC; internal NLB / node IP)
[[ -n "$GW_URL_INTERNAL" ]] || GW_URL_INTERNAL="$GW_URL" # older state without the internal output
GATEWAY_RUNTIME="$(val '.gateway_runtime.value')"; GATEWAY_RUNTIME="${GATEWAY_RUNTIME:-ec2}"
LIGHTHOUSE_RUNTIME="$(val '.lighthouse_runtime.value')"; LIGHTHOUSE_RUNTIME="${LIGHTHOUSE_RUNTIME:-ec2}"
NAME_PREFIX="$(val '.name_prefix.value')"; NAME_PREFIX="${NAME_PREFIX:-ncp}"
HARBOR_CONFIG_ARN="$(val '.harbor_config_secret_arn.value')" # durable harbor identity+config bundle (Secrets Manager)
TF_REGION="$(val '.region.value')"
# Lighthouse set (HA). For the fargate runtime the app stack stands up N INDEPENDENT lighthouses
# (var.lighthouse_count) — each with its own cert/overlay-IP AND its own NLB+EIP — so rotating one
# (an ECS redeploy) never blacks out discovery: the others keep serving. Derive (name, overlay_ip,
# public_addr) for each from the lighthouse_addrs output. Overlay IPs are deterministic + reserved
# in the central block: lighthouse-1 = $LH_OVERLAY (10.44.0.1), lighthouse-N>1 = 10.44.0.(N+1)
# (skips harbor's .2). EC2 (or older state without the output) keeps the single lighthouse-1.
LH_ADDRS_JSON="$(val '.lighthouse_addrs.value')"
[[ -z "$LH_ADDRS_JSON" || "$LH_ADDRS_JSON" == "null" ]] && LH_ADDRS_JSON="{}"
declare -a LH_NAMES LH_OVERLAYS LH_PUBADDRS
if [[ "$LIGHTHOUSE_RUNTIME" == "fargate" && "$LH_ADDRS_JSON" != "{}" ]]; then
  while IFS=$'\t' read -r _ln _la; do
    [[ -z "$_ln" ]] && continue
    _n="${_ln##*-}" # lighthouse-2 -> 2
    if [[ "$_n" == 1 ]]; then _lip="$LH_OVERLAY"; else _lip="10.44.0.$((_n + 1))"; fi
    LH_NAMES+=("$_ln"); LH_OVERLAYS+=("$_lip"); LH_PUBADDRS+=("$_la")
  done < <(jq -r 'to_entries[] | "\(.key)\t\(.value)"' <<<"$LH_ADDRS_JSON" | sort)
else
  LH_NAMES=("lighthouse-1"); LH_OVERLAYS=("$LH_OVERLAY"); LH_PUBADDRS=("$LH_ADDR")
fi
LH_COUNT="${#LH_NAMES[@]}"
# SSH/scp to the nodes ride SSM Session Manager — the private nodes (harbor/client/monitoring) have
# no public IP. Append the ProxyCommand now that the region is known; rsh/rcp target INSTANCE IDs
# (HB_ID/CL_ID/LH_ID/GW_ID), and SSH key auth still happens over the SSM tunnel (the EC2 key pair).
SSM_PROXY="ProxyCommand=aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p${TF_REGION:+ --region $TF_REGION}"
SSH_OPTS+=(-o "$SSM_PROXY")
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
  # lighthouse rotate-cert uses addBackendFlags (the SINGLE-key form): -kms-key-id, NOT genesis'
  # -kms-ca-key-id/-kms-config-key-id (cert signing needs only the CA key). The harbor role's
  # core_kms_sign grant already covers kms:Sign on this key.
  ROTATE_BACKEND="-backend kms -kms-key-id $CA_KEY_ARN${TF_REGION:+ -kms-region $TF_REGION}"
  TRUST_BACKEND_DESC="AWS KMS (CA + config-signing private keys never on disk)"
else
  GENESIS_BACKEND=""                                                     # software: genesis GENERATES + writes the keys to -out
  SIGN_BACKEND="-ca-key \$G/ca.key -config-key \$G/config-signing.key"   # software: read the genesis-written keys (\$G expands remotely)
  APPROVE_BACKEND="-ca-key ~/ncp/genesis/ca.key -config-key ~/ncp/genesis/config-signing.key"
  ROTATE_BACKEND="-backend software -ca-key /home/$SSH_USER/ncp/genesis/ca.key" # absolute: the timer runs as root
  TRUST_BACKEND_DESC="software (keys in ~/ncp/genesis on the harbor node)"
fi
# Data backend (ADR 0007): SQLite on the harbor node by default; opt into Aurora with
# DB_BACKEND=aurora. For Aurora, Core resolves the login from the RDS-managed (ROTATING)
# secret via its instance role, refreshed per-connection — so NO static password is ever in
# the DSN, on argv, or on disk (the laptop never sees it either). One flag set is shared by
# EVERY harbor invocation (migrate/genesis/cloudtrust/gateway/collect/joinkey/core-api/admin-api)
# so they all hit the same database. The DSN is single-quoted so the remote shell keeps the
# '?'/'&' query chars literal (no globbing/splitting).
# Derive the data backend from the DURABLE layer (terraform outputs) so a recover/replace can't
# silently come up against an empty local SQLite while Aurora still holds all the genesis/enrollment
# state. If the app stack provisioned Aurora (db_cluster_endpoint output set), default to aurora; an
# explicit DB_BACKEND env still wins. Fail LOUD on the footgun: Aurora exists but someone forced
# sqlite — that would hollow the control plane on recover.
if [[ -z "$DB_BACKEND" ]]; then
  if [[ -n "$(val '.db_cluster_endpoint.value')" ]]; then DB_BACKEND="aurora"; else DB_BACKEND="sqlite"; fi
elif [[ "$DB_BACKEND" == "sqlite" && -n "$(val '.db_cluster_endpoint.value')" ]]; then
  echo "FATAL: DB_BACKEND=sqlite but the app stack has Aurora (db_cluster_endpoint is set). Harbor's state lives in Aurora; a sqlite recover would come up HOLLOW (empty registry/cloudtrust/enrollments). Unset DB_BACKEND (auto-derives aurora) or pass DB_BACKEND=aurora." >&2
  exit 1
fi
if [[ "$DB_BACKEND" == "aurora" || "$DB_BACKEND" == "postgres" ]]; then
  DB_HOST="$(val '.db_cluster_endpoint.value')"
  DB_PORT="$(val '.db_port.value')"; DB_PORT="${DB_PORT:-5432}"
  DB_NAME="$(val '.db_name.value')"
  DB_SECRET_ARN="$(val '.db_master_secret_arn.value')"
  [[ -n "$DB_HOST" && -n "$DB_NAME" && -n "$DB_SECRET_ARN" ]] \
    || { echo "FATAL: DB_BACKEND=$DB_BACKEND but the data-layer outputs are empty (db_cluster_endpoint/db_name/db_master_secret_arn). Apply the app stack's data layer (Aurora) first." >&2; exit 1; }
  HARBOR_DB_FLAGS="-driver postgres -dsn 'postgres://$DB_HOST:$DB_PORT/$DB_NAME?sslmode=require' -db-secret-arn '$DB_SECRET_ARN'${TF_REGION:+ -db-secret-region '$TF_REGION'}"
  # Display variant for the printed enroll-approve hint, which is wrapped in single quotes
  # (deferring expansion to the box's shell) — so it must carry NO inner single quotes. The
  # DSN/ARN have no spaces, and the '?' can't glob-match a real file, so leaving them unquoted
  # is safe here.
  HARBOR_DB_FLAGS_HINT="-driver postgres -dsn postgres://$DB_HOST:$DB_PORT/$DB_NAME?sslmode=require -db-secret-arn $DB_SECRET_ARN${TF_REGION:+ -db-secret-region $TF_REGION}"
  DB_BACKEND_DESC="Aurora PostgreSQL @ $DB_HOST:$DB_PORT/$DB_NAME (rotating creds via Secrets Manager; no static password)"
else
  HARBOR_DB_FLAGS="-dsn ~/ncp/harbor.db"        # remote tilde expands to the harbor user's home
  HARBOR_DB_FLAGS_HINT="$HARBOR_DB_FLAGS"
  DB_BACKEND_DESC="SQLite (~/ncp/harbor.db on the harbor node)"
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
  CORE_URL="$(url_for https "$HARBOR_DOMAIN" "$CORE_PORT")"; ADMIN_URL="$(url_for https "$HARBOR_DOMAIN" "$ADMIN_PORT")"
else
  CORE_URL="$(url_for http "$HARBOR_OVERLAY" "$CORE_PORT")"; ADMIN_URL="$(url_for http "$HARBOR_OVERLAY" "$ADMIN_PORT")"
fi
echo "    harbor=$HB_ID  client=$CL_ID  lighthouse=${LH_ID:-<fargate>}  gateway=${GW_ID:-<fargate>}  (instance IDs; private nodes reached via SSM)"
echo "    lighthouse underlay=$LH_ADDR  enroll=$GW_URL  collect=$GW_COLLECT  harbor-overlay=$HARBOR_OVERLAY"
echo "    runtimes: gateway=$GATEWAY_RUNTIME  lighthouse=$LIGHTHOUSE_RUNTIME  harbor-tls=${HARBOR_DOMAIN:+ACME:$HARBOR_DOMAIN}${HARBOR_DOMAIN:-plain-http}"
echo "    trust-root signing: $TRUST_BACKEND_DESC"
echo "    data backend: $DB_BACKEND_DESC"

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

# SSO (ADR 0004): when enabled at GENESIS, the operator MUST supply the second SAML app's IdP
# metadata (URL or file) and the SP entity id + assertion realm — fail closed before any work
# rather than launch a half-configured portal (the gateway itself also fails closed,
# cmd/gateway/sso.go). On RECOVER this is skipped: the SSO state + material come SOLELY from the
# bundle (re-derived below), so the operator need not re-supply the env knobs.
if [[ "$MODE" != "recover" && "$SSO_ENABLED" -eq 1 ]]; then
  [[ -n "$SSO_IDP_METADATA_URL" || -n "$SSO_IDP_METADATA_FILE" ]] \
    || { echo "FATAL: SSO_ACS_URL is set (SSO enabled) but no IdP metadata — set SSO_IDP_METADATA_URL or SSO_IDP_METADATA_FILE (the SECOND SAML app's metadata; see ADR 0004 'Operator setup')." >&2; exit 1; }
  [[ -z "$SSO_IDP_METADATA_FILE" || -f "$SSO_IDP_METADATA_FILE" ]] \
    || { echo "FATAL: SSO_IDP_METADATA_FILE=$SSO_IDP_METADATA_FILE not found" >&2; exit 1; }
  [[ -n "$SSO_ENTITY_ID" ]] \
    || { echo "FATAL: SSO enabled but SSO_ENTITY_ID is unset (the enrollment-portal SP entity id; MUST be distinct from the console's -saml-entity-id — ADR 0004)." >&2; exit 1; }
  [[ -n "$SSO_ISSUER" ]] \
    || { echo "FATAL: SSO enabled but SSO_ISSUER is unset (the assertion realm fed to Core's usertrust.Match — the IdP issuer)." >&2; exit 1; }
  # The metadata is embedded into the gateway secret + the recover bundle (so recover is exact);
  # fetching a URL needs curl. (A FILE needs nothing beyond the -f check above.)
  if [[ -z "$SSO_IDP_METADATA_FILE" ]]; then
    command -v curl >/dev/null || { echo "missing tool (SSO_IDP_METADATA_URL set, fetches the IdP metadata): curl — or supply SSO_IDP_METADATA_FILE instead" >&2; exit 1; }
  fi
  echo "    NOTE: SSO enrollment portal ENABLED — ACS=$SSO_ACS_URL entity-id=$SSO_ENTITY_ID issuer=$SSO_ISSUER"
fi

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
LH="$LH_OVERLAY=$LH_ADDR"

# ── 0. build + distribute binaries ──────────────────────────────────────────
if [[ "$SKIP_BUILD" -eq 0 ]]; then
  VER="$(cat "$ROOT/VERSION" 2>/dev/null || echo dev)" # stamp main.version (else binaries report "dev")
  # Build the React admin console bundle FIRST so harbor can embed it via `-tags ui`
  # (//go:embed all:dist in internal/adminui). The poc serves the full console at :443;
  # without this, harbor's console is the "not bundled" 501 stub. pilot/gateway have no UI.
  echo "==> building the admin console UI bundle (npm) -> internal/adminui/dist"
  ( npm --prefix "$ROOT/ui" install --no-audit --no-fund && npm --prefix "$ROOT/ui" run build )
  echo "==> building harbor (-tags ui)/pilot/gateway $VER (linux/amd64, cgo-free)"
  ( cd "$ROOT" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags ui -ldflags "-X main.version=$VER" -o "$WORK/harbor" ./cmd/harbor \
    && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-X main.version=$VER" -o "$WORK/pilot" ./cmd/pilot \
    && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-X main.version=$VER" -o "$WORK/gateway" ./cmd/gateway )
  # harbor/client are always EC2; the lighthouse + gateway are EC2 nodes only under their
  # "ec2" runtime (under fargate each is a container — no VM to scp to). Target INSTANCE IDs:
  # SSH/scp ride SSM, and the private nodes have no public IP.
  if [[ "$MODE" == "recover" ]]; then
    NODE_IDS=("$HB_ID") # recover: only the recreated harbor needs binaries (the others keep running)
  else
    NODE_IDS=("$HB_ID" "$CL_ID")
    [[ "$LIGHTHOUSE_RUNTIME" == "ec2" && -n "$LH_ID" ]] && NODE_IDS+=("$LH_ID")
    [[ "$GATEWAY_RUNTIME" == "ec2" && -n "$GW_ID" ]] && NODE_IDS+=("$GW_ID")
  fi
  for id in "${NODE_IDS[@]}"; do
    echo "    -> $id"
    rcp "$WORK/harbor" "$WORK/pilot" "$WORK/gateway" "$SSH_USER@$id:/tmp/"
    rsh "$id" 'sudo install -m0755 /tmp/harbor /tmp/pilot /tmp/gateway /usr/local/bin/ && rm -f /tmp/harbor /tmp/pilot /tmp/gateway'
  done
fi

if [[ "$MODE" == "recover" ]]; then
  # ── recover: restore harbor's identity + config from the ncp-harbor-config bundle ──
  # The genesis ceremony is NOT idempotent (duplicate CA-key name / lighthouse IP), and a fresh
  # genesis would mint a NEW CA cert — a new fingerprint that breaks every enrolled member, since
  # nebula pins the CA by its certificate fingerprint. So instead we restore harbor byte-identical
  # from Secrets Manager (+ KMS keeps signing; Aurora keeps the genesis state). The lighthouse +
  # gateway are untouched and still match the restored hmac / mTLS material.
  echo "==> [recover] restoring harbor from ${NAME_PREFIX}-harbor-config (Secrets Manager)"
  [[ -n "$HARBOR_CONFIG_ARN" ]] || { echo "FATAL: recover needs the harbor_config_secret_arn output (apply the app stack)" >&2; exit 1; }
  BUNDLE="$(aws secretsmanager get-secret-value --region "$TF_REGION" --secret-id "$HARBOR_CONFIG_ARN" --query SecretString --output text)"
  [[ -n "$BUNDLE" && "$(jq -r '.ca_crt_pem // ""' <<<"$BUNDLE")" != "" ]] \
    || { echo "FATAL: ${NAME_PREFIX}-harbor-config is empty — run a MODE=genesis bootstrap first to populate it" >&2; exit 1; }
  # Public artifacts also land in $WORK (downstream steps + the client pin read from there).
  jq -r '.ca_crt_pem' <<<"$BUNDLE" >"$WORK/ca.crt"
  jq -r '.config_signing_pub_pem' <<<"$BUNDLE" >"$WORK/config-signing.pub"
  jq -r '.host_crt_pem' <<<"$BUNDLE" >"$WORK/harbor-core.crt"
  jq -r '.harbor_collect_cert_pem' <<<"$BUNDLE" >"$WORK/harbor-collect.crt"
  jq -r '.hmac_key_b64' <<<"$BUNDLE" | tr -d '\n' >"$WORK/hmac.b64"
  jq -r '.gw_collect_cert_pem' <<<"$BUNDLE" >"$WORK/gw-collect.crt"
  # Restore harbor's on-box files. Secrets ride ssh stdin (never argv); the nebula host key is
  # root-owned 0600 in /etc/nebula, the rest live under ~/ncp owned by $SSH_USER.
  jq -r '.host_key_pem' <<<"$BUNDLE" | rsh "$HB_ID" "sudo install -d -m0700 /etc/nebula && sudo tee /etc/nebula/host.key >/dev/null && sudo chmod 600 /etc/nebula/host.key"
  jq -r '.host_crt_pem' <<<"$BUNDLE" | rsh "$HB_ID" "sudo tee /etc/nebula/host.crt >/dev/null && sudo chmod 644 /etc/nebula/host.crt"
  jq -r '.ca_crt_pem' <<<"$BUNDLE" | rsh "$HB_ID" "sudo tee /etc/nebula/ca.crt >/dev/null && sudo chmod 644 /etc/nebula/ca.crt"
  jq -r '.host_config_yml' <<<"$BUNDLE" | rsh "$HB_ID" "sudo tee /etc/nebula/config.yml >/dev/null && sudo chmod 644 /etc/nebula/config.yml"
  rsh "$HB_ID" "umask 077; mkdir -p ~/ncp/genesis"
  jq -r '.ca_crt_pem' <<<"$BUNDLE" | rsh "$HB_ID" "cat > ~/ncp/genesis/ca.crt"
  jq -r '.config_signing_pub_pem' <<<"$BUNDLE" | rsh "$HB_ID" "cat > ~/ncp/genesis/config-signing.pub"
  jq -r '.hmac_key_b64' <<<"$BUNDLE" | rsh "$HB_ID" "umask 077; tr -d '\n' > ~/ncp/hmac.b64"
  jq -r '.harbor_collect_cert_pem' <<<"$BUNDLE" | rsh "$HB_ID" "umask 077; cat > ~/ncp/harbor-collect.crt"
  jq -r '.harbor_collect_key_pem' <<<"$BUNDLE" | rsh "$HB_ID" "umask 077; cat > ~/ncp/harbor-collect.key && chmod 600 ~/ncp/harbor-collect.key"
  jq -r '.queue_key_b64' <<<"$BUNDLE" | rsh "$HB_ID" "umask 077; tr -d '\n' > ~/ncp/queue.b64"
  jq -r '.gw_collect_cert_pem' <<<"$BUNDLE" | rsh "$HB_ID" "umask 077; cat > ~/ncp/gw-collect.crt"
  # Restore the ACME cert cache if the bundle carries one — harbor then reuses its existing LE cert
  # (no re-issuance / no rate-limit risk). Empty = no cached cert; core/admin issue fresh on start.
  ACMEB64="$(jq -r '.acme_cache_tgz_b64 // ""' <<<"$BUNDLE")"
  if [[ -n "$ACMEB64" ]]; then
    printf '%s' "$ACMEB64" | base64 -d | rsh "$HB_ID" "umask 077; mkdir -p ~/ncp && tar -xzf - -C ~/ncp" &&
      echo "    restored the ACME cert cache (harbor reuses its existing LE cert; no re-issuance)"
  fi
  # SSO (ADR 0004): if the bundle carries SSO material (sso_acs_url non-empty => SSO was on at
  # genesis), restore it byte-identical and re-enable the downstream threading. The recover-time
  # SSO state is driven SOLELY by the bundle (the operator env knobs are NOT needed on recover) —
  # so a recovered control plane reconstructs SSO exactly as genesis left it. An empty sso_acs_url
  # (the default / SSO-off case) leaves SSO_ENABLED=0 and nothing SSO-related is touched.
  SSO_ACS_URL="$(jq -r '.sso_acs_url // ""' <<<"$BUNDLE")"
  if [[ -n "$SSO_ACS_URL" ]]; then
    SSO_ENABLED=1
    SSO_ENTITY_ID="$(jq -r '.sso_entity_id // ""' <<<"$BUNDLE")"
    SSO_ISSUER="$(jq -r '.sso_issuer // ""' <<<"$BUNDLE")"
    SSO_GROUPS_ATTR="$(jq -r '.sso_groups_attr // ""' <<<"$BUNDLE")"
    jq -r '.sso_assert_priv_pem' <<<"$BUNDLE" >"$WORK/sso-assert.key"
    jq -r '.sso_assert_pub_pem'  <<<"$BUNDLE" >"$WORK/sso-assert.pub"
    jq -r '.sso_sp_cert_pem'     <<<"$BUNDLE" >"$WORK/sso-sp.crt"
    jq -r '.sso_sp_key_pem'      <<<"$BUNDLE" >"$WORK/sso-sp.key"
    jq -r '.sso_idp_metadata'    <<<"$BUNDLE" >"$WORK/sso-idp-metadata.xml"
    # Core pins the assertion PUBLIC half from a file on the box; restore it (genesis writes it
    # under ~/ncp/genesis; the collect/core/admin invocations below read $G/sso-assert.pub).
    jq -r '.sso_assert_pub_pem' <<<"$BUNDLE" | rsh "$HB_ID" "umask 077; cat > ~/ncp/genesis/sso-assert.pub"
    echo "    restored SSO material (assertion keypair + SP keypair + IdP metadata + ACS/entity/issuer knobs) — SSO re-enabled"
  else
    SSO_ENABLED=0
  fi
  # Console SAML (admin login): if the bundle carries it (saml_role_map non-empty => real Entra SAML
  # was wired), restore the SP keypair + IdP metadata to the box and set the vars so the IDP_FLAGS
  # recover branch (below) rebuilds production flags. Without this, recover SILENTLY downgrades the
  # console to the dev mock-IdP and drops the admin role-map. Empty => console stays mock-IdP (dev).
  SAML_ROLE_MAP="$(jq -r '.saml_role_map // ""' <<<"$BUNDLE")"
  if [[ -n "$SAML_ROLE_MAP" ]]; then
    SAML_RESTORED=1
    SAML_ENTITY_ID="$(jq -r '.saml_entity_id // ""' <<<"$BUNDLE")"
    SAML_GROUPS_ATTR="$(jq -r '.saml_groups_attr // ""' <<<"$BUNDLE")"
    SAML_METADATA_URL="$(jq -r '.saml_metadata_url // ""' <<<"$BUNDLE")"
    rsh "$HB_ID" "umask 077; mkdir -p $SAML_DIR"
    jq -r '.saml_sp_key_pem'  <<<"$BUNDLE" | rsh "$HB_ID" "umask 077; cat > $SAML_DIR/sp.key && chmod 600 $SAML_DIR/sp.key"
    jq -r '.saml_sp_cert_pem' <<<"$BUNDLE" | rsh "$HB_ID" "cat > $SAML_DIR/sp.crt && chmod 644 $SAML_DIR/sp.crt"
    IDP_META="$(jq -r '.saml_idp_metadata // ""' <<<"$BUNDLE")"
    [[ -n "$IDP_META" ]] && printf '%s' "$IDP_META" | rsh "$HB_ID" "cat > $SAML_DIR/idp-metadata.xml && chmod 644 $SAML_DIR/idp-metadata.xml"
    echo "    restored console SAML (role-map + SP keypair + IdP metadata) — console SSO re-enabled on recover"
  else
    SAML_RESTORED=0
  fi
  cp "$WORK/config-signing.pub" "$ROOT/deploy/prod/terraform/app/config-signing.pub" # the pin for clients
  echo "    restored: ca.crt + config-signing pin + harbor identity (key/cert/config) + hmac + collect mTLS + queue key"
else
  # ── 1. lighthouse: init ──────────────────────────────────────────────────────
  # EC2: init on the box (host key never leaves it). Fargate (spike): generate the keypair
  # HERE (off-box) — there is no node — and inject it via Secrets Manager in step 4.
  if [[ "$LIGHTHOUSE_RUNTIME" == "ec2" ]]; then
  echo "==> [lighthouse/ec2] pilot init -am-lighthouse"
  rsh "$LH_ID" 'sudo pilot init -am-lighthouse -dir /etc/nebula >/dev/null && sudo cat /etc/nebula/host.pub' > "$WORK/lh-host.pub"
else
  echo "==> [lighthouse/fargate] generate lighthouse keypair off-box"
  "$WORK/pilot" init -am-lighthouse -dir "$WORK/lhkeys" >/dev/null
  cp "$WORK/lhkeys/host.pub" "$WORK/lh-host.pub"
fi
echo "    got lighthouse host pubkey"

# ── 2. harbor: init its OWN mesh key, with ALL lighthouses in static_host_map ─
# All N lighthouses go in harbor's initial static_host_map so it can reach discovery before its
# first signed bundle (under pilot, the bundle — built from the -lighthouse-db registry below —
# then carries the authoritative set). Built locally from the derived lighthouse arrays.
echo "==> [harbor] pilot init (control-plane node key); ${LH_COUNT} lighthouse(s) in static_host_map"
LH_VALUES_YAML="lighthouses:"
for i in "${!LH_NAMES[@]}"; do
  LH_VALUES_YAML+="
  - overlay_ip: ${LH_OVERLAYS[$i]}
    public_addrs: [\"${LH_PUBADDRS[$i]}\"]"
done
rsh "$HB_ID" "set -e
  sudo tee /etc/nebula-values.yml >/dev/null <<YAML
$LH_VALUES_YAML
YAML
  sudo pilot init -dir /etc/nebula -values /etc/nebula-values.yml >/dev/null
  sudo cat /etc/nebula/host.pub" > "$WORK/hb-host.pub"
echo "    got harbor host pubkey"

# pilot init's default nebula firewall allows inbound ICMP only — fine for a data-plane
# member, but harbor SERVES core-api + the console over the overlay, so the mesh must be
# allowed to reach those TCP ports inbound (otherwise heartbeat/renew + the console time out:
# ping works, the HTTP call is dropped). Patch the firewall BEFORE nebula starts. The ports
# follow CORE_PORT/ADMIN_PORT (passed as argv), so moving the console to 443 stays consistent.
echo "==> [harbor] open nebula firewall for control-plane ports (core-api $CORE_PORT + console $ADMIN_PORT + collect-metrics $COLLECT_OBS_PORT)"
rsh "$HB_ID" 'sudo python3 - /etc/nebula/config.yml '"$CORE_PORT $ADMIN_PORT $COLLECT_OBS_PORT"' <<PY
import sys
p = sys.argv[1]
ports = [int(a) for a in sys.argv[2:]]
lines = open(p).read().splitlines()
out, i, done = [], 0, False
while i < len(lines):
    out.append(lines[i])
    if (not done and lines[i].strip() == "proto: icmp"
            and i + 1 < len(lines) and lines[i + 1].strip().startswith("host:")):
        out.append(lines[i + 1])
        for port in ports:
            out += ["    - port: %d" % port, "      proto: tcp", "      host: any"]
        done = True
        i += 2
        continue
    i += 1
open(p, "w").write("\n".join(out) + "\n")
msg = "firewall: added inbound tcp " + "+".join(str(x) for x in ports)
print(msg if done else "firewall: PATTERN NOT FOUND (left unchanged)")
PY'

# ── 3. harbor: migrate + genesis (lighthouse + HARBOR control-plane certs) ───
echo "==> [harbor] migrate + genesis (incl. -core-pub for Harbor's control-plane cert)"
rcp "$WORK/lh-host.pub" "$SSH_USER@$HB_ID:/tmp/lh-host.pub"
rcp "$WORK/hb-host.pub" "$SSH_USER@$HB_ID:/tmp/hb-host.pub"
rsh "$HB_ID" "set -e
  mkdir -p ~/ncp
  harbor migrate up $HARBOR_DB_FLAGS >/dev/null
  harbor genesis $HARBOR_DB_FLAGS -out ~/ncp/genesis${GENESIS_BACKEND:+ $GENESIS_BACKEND} \
    -operator-a alice -operator-b bob -pool '$POOL' \
    -lighthouse-pub /tmp/lh-host.pub -lighthouse-ip '$LH_OVERLAY' -lighthouse-addr '$LH_ADDR' \
    -core-pub /tmp/hb-host.pub -core-ip '$HARBOR_OVERLAY' -core-name harbor-core >/dev/null
  echo ok"
rcp "$SSH_USER@$HB_ID:ncp/genesis/ca.crt"             "$WORK/ca.crt"
rcp "$SSH_USER@$HB_ID:ncp/genesis/lighthouse-1.crt"   "$WORK/lighthouse-1.crt"
rcp "$SSH_USER@$HB_ID:ncp/genesis/harbor-core.crt"    "$WORK/harbor-core.crt"
rcp "$SSH_USER@$HB_ID:ncp/genesis/config-signing.pub" "$WORK/config-signing.pub"
echo "    genesis done; pulled ca.crt + lighthouse + harbor-core certs + config-signing pin"

# ── 3d. SSO material (ADR 0004) — only when SSO is enabled ───────────────────
# Genesis ALWAYS mints the dedicated assertion keypair (sso-assert.key/.pub, decision B15),
# but we only DISTRIBUTE it (and mint the SP keypair) when the operator turned SSO on. The
# assertion private half goes to the gateway, the public half is pinned on Core. The SAML SP
# signing keypair must be STABLE + recoverable (the IdP app pins the SP cert) — so it is minted
# ONCE here at genesis (a self-signed RSA pair, what crewjam SAML requires; the assertion key is
# ECDSA and lives in genesis, the SP key is RSA and lives in the recover bundle) and snapshotted
# into the harbor-config bundle alongside the other keys, so MODE=recover restores it byte-identical.
if [[ "$SSO_ENABLED" -eq 1 ]]; then
  echo "==> [harbor] SSO: pull the genesis assertion keypair + mint the STABLE SAML SP keypair"
  rcp "$SSH_USER@$HB_ID:ncp/genesis/sso-assert.key" "$WORK/sso-assert.key"   # gateway's assertion-signing PRIVATE half (S6)
  rcp "$SSH_USER@$HB_ID:ncp/genesis/sso-assert.pub" "$WORK/sso-assert.pub"   # Core pins this PUBLIC half
  # Mint the SP keypair on harbor (it has openssl); RSA-2048 self-signed, long-lived (the IdP
  # app pins it, so it must not rotate on a task restart). Idempotent: keep an existing one.
  rsh "$HB_ID" "set -e
    cd ~/ncp; umask 077
    if [ ! -f sso-sp.key ] || [ ! -f sso-sp.crt ]; then
      openssl req -x509 -newkey rsa:2048 -keyout sso-sp.key -out sso-sp.crt -days 3650 -nodes \
        -subj '/CN=ncp-sso-portal-sp' >/dev/null 2>&1
      chmod 600 sso-sp.key
    fi
    echo ok"
  rcp "$SSH_USER@$HB_ID:ncp/sso-sp.crt" "$WORK/sso-sp.crt"
  rcp "$SSH_USER@$HB_ID:ncp/sso-sp.key" "$WORK/sso-sp.key"
  # The operator-supplied IdP metadata: stage it into $WORK so the gateway-secret assembly +
  # the recover-bundle snapshot can embed it verbatim. From a file, or fetched from the URL.
  if [[ -n "$SSO_IDP_METADATA_FILE" ]]; then
    cp "$SSO_IDP_METADATA_FILE" "$WORK/sso-idp-metadata.xml"
  else
    curl -fsSL "$SSO_IDP_METADATA_URL" -o "$WORK/sso-idp-metadata.xml" \
      || { echo "FATAL: failed to fetch SSO_IDP_METADATA_URL=$SSO_IDP_METADATA_URL" >&2; exit 1; }
  fi
  echo "    SSO material ready: assertion keypair (genesis) + SP keypair (minted, stable) + IdP metadata"
fi

# ── 4. lighthouse: install issued cert + start ──────────────────────────────
if [[ "$LIGHTHOUSE_RUNTIME" == "ec2" ]]; then
  echo "==> [lighthouse/ec2] install cert + start nebula"
  rcp "$WORK/ca.crt"           "$SSH_USER@$LH_ID:/tmp/ca.crt"
  rcp "$WORK/lighthouse-1.crt" "$SSH_USER@$LH_ID:/tmp/host.crt"
  rsh "$LH_ID" 'set -e
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
fi # end MODE=genesis (steps 1-4); in recover, harbor was restored from the bundle above

# ── 4b. additional lighthouses (HA): mint identity + inject secret + deploy ──
# lighthouse-1 was minted by genesis (step 3) + deployed (step 4). For HA (lighthouse_count>1) the
# app stack also stood up lighthouse-2..N — each its OWN NLB+EIP + an EMPTY config secret. Stand
# each up here: generate a keypair off-box, `harbor lighthouse mint` ON the harbor box (pins the
# reserved overlay IP, issues in group lighthouse, records the enrollment so rotate-cert finds it),
# then inject its secret {ca,cert,key} + force its ECS deploy. Genesis only — on recover the extra
# lighthouses' certs (Secrets Manager) + enrollments (Aurora) survive. They're added to the
# discovery registry alongside lighthouse-1 in the -lighthouse-db step below (which runs in both modes).
if [[ "$MODE" != "recover" && "$LIGHTHOUSE_RUNTIME" == "fargate" && "$LH_COUNT" -gt 1 ]]; then
  for i in "${!LH_NAMES[@]}"; do
    [[ "$i" == 0 ]] && continue # lighthouse-1 handled by genesis + step 4
    ln="${LH_NAMES[$i]}"; lip="${LH_OVERLAYS[$i]}"
    echo "==> [lighthouse/fargate] $ln @ $lip: mint identity + inject secret + deploy (HA)"
    "$WORK/pilot" init -am-lighthouse -dir "$WORK/lhkeys-$ln" >/dev/null
    rcp "$WORK/lhkeys-$ln/host.pub" "$SSH_USER@$HB_ID:/tmp/$ln.pub"
    # Mint ON the harbor box (it holds the CA backend + DB); the new cert is mint's stdout.
    LH_CRT="$(rsh "$HB_ID" "harbor lighthouse mint $HARBOR_DB_FLAGS $ROTATE_BACKEND -ca-cert ~/ncp/genesis/ca.crt -name '$ln' -ip '$lip' -in-pub /tmp/$ln.pub -pool '$POOL' 2>/dev/null; rm -f /tmp/$ln.pub")"
    [[ -n "$LH_CRT" ]] || { echo "FATAL: minting $ln produced no cert" >&2; exit 1; }
    LH_SECRET_JSON="$(jq -n --rawfile ca "$WORK/ca.crt" --arg crt "$LH_CRT" --rawfile key "$WORK/lhkeys-$ln/host.key" \
      '{ca_crt_pem:$ca, host_crt_pem:$crt, host_key_pem:$key}')"
    aws secretsmanager put-secret-value --region "$TF_REGION" \
      --secret-id "${NAME_PREFIX}-${ln}-config" --secret-string "$LH_SECRET_JSON" >/dev/null
    aws ecs update-service --region "$TF_REGION" \
      --cluster "${NAME_PREFIX}-lighthouse" --service "${NAME_PREFIX}-${ln}" --force-new-deployment >/dev/null
    echo "    $ln minted ($lip), secret populated, ECS deploy forced"
  done
fi

# ── 5. harbor: install control-plane cert + join the mesh ───────────────────
echo "==> [harbor] install control-plane cert + start nebula UNDER PILOT (joins at $HARBOR_OVERLAY; heartbeats + auto-renews)"
rcp "$WORK/ca.crt"             "$SSH_USER@$HB_ID:/tmp/ca.crt"
rcp "$WORK/harbor-core.crt"    "$SSH_USER@$HB_ID:/tmp/host.crt"
rcp "$WORK/config-signing.pub" "$SSH_USER@$HB_ID:/tmp/config-signing.pub"   # pilot's bundle-pin
rsh "$HB_ID" "set -e
  sudo install -m0644 /tmp/ca.crt             /etc/nebula/ca.crt
  sudo install -m0644 /tmp/host.crt           /etc/nebula/host.crt
  sudo install -m0644 /tmp/config-signing.pub /etc/nebula/config-signing.pub
  rm -f /tmp/ca.crt /tmp/host.crt /tmp/config-signing.pub
  # Run nebula UNDER pilot (not standalone) so harbor is a MANAGED mesh member: it heartbeats
  # (so it shows up in 'harbor fleet') and auto-renews its own control-plane cert. pilot's
  # drift/renew re-render config.yml from the signed bundle — SAFE for the control-plane node
  # because its bundle always carries the invariant inbound/outbound any/any/any firewall
  # (bundle.CompileFirewall), a SUPERSET of the hand-opened control-plane ports, whether or not a
  # policy is published. -core is harbor's OWN core-api over the mesh; pilot just warns+retries
  # the renew/heartbeat until core-api comes up in step 8.
  sudo systemd-run --unit ncp-nebula --collect /usr/local/bin/pilot supervise -dir /etc/nebula -config /etc/nebula/config.yml -core '$CORE_URL' -config-pub /etc/nebula/config-signing.pub >/dev/null
  echo started"
echo "    harbor nebula running under pilot (control-plane node — appears in fleet + auto-renews; firewall from the signed bundle)"

# ── 6. derive this account from the client's IMDS + publish cloud-trust ──────
# Genesis only — on recover the cloud-trust config already lives in Aurora (it survived).
if [[ "$MODE" != "recover" ]]; then
echo "==> deriving AWS account/role/region from the client IMDS + publishing cloud-trust"
IMDS="$(rsh "$CL_ID" 'set -e
  T=$(curl -sX PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
  DOC=$(curl -s -H "X-aws-ec2-metadata-token: $T" http://169.254.169.254/latest/dynamic/instance-identity/document)
  ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $T" http://169.254.169.254/latest/meta-data/iam/security-credentials/)
  echo "$DOC" | tr -d "\n"; echo; echo "$ROLE"')"
ACCOUNT="$(jq -r .accountId <<<"$(head -n1 <<<"$IMDS")")"
REGION="$(jq -r .region    <<<"$(head -n1 <<<"$IMDS")")"
ROLE="$(tail -n1 <<<"$IMDS")"
echo "    account=$ACCOUNT region=$REGION role=$ROLE"
rsh "$HB_ID" "set -e
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
  harbor cloudtrust publish $HARBOR_DB_FLAGS -config ~/ncp/cloudtrust.json \
    -operator-a alice -operator-b bob >/dev/null
  echo ok"
echo "    cloud-trust published (account $ACCOUNT -> [workloads], auto-issue)"
fi # end step 6 (genesis only)

# ── 7. enrollment plane: OFF-MESH gateway node + Harbor's pull collector (ADR 0005) ─
# The gateway is now a SEPARATE, off-mesh node: it serves the public enroll port and
# a Harbor-only mTLS collect port over its LOCAL queue, and initiates nothing. Harbor
# PULLS from it (re-verifying every candidate), issues, and pushes results back. mTLS
# is leaf-pinned: each side self-signs, the peer pins the leaf (no CA).
GW_PORT="${GW_URL##*:}"
COLLECT_PORT="${GW_COLLECT##*:}"

# Mint + push the gateway material — genesis only. On recover, harbor's hmac + collect mTLS were
# restored from the bundle and the gateway/lighthouse are untouched (their config still matches),
# so there is nothing to mint or re-push — we go straight to the (idempotent) register + collector start.
if [[ "$MODE" != "recover" ]]; then
echo "==> [harbor] mint the collector's client identity + the shared nonce key"
rsh "$HB_ID" "set -e
  cd ~/ncp; umask 077
  [ -f hmac.b64 ] || openssl rand 32 | basenc --base64url | tr -d '=' > hmac.b64
  [ -f harbor-collect.key ] || gateway collect-keygen -cn harbor-collector \
    -cert-out harbor-collect.crt -key-out harbor-collect.key >/dev/null
  echo ok"
rcp "$SSH_USER@$HB_ID:ncp/harbor-collect.crt" "$WORK/harbor-collect.crt"  # Harbor's pinned client cert
rcp "$SSH_USER@$HB_ID:ncp/hmac.b64"           "$WORK/hmac.b64"            # shared nonce key (gateway mints, Core verifies)

if [[ "$GATEWAY_RUNTIME" == "ec2" ]]; then
  echo "==> [gateway/ec2] mint server identity + start the off-mesh gateway (enroll :$GW_PORT, collect :$COLLECT_PORT)"
  rcp "$WORK/harbor-collect.crt" "$SSH_USER@$GW_ID:/tmp/harbor-collect.crt"
  rcp "$WORK/hmac.b64"           "$SSH_USER@$GW_ID:/tmp/hmac.b64"
  # SSO (ADR 0004) — deliver the portal material as 0600/0644 files (NOT argv; the EC2 gateway
  # already reads its secrets from files) and add the -sso-* flags. Empty/SSO-off => GW_SSO_FLAGS
  # stays "", the files are never delivered, and the gateway start line is byte-for-byte unchanged.
  GW_SSO_FLAGS=""
  if [[ "$SSO_ENABLED" -eq 1 ]]; then
    rcp "$WORK/sso-assert.key"       "$SSH_USER@$GW_ID:/tmp/sso-assert.key"
    rcp "$WORK/sso-sp.crt"           "$SSH_USER@$GW_ID:/tmp/sso-sp.crt"
    rcp "$WORK/sso-sp.key"           "$SSH_USER@$GW_ID:/tmp/sso-sp.key"
    rcp "$WORK/sso-idp-metadata.xml" "$SSH_USER@$GW_ID:/tmp/sso-idp-metadata.xml"
    rsh "$GW_ID" "set -e
      sudo install -d -o $SSH_USER -g $SSH_USER -m0750 /opt/ncp-gw
      install -m0600 /tmp/sso-assert.key /opt/ncp-gw/sso-assert.key
      install -m0600 /tmp/sso-sp.key /opt/ncp-gw/sso-sp.key
      install -m0644 /tmp/sso-sp.crt /opt/ncp-gw/sso-sp.crt
      install -m0644 /tmp/sso-idp-metadata.xml /opt/ncp-gw/sso-idp-metadata.xml
      rm -f /tmp/sso-assert.key /tmp/sso-sp.key /tmp/sso-sp.crt /tmp/sso-idp-metadata.xml"
    # URLs/strings single-quoted so the remote shell keeps them literal.
    GW_SSO_FLAGS="-sso-acs-url '$SSO_ACS_URL' -sso-entity-id '$SSO_ENTITY_ID' -sso-issuer '$SSO_ISSUER' \
      -sso-assert-key /opt/ncp-gw/sso-assert.key -sso-sp-cert /opt/ncp-gw/sso-sp.crt -sso-sp-key /opt/ncp-gw/sso-sp.key \
      -sso-idp-metadata-file /opt/ncp-gw/sso-idp-metadata.xml"
    [[ -n "$SSO_GROUPS_ATTR" ]] && GW_SSO_FLAGS="$GW_SSO_FLAGS -sso-groups-attr '$SSO_GROUPS_ATTR'"
  fi
  rsh "$GW_ID" "set -e
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
      -collect-key /opt/ncp-gw/gw-collect.key -harbor-client-cert /opt/ncp-gw/harbor-collect.crt $GW_SSO_FLAGS >/dev/null
    cat gw-collect.crt" > "$WORK/gw-collect.crt"
  echo "    gateway up (off-mesh EC2 node; public enroll + Harbor-only collect$( [[ "$SSO_ENABLED" -eq 1 ]] && echo ' + SSO portal'))"
else
  # Fargate: no node to start. Mint the gateway's server identity + queue key (on
  # harbor — it has the gateway binary), build/push the image, populate the config
  # secret with the genesis material, and roll the ECS service onto it.
  echo "==> [gateway/fargate] mint server identity + queue key (on harbor)"
  rsh "$HB_ID" "set -e
    cd ~/ncp; umask 077
    [ -f gw-collect.key ] || gateway collect-keygen -cn gateway-1 -cert-out gw-collect.crt -key-out gw-collect.key >/dev/null
    [ -f gw-qkey.b64 ] || openssl rand 32 | basenc --base64url | tr -d '=' > gw-qkey.b64
    echo ok"
  rcp "$SSH_USER@$HB_ID:ncp/gw-collect.crt" "$WORK/gw-collect.crt"
  rcp "$SSH_USER@$HB_ID:ncp/gw-collect.key" "$WORK/gw-collect.key"
  rcp "$SSH_USER@$HB_ID:ncp/gw-qkey.b64"    "$WORK/gw-qkey.b64"

  echo "==> [gateway/fargate] build + push the gateway image to ECR"
  bash "$ROOT/deploy/prod/fargate/build-push.sh" gateway

  echo "==> [gateway/fargate] populate the config secret ${NAME_PREFIX}-gateway-config + force the ECS deploy"
  # SSO (ADR 0004) — when enabled, fold the portal material into the SAME config secret as
  # NCP_GW_SSO_* fields (the terraform task def injects each as an env var; cmd/gateway/sso.go
  # reads them env-first). When SSO is OFF, GW_SSO_JSON still carries all eight sso_* keys EMPTY:
  # the task def references them UNCONDITIONALLY (gateway_fargate.tf `secrets`), so every key must
  # exist in the secret or ECS can't resolve the valueFrom and the task fails to start (a `{}` here
  # was the cause of the gateway-config drift). Empty => the gateway stays fail-closed-disabled
  # (cmd/gateway/sso.go: nil Config.SSO unless sso_acs_url is set), so behavior is unchanged.
  GW_SSO_JSON='{"sso_acs_url":"","sso_entity_id":"","sso_issuer":"","sso_groups_attr":"","sso_idp_metadata":"","sso_assert_key_pem":"","sso_sp_cert_pem":"","sso_sp_key_pem":""}'
  if [[ "$SSO_ENABLED" -eq 1 ]]; then
    GW_SSO_JSON="$(jq -n \
      --rawfile akey "$WORK/sso-assert.key" \
      --rawfile spc  "$WORK/sso-sp.crt" \
      --rawfile spk  "$WORK/sso-sp.key" \
      --rawfile idp  "$WORK/sso-idp-metadata.xml" \
      --arg acs    "$SSO_ACS_URL" \
      --arg ent    "$SSO_ENTITY_ID" \
      --arg iss    "$SSO_ISSUER" \
      --arg grp    "$SSO_GROUPS_ATTR" \
      '{sso_acs_url:$acs, sso_entity_id:$ent, sso_issuer:$iss, sso_groups_attr:$grp,
        sso_idp_metadata:$idp, sso_assert_key_pem:$akey, sso_sp_cert_pem:$spc, sso_sp_key_pem:$spk}')"
  fi
  SECRET_JSON="$(jq -n \
    --rawfile hmac "$WORK/hmac.b64" \
    --rawfile qkey "$WORK/gw-qkey.b64" \
    --rawfile cert "$WORK/gw-collect.crt" \
    --rawfile key  "$WORK/gw-collect.key" \
    --rawfile hcli "$WORK/harbor-collect.crt" \
    --argjson sso "$GW_SSO_JSON" \
    '{hmac_key_b64:($hmac|rtrimstr("\n")), queue_key_b64:($qkey|rtrimstr("\n")),
      collect_cert_pem:$cert, collect_key_pem:$key, harbor_client_pem:$hcli} + $sso')"
  aws secretsmanager put-secret-value --region "$TF_REGION" \
    --secret-id "${NAME_PREFIX}-gateway-config" --secret-string "$SECRET_JSON" >/dev/null
  aws ecs update-service --region "$TF_REGION" \
    --cluster "${NAME_PREFIX}-gateway" --service "${NAME_PREFIX}-gateway" --force-new-deployment >/dev/null
  echo "    gateway image pushed, secret populated, ECS deployment forced (off-mesh Fargate; NLB enroll + Harbor-only collect)"
fi
fi # end step 7 mint+gateway (genesis only)

# Core SSO flags (ADR 0004) — added to ALL THREE issuing consumers (collect runs processSSO;
# core-api + admin-api go through buildConsumer / the approve path). -sso-assert-pub pins the
# gateway's assertion-signing PUBLIC half (genesis sso-assert.pub on the box); -usertrust-db
# enables the LIVE per-enrollment user-trust getter. Empty/SSO-off => CORE_SSO_FLAGS stays ""
# and every invocation is byte-for-byte unchanged (Core then denies any SSO enrollment with the
# existing terminal ErrSSONotConfigured — fail closed). \$G expands remotely to ~/ncp/genesis.
CORE_SSO_FLAGS=""
[[ "$SSO_ENABLED" -eq 1 ]] && CORE_SSO_FLAGS="-sso-assert-pub \$G/sso-assert.pub -usertrust-db"

# Build the lighthouse register+verify commands (one per HA lighthouse). Values expand LOCALLY
# here; the resulting commands run on the harbor box inside the core/collect-start rsh below — so
# EVERY lighthouse (1..N) is in the registry as the -lighthouse-db authoritative source before any
# -lighthouse-db service starts (an empty/partial registry would drop lighthouses from bundles).
LH_REGISTER_BLOCK=""
for i in "${!LH_NAMES[@]}"; do
  LH_REGISTER_BLOCK+="  harbor lighthouse list $HARBOR_DB_FLAGS 2>/dev/null | grep -Fq '${LH_OVERLAYS[$i]}' || harbor lighthouse add $HARBOR_DB_FLAGS -ip '${LH_OVERLAYS[$i]}' -addrs '${LH_PUBADDRS[$i]}' -name '${LH_NAMES[$i]}' -actor alice
  harbor lighthouse list $HARBOR_DB_FLAGS 2>/dev/null | grep -Fq '${LH_OVERLAYS[$i]}' || { echo 'FATAL: lighthouse ${LH_OVERLAYS[$i]} (${LH_NAMES[$i]}) not registered — bundles under -lighthouse-db would carry it as missing' >&2; exit 1; }
"
done

echo "==> [harbor] register the gateway + start the pull collector"
rcp "$WORK/gw-collect.crt" "$SSH_USER@$HB_ID:/tmp/gw-collect.crt"
rsh "$HB_ID" "set -e
  cd ~/ncp
  G=~/ncp/genesis
  install -m0644 /tmp/gw-collect.crt gw-collect.crt; rm -f /tmp/gw-collect.crt
  # Idempotent register: add only if this URL isn't already listed, then VERIFY it is —
  # do NOT swallow a failed registration (a collector with zero gateways drains nothing).
  if ! harbor gateway list $HARBOR_DB_FLAGS 2>/dev/null | grep -Fq '$GW_COLLECT'; then
    harbor gateway add $HARBOR_DB_FLAGS -name gw1 -url '$GW_COLLECT' -cert ~/ncp/gw-collect.crt -actor alice
  fi
  harbor gateway list $HARBOR_DB_FLAGS 2>/dev/null | grep -Fq '$GW_COLLECT' \
    || { echo 'FATAL: gateway gw1 ($GW_COLLECT) not registered with harbor — the collector would pull nothing' >&2; exit 1; }
  # Register EVERY lighthouse (1..N) in the DB registry (idempotent) so the -lighthouse-db services
  # below read them as the AUTHORITATIVE source (like the gateway list) and 'harbor lighthouse list'
  # shows them; the static -lighthouse flag stays as the read-error fallback. VERIFY each landed
  # BEFORE starting any -lighthouse-db service — an EMPTY registry under -lighthouse-db yields bundles
  # with NO lighthouse (the static fallback only triggers on a DB read ERROR, not on an empty result).
  # The per-lighthouse add/verify lines were built locally as \$LH_REGISTER_BLOCK.
$LH_REGISTER_BLOCK
  sudo systemctl reset-failed ncp-collect ncp-core ncp-admin 2>/dev/null || true
  # Run AS ec2-user (owns ~/ncp; on the SQLite backend this keeps harbor.db writable by the CLI/console).
  # -blocklist-db: bundles issued for NEW gateway enrollments carry the live pki.blocklist
  # (7.1) — matches core-api's renew path so a revocation propagates on both enroll and renew.
  # -lighthouse-db: bundles read the DB lighthouse registry (above) as the source of truth; the
  # static -lighthouse flag is kept as the fallback if that registry read ever errors.
  sudo systemd-run --uid=$SSH_USER --gid=$SSH_USER --unit ncp-collect --collect /usr/local/bin/harbor collect -pool '$POOL' \
    $HARBOR_DB_FLAGS -ca-cert \$G/ca.crt $SIGN_BACKEND \
    -hmac-key ~/ncp/hmac.b64 -lighthouse '$LH' -lighthouse-db -cloudtrust-db -blocklist-db -obs-addr $HARBOR_OVERLAY:$COLLECT_OBS_PORT \
    -client-cert ~/ncp/harbor-collect.crt -client-key ~/ncp/harbor-collect.key $CORE_SSO_FLAGS >/dev/null
  echo registered"
echo "    gateway registered + collector pulling (attestation enabled)"

# CLI convenience: drop the HARBOR_DB_* env defaults into /etc/profile.d so a shell on the control-plane
# node can run `harbor <subcommand>` with NO connection flags (the binary reads these as its flag
# defaults — positionals like `enroll approve <id>` included). System-wide → every user (ec2-user AND
# the SSM-created ssm-user). Kept POSIX-sh-SAFE (exports only): the SSM Session Manager shell profile
# sources it in a NON-LOGIN `sh`, which rejects a hyphenated function name — so the harbor-logs helper
# is a standalone /usr/local/bin script (works in sh + bash). No DB password here — harbor fetches the
# rotating credential from Secrets Manager via the instance role.
echo "==> [harbor] install /etc/profile.d/harbor-cli.sh (HARBOR_DB_* env, sh-safe) + /usr/local/bin/harbor-logs"
if [[ "$DB_BACKEND" == "aurora" || "$DB_BACKEND" == "postgres" ]]; then
  HARBOR_CLI_ENV="export HARBOR_DB_DRIVER=postgres
export HARBOR_DSN='postgres://$DB_HOST:$DB_PORT/$DB_NAME?sslmode=require'
export HARBOR_DB_SECRET_ARN='$DB_SECRET_ARN'${TF_REGION:+
export HARBOR_DB_SECRET_REGION='$TF_REGION'}"
else
  HARBOR_CLI_ENV="export HARBOR_DB_DRIVER=sqlite
export HARBOR_DSN='/home/$SSH_USER/ncp/harbor.db'"
fi
rsh "$HB_ID" "sudo tee /etc/profile.d/harbor-cli.sh >/dev/null && sudo chmod 644 /etc/profile.d/harbor-cli.sh" <<RPROF
# Auto-generated by bootstrap-genesis.sh. Lets any shell on the control-plane node (ec2-user OR
# ssm-user) run \`harbor <subcommand>\` with no DB flags: the harbor binary reads these HARBOR_DB_*
# vars as its DB-connection flag defaults. POSIX-sh-safe (exports only) — sourced by login shells AND
# the SSM Session Manager shell profile (a non-login sh). No DB PASSWORD here — harbor fetches the
# rotating credential from Secrets Manager via the instance role. An explicit -dsn/-driver wins.
$HARBOR_CLI_ENV
RPROF
# harbor-logs as a standalone script (NOT a profile function — POSIX sh can't define a hyphenated name,
# and the SSM session shell is sh). Tails the control-plane units; sudo-fallback when not in the
# systemd-journal group (ssm-user). Quoted heredoc → \$#/\$@/\$jc stay literal.
rsh "$HB_ID" "sudo tee /usr/local/bin/harbor-logs >/dev/null && sudo chmod 755 /usr/local/bin/harbor-logs" <<'RLOGS'
#!/usr/bin/env bash
# Tail the harbor control-plane units.  harbor-logs -f   |   harbor-logs -n 100 -u ncp-admin
[ "$#" -eq 0 ] && set -- -n 50
jc=journalctl
id -nG 2>/dev/null | tr ' ' '\n' | grep -qx systemd-journal || jc="sudo journalctl"
exec $jc -u ncp-core -u ncp-collect -u ncp-admin -u ncp-nebula "$@"
RLOGS
echo "    harbor CLI env + harbor-logs installed (run 'harbor joinkey list' etc. with no flags)"

# SSM convenience (account/region-wide): Session Manager runs a NON-LOGIN `sh`, which does NOT source
# /etc/profile.d — so an `ssm-user` shell wouldn't pick up HARBOR_DB_* and `harbor` would fall back to
# sqlite. Ensure the Session Manager shell profile sources the harbor env at session start. Idempotent:
# create ONLY if the doc is absent (never clobber existing Session Manager logging/KMS prefs). The
# shellProfile is guarded, so it's a no-op on instances without /etc/profile.d/harbor-cli.sh.
echo "==> [account] ensure SSM Session Manager shell profile loads the harbor CLI env (for ssm-user)"
if [[ -n "$TF_REGION" ]] && command -v aws >/dev/null 2>&1; then
  if aws ssm get-document --name SSM-SessionManagerRunShell --region "$TF_REGION" >/dev/null 2>&1; then
    echo "    SSM-SessionManagerRunShell already exists — leaving it (ensure its shellProfile.linux sources /etc/profile.d/harbor-cli.sh)"
  else
    aws ssm create-document --name SSM-SessionManagerRunShell --document-type Session --document-format JSON \
      --region "$TF_REGION" \
      --content '{"schemaVersion":"1.0","description":"Session Manager preferences - source the harbor CLI env (HARBOR_DB_*) so harbor subcommands work without flags.","sessionType":"Standard_Stream","inputs":{"shellProfile":{"linux":"[ -f /etc/profile.d/harbor-cli.sh ] && . /etc/profile.d/harbor-cli.sh"}}}' >/dev/null \
      && echo "    created SSM-SessionManagerRunShell (ssm-user sessions now load the harbor env)" \
      || echo "    WARN: could not create SSM-SessionManagerRunShell — set the Session Manager shell profile manually if you use ssm-user"
  fi
else
  echo "    (skipped: no region/aws CLI — set the Session Manager shell profile manually for ssm-user)"
fi

# ── lighthouse cert rotation (Fargate lighthouse only) ───────────────────────
# The Fargate lighthouse can't self-renew: core-api's host-renew is authed by the caller's source
# overlay IP, which an off-box re-mint doesn't have. Install a timer ON the harbor box that re-mints
# the lighthouse cert against the CA (KMS via the instance role's core_kms_sign grant), re-injects it
# into the lighthouse secret, and forces an ECS redeploy. rotate-if-within makes it a no-op until
# ~90d before expiry, so the monthly timer is near-instant until then. Runs in BOTH genesis + recover
# (a recovered harbor must still rotate the lighthouse). IAM: app stack core_lighthouse_rotate
# (count = lh_fargate). See deploy/prod/lighthouse-rotate/.
if [[ "$LIGHTHOUSE_RUNTIME" == "fargate" ]]; then
  echo "==> [harbor] install the Fargate lighthouse cert-rotation timer"
  LR="$ROOT/deploy/prod/lighthouse-rotate"
  rcp "$LR/rotate-lighthouse-cert.sh"        "$SSH_USER@$HB_ID:/tmp/rotate-lighthouse-cert.sh"
  rcp "$LR/harbor-lighthouse-rotate.service" "$SSH_USER@$HB_ID:/tmp/harbor-lighthouse-rotate.service"
  rcp "$LR/harbor-lighthouse-rotate.timer"   "$SSH_USER@$HB_ID:/tmp/harbor-lighthouse-rotate.timer"
  # One tuple per lighthouse: name:secret:cluster:service. The rotation script health-gates between
  # them (one redeploy at a time) so an HA rotation is blip-free. Names match the terraform rname:
  # lighthouse-1 keeps the legacy ncp-lighthouse(-config); the rest are ncp-<name>(-config). Shared
  # cluster ncp-lighthouse.
  LH_ROTATE_TUPLES=""
  for i in "${!LH_NAMES[@]}"; do
    _rn="${NAME_PREFIX}-lighthouse"; [[ "$i" != 0 ]] && _rn="${NAME_PREFIX}-${LH_NAMES[$i]}"
    LH_ROTATE_TUPLES+="${LH_NAMES[$i]}:${_rn}-config:${NAME_PREFIX}-lighthouse:${_rn} "
  done
  LH_ROTATE_TUPLES="${LH_ROTATE_TUPLES% }"
  rsh "$HB_ID" "sudo tee /etc/nebula/lighthouse-rotate.env >/dev/null && sudo chmod 600 /etc/nebula/lighthouse-rotate.env" <<RENV
# Auto-generated by bootstrap-genesis.sh — config for rotate-lighthouse-cert.sh (run by
# harbor-lighthouse-rotate.timer). All auth (KMS sign, Secrets Manager, ECS, Aurora) is via the
# harbor instance role; NO credentials live here. -kms-key-id is the single-key form addBackendFlags
# wants (not genesis' -kms-ca-key-id). DB/backend flag values are space-free (unquoted-expanded).
REGION=$TF_REGION
CA_CERT=/etc/nebula/ca.crt
BACKEND_FLAGS="$ROTATE_BACKEND"
POOL=$POOL
LIFETIME=8760h
WITHIN=2160h
HARBOR_DB_FLAGS="$HARBOR_DB_FLAGS_HINT"
LIGHTHOUSES="$LH_ROTATE_TUPLES"
RENV
  rsh "$HB_ID" 'set -e
    sudo install -m0755 /tmp/rotate-lighthouse-cert.sh        /usr/local/bin/rotate-lighthouse-cert.sh
    sudo install -m0644 /tmp/harbor-lighthouse-rotate.service /etc/systemd/system/harbor-lighthouse-rotate.service
    sudo install -m0644 /tmp/harbor-lighthouse-rotate.timer   /etc/systemd/system/harbor-lighthouse-rotate.timer
    rm -f /tmp/rotate-lighthouse-cert.sh /tmp/harbor-lighthouse-rotate.service /tmp/harbor-lighthouse-rotate.timer
    sudo systemctl daemon-reload
    sudo systemctl enable --now harbor-lighthouse-rotate.timer >/dev/null
    echo enabled'
  echo "    lighthouse-rotate timer enabled (monthly; re-signs only within ~90d of expiry, then redeploys ECS)"
fi

# imac (off-cloud, no AWS identity) joins via a join key with manual approval. Genesis only — on
# recover the imac's existing enrollment is unaffected (its cert validates against the same CA).
IMAC_KEY=""
if [[ "$MODE" != "recover" ]]; then
  echo "==> [harbor] create the imac join key"
  IMAC_KEY="$(rsh "$HB_ID" "harbor joinkey create $HARBOR_DB_FLAGS -name imac -groups laptops 2>/dev/null | grep -o 'njk_[A-Za-z0-9_-]*' || true")"
fi

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
    || { echo "FATAL: Cloudflare token secret is empty/placeholder — run deploy/prod/init-secrets.sh (with NCP_CF_GPG set) before 'terraform apply' so the secret is created with your scoped Zone.DNS:Edit token." >&2; exit 1; }
  # Write to the SAME literal path the -acme-cloudflare-token-file flag uses (so they can't
  # diverge), and chmod 600 explicitly — `cat >` truncates but does not re-permission an
  # existing file, so a re-run must not leave a looser mode on this credential.
  printf '%s' "$CF_TOKEN" | rsh "$HB_ID" "umask 077; mkdir -p /home/$SSH_USER/ncp/acme; cat > /home/$SSH_USER/ncp/cf-token && chmod 600 /home/$SSH_USER/ncp/cf-token"
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
if [[ "$MODE" == "recover" && "${SAML_RESTORED:-0}" == "1" ]]; then
  # RECOVER: the console SAML material (SP keypair [+ idp-metadata.xml] + role-map/entity/groups/
  # metadata-url) was restored to the box + into these vars from the ncp-harbor-config bundle. Build
  # the SAME production flags from the box-resident paths — NO operator env needed, so a recovered
  # console comes back on real Entra (not the dev mock-IdP). Fully durable console SSO.
  echo "==> [harbor] console SAML restored from the bundle (production posture)"
  IDP_FLAGS="-saml-sp-key $SAML_DIR/sp.key -saml-sp-cert $SAML_DIR/sp.crt -role-map '$SAML_ROLE_MAP' -environment production"
  if [[ -n "${SAML_METADATA_URL:-}" ]]; then
    IDP_FLAGS="$IDP_FLAGS -saml-idp-metadata-url '$SAML_METADATA_URL'"
  else
    IDP_FLAGS="$IDP_FLAGS -saml-idp-metadata-file $SAML_DIR/idp-metadata.xml"
  fi
  [[ -n "${SAML_ENTITY_ID:-}" ]] && IDP_FLAGS="$IDP_FLAGS -saml-entity-id '$SAML_ENTITY_ID'"
  IDP_FLAGS="$IDP_FLAGS -saml-groups-attr '${SAML_GROUPS_ATTR:-http://schemas.microsoft.com/ws/2008/06/identity/claims/groups}'"
  echo "    console IdP: Entra SAML [production] — role-map + SP keypair + IdP metadata restored from Secrets Manager"
elif [[ "$MODE" != "recover" && ( -n "${SAML_METADATA_URL:-}" || -n "${SAML_METADATA_FILE:-}" ) ]]; then
  echo "==> [harbor] wire the console to real Entra SAML (production posture)"
  # SAML needs HTTPS: the cross-site ACS cookie is SameSite=None => Secure (set by -environment
  # production), so a plain-HTTP overlay console can never complete login. base-url ($ADMIN_URL) is
  # HTTPS only when the mesh domain (ACME) is set — refuse rather than launch a silently-broken SSO.
  [[ -n "$HARBOR_DOMAIN" ]] || { echo "FATAL: SAML requires HTTPS, but the console would serve plain HTTP at $ADMIN_URL (mesh_name/mesh_domain unset). Set mesh_name + mesh_domain so harbor serves HTTPS via ACME, then re-run." >&2; exit 1; }
  [[ -n "${SAML_SP_KEY_FILE:-}"  && -f "${SAML_SP_KEY_FILE:-}"  ]] || { echo "FATAL: SAML requested but SAML_SP_KEY_FILE is unset/missing (the STABLE SP signing key PEM)" >&2; exit 1; }
  [[ -n "${SAML_SP_CERT_FILE:-}" && -f "${SAML_SP_CERT_FILE:-}" ]] || { echo "FATAL: SAML requested but SAML_SP_CERT_FILE is unset/missing (the SP signing cert PEM)" >&2; exit 1; }
  [[ -n "${SAML_ROLE_MAP:-}" ]] || { echo "FATAL: SAML requested but SAML_ROLE_MAP is unset (e.g. '<entra-admin-group-guid>=admin') — without it every SSO user lands as viewer" >&2; exit 1; }
  # Deliver the SP keypair (key 0600, cert 0644) — bytes preserved via ssh stdin, never argv.
  rsh "$HB_ID" "umask 077; mkdir -p /home/$SSH_USER/ncp/saml; cat > /home/$SSH_USER/ncp/saml/sp.key && chmod 600 /home/$SSH_USER/ncp/saml/sp.key" < "$SAML_SP_KEY_FILE"
  rsh "$HB_ID" "cat > /home/$SSH_USER/ncp/saml/sp.crt && chmod 644 /home/$SSH_USER/ncp/saml/sp.crt" < "$SAML_SP_CERT_FILE"
  # URLs/role-map are single-quoted so the remote shell keeps ';', '&', '?' literal (not command/glob).
  IDP_FLAGS="-saml-sp-key /home/$SSH_USER/ncp/saml/sp.key -saml-sp-cert /home/$SSH_USER/ncp/saml/sp.crt -role-map '$SAML_ROLE_MAP' -environment production"
  if [[ -n "${SAML_METADATA_URL:-}" ]]; then
    IDP_FLAGS="$IDP_FLAGS -saml-idp-metadata-url '$SAML_METADATA_URL'"
  else
    rsh "$HB_ID" "cat > /home/$SSH_USER/ncp/saml/idp-metadata.xml && chmod 644 /home/$SSH_USER/ncp/saml/idp-metadata.xml" < "$SAML_METADATA_FILE"
    IDP_FLAGS="$IDP_FLAGS -saml-idp-metadata-file /home/$SSH_USER/ncp/saml/idp-metadata.xml"
  fi
  [[ -n "${SAML_ENTITY_ID:-}" ]] && IDP_FLAGS="$IDP_FLAGS -saml-entity-id '$SAML_ENTITY_ID'"
  # Entra emits the group claim under its long URI name, but harbor's -saml-groups-attr defaults to
  # "groups" — mismatch => NO group matches the role-map => every SSO user lands as viewer. Default
  # to the Entra claim name (override SAML_GROUPS_ATTR for a different IdP or a renamed claim).
  SAML_GROUPS_ATTR="${SAML_GROUPS_ATTR:-http://schemas.microsoft.com/ws/2008/06/identity/claims/groups}"
  IDP_FLAGS="$IDP_FLAGS -saml-groups-attr '$SAML_GROUPS_ATTR'"
  # Persist the console SAML config to the box (env-free) so the snapshot can bundle it and a
  # recover can rebuild the SAME flags WITHOUT the operator's env — fully durable console SSO.
  # Single-quoted values keep ';'/'='/URI chars literal (GUID/role-map values carry no single quote).
  rsh "$HB_ID" "umask 077; cat > $SAML_DIR/saml.env" <<SAMLENV
SAML_ROLE_MAP='$SAML_ROLE_MAP'
SAML_ENTITY_ID='${SAML_ENTITY_ID:-}'
SAML_GROUPS_ATTR='$SAML_GROUPS_ATTR'
SAML_METADATA_URL='${SAML_METADATA_URL:-}'
SAMLENV
  # The SP advertises ACS/metadata/entity-id derived from base-url ($ADMIN_URL); print the EXACT
  # values (clean https URLs now that the console defaults to 443) the operator registers in Entra so
  # they can't drift. Entity ID is the -saml-entity-id override if set, else the SP metadata URL.
  SAML_ENTITY="${SAML_ENTITY_ID:-$ADMIN_URL/admin/v1/auth/saml/metadata}"
  echo "    console IdP: Entra SAML [production]; SP keypair delivered (0600); role-map=$SAML_ROLE_MAP"
  echo "    register these EXACT values in the Entra Enterprise App (copy them verbatim, including any port):"
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
# Binding a privileged port (<1024, e.g. the default console port 443) needs CAP_NET_BIND_SERVICE:
# the console runs as the non-root service user, and the bind address (the overlay IP) is still a
# privileged port. Grant the cap to the ncp-admin unit only when its port actually needs it. (core-api
# stays on 8444, so it never needs the cap.)
ADMIN_CAP=""; TUNNEL_PRIV_NOTE=""
if [[ "$ADMIN_PORT" -lt 1024 ]]; then
  ADMIN_CAP=" -p AmbientCapabilities=CAP_NET_BIND_SERVICE"
  TUNNEL_PRIV_NOTE="   (the tunnel binds local $ADMIN_PORT, a privileged port — prefix the ssh with 'sudo', or just browse from an on-mesh member: no tunnel needed)"
fi
# Postgres connection-pool tuning for core-api (harbor's -db-* flags / store.go). Effective only
# on the Aurora backend (DB_BACKEND=aurora); SQLite is single-writer and IGNORES these. Unset =>
# harbor's built-in defaults (20 open / 5 idle / 30m lifetime). Tune so (Cores × max-open) stays
# under Aurora's max_connections:
#   DB_MAX_OPEN_CONNS   DB_MAX_IDLE_CONNS   DB_CONN_MAX_LIFETIME (a Go duration, e.g. 30m)
DB_POOL_FLAGS=""
[[ -n "${DB_MAX_OPEN_CONNS:-}" ]]    && DB_POOL_FLAGS="$DB_POOL_FLAGS -db-max-open-conns $DB_MAX_OPEN_CONNS"
[[ -n "${DB_MAX_IDLE_CONNS:-}" ]]    && DB_POOL_FLAGS="$DB_POOL_FLAGS -db-max-idle-conns $DB_MAX_IDLE_CONNS"
[[ -n "${DB_CONN_MAX_LIFETIME:-}" ]] && DB_POOL_FLAGS="$DB_POOL_FLAGS -db-conn-max-lifetime $DB_CONN_MAX_LIFETIME"
echo "==> [harbor] start core-api + admin console on the overlay ($HARBOR_OVERLAY, mesh-only)"
rsh "$HB_ID" "set -e
  cd ~/ncp
  QDSN=~/ncp/queue.db; G=~/ncp/genesis
  # core-api runs as $SSH_USER but -host-cert lives in /etc/nebula (root, mode 0700 from
  # pilot init); make the dir traversable so it can read the 0644 host.crt (host.key
  # stays 0600 root). Without this core-api crashes at boot with 'permission denied'.
  sudo chmod o+rx /etc/nebula
  # admin-api needs a local queue key (issuance/approval queue); the bootstrap never minted
  # it, so ncp-admin (the console + its IdP) crashed at boot. Mint it here, like hmac.b64.
  umask 077; [ -f ~/ncp/queue.b64 ] || openssl rand 32 | basenc --base64url | tr -d '=' > ~/ncp/queue.b64
  # core-api: renew + heartbeat over the mesh, verifying its own control-plane cert at boot.
  # -blocklist-db: source pki.blocklist from the DB revocations registry (7.1) so revocations
  # (manual + reaper) actually propagate into renewed host bundles. Without it the blocklist is
  # recorded but never shipped — revocation is silently inert. ALWAYS on (revocation must work).
  sudo systemd-run --uid=$SSH_USER --gid=$SSH_USER --unit ncp-core --collect /usr/local/bin/harbor core-api \
    $HARBOR_DB_FLAGS -ca-cert \$G/ca.crt $SIGN_BACKEND \
    -pool '$POOL' -lighthouse '$LH' -lighthouse-db -host-cert /etc/nebula/host.crt -blocklist-db \
    -addr $HARBOR_OVERLAY:$CORE_PORT$DB_POOL_FLAGS${CORE_SSO_FLAGS:+ $CORE_SSO_FLAGS}${ACME_FLAGS:+ $ACME_FLAGS} >/dev/null
  # admin console: issuance mode (so it can approve enrollments) + SAML/mock IdP. $ADMIN_CAP grants
  # CAP_NET_BIND_SERVICE when the console is on a privileged port (default 443). $CORE_SSO_FLAGS
  # adds -sso-assert-pub + -usertrust-db on the approve path so a pending SSO host can be approved.
  sudo systemd-run --uid=$SSH_USER --gid=$SSH_USER$ADMIN_CAP --unit ncp-admin --collect /usr/local/bin/harbor admin-api \
    $HARBOR_DB_FLAGS -ca-cert \$G/ca.crt $SIGN_BACKEND \
    -hmac-key ~/ncp/hmac.b64 -queue-dsn \$QDSN -queue-key ~/ncp/queue.b64 -pool '$POOL' \
    -addr $HARBOR_OVERLAY:$ADMIN_PORT -base-url $ADMIN_URL \
    $IDP_FLAGS${CORE_SSO_FLAGS:+ $CORE_SSO_FLAGS}${ACME_FLAGS:+ $ACME_FLAGS} >/dev/null
  echo ok"
cp "$WORK/config-signing.pub" "$ROOT/deploy/prod/terraform/app/config-signing.pub"  # gitignored; the pin for clients
echo "    core-api + admin console up"
[[ -n "$DB_POOL_FLAGS" ]] && echo "    core-api postgres pool:$DB_POOL_FLAGS (effective only when harbor runs on postgres)"

# ── 9. snapshot harbor's recoverable identity + config to Secrets Manager ─────
# Make harbor a cattle node (parity with the Fargate gateway/lighthouse, which already read
# their config from Secrets Manager): persist its CA CERT (the public trust anchor — the CA
# KEY stays in KMS), the config-signing pin, harbor's OWN nebula identity (key+cert+config),
# and the shared enrollment secrets (the nonce HMAC + leaf-pinned harbor<->gateway mTLS) to
# ncp-harbor-config. A destroyed/recreated harbor then restores byte-identical from Secrets
# Manager + KMS + Aurora — no re-genesis, which would mint a NEW CA cert (new fingerprint) and
# break every enrolled member, since nebula pins the CA by its certificate fingerprint. The
# operator's creds write it here; harbor's instance role only reads (terraform). Re-runs just
# refresh the snapshot (put-secret-value is idempotent).
if [[ "$MODE" != "recover" && -n "$HARBOR_CONFIG_ARN" ]]; then
  echo "==> [harbor] snapshot identity + config to ${NAME_PREFIX}-harbor-config (Secrets Manager)"
  # Pull harbor's on-box material to $WORK. The private keys come back over ssh (sudo cat for the
  # root-owned /etc/nebula key), never on argv — same posture as the Fargate gateway-secret assembly.
  rsh "$HB_ID" 'sudo cat /etc/nebula/host.key'   > "$WORK/hb-host.key"
  rsh "$HB_ID" 'sudo cat /etc/nebula/host.crt'   > "$WORK/hb-host.crt"
  rsh "$HB_ID" 'sudo cat /etc/nebula/config.yml' > "$WORK/hb-config.yml"
  rsh "$HB_ID" 'cat ~/ncp/harbor-collect.key'    > "$WORK/harbor-collect.key"
  rsh "$HB_ID" 'cat ~/ncp/queue.b64'             > "$WORK/queue.b64"
  # The ACME cert cache (account + the issued LE cert/key) — so a recovered harbor REUSES the cert
  # rather than re-issuing (which would risk Let's Encrypt rate limits). A tar.gz, base64 into the
  # bundle; empty when no cert has been obtained yet (recover then issues fresh, now that the
  # autotls propagation check uses public resolvers — see internal/autotls).
  rsh "$HB_ID" 'cd ~/ncp && tar -czf - acme 2>/dev/null | base64 -w0 || true' > "$WORK/acme.tgz.b64"
  # SSO (ADR 0004) — snapshot the portal material so MODE=recover reconstructs SSO byte-identical:
  # the assertion keypair (Core pins the public half, the gateway signs with the private half), the
  # STABLE SP keypair (the IdP app pins the SP cert — it MUST survive a recreate), the IdP metadata,
  # and the ACS/entity/issuer/groups knobs. When SSO is OFF, SSO_BUNDLE_JSON is {} so the bundle is
  # byte-for-byte the pre-SSO object (recover then sees an empty sso_acs_url => SSO stays off).
  SSO_BUNDLE_JSON='{}'
  if [[ "$SSO_ENABLED" -eq 1 ]]; then
    SSO_BUNDLE_JSON="$(jq -n \
      --rawfile apriv "$WORK/sso-assert.key" \
      --rawfile apub  "$WORK/sso-assert.pub" \
      --rawfile spc   "$WORK/sso-sp.crt" \
      --rawfile spk   "$WORK/sso-sp.key" \
      --rawfile idp   "$WORK/sso-idp-metadata.xml" \
      --arg acs "$SSO_ACS_URL" --arg ent "$SSO_ENTITY_ID" --arg iss "$SSO_ISSUER" --arg grp "$SSO_GROUPS_ATTR" \
      '{sso_assert_priv_pem:$apriv, sso_assert_pub_pem:$apub, sso_sp_cert_pem:$spc, sso_sp_key_pem:$spk,
        sso_idp_metadata:$idp, sso_acs_url:$acs, sso_entity_id:$ent, sso_issuer:$iss, sso_groups_attr:$grp}')"
  fi
  # Console SAML (admin login) — snapshot the role-map + STABLE SP keypair + IdP metadata so
  # MODE=recover reconstructs real-Entra console SSO byte-identical (else recover silently reverts to
  # the dev mock-IdP + drops the admin role-map). Read straight off the box ($SAML_DIR/saml.env +
  # the SP keypair / idp-metadata), so a later MODE=snapshot refresh needs no operator env. Empty
  # (no saml.env => SAML off) => the bundle is byte-for-byte the pre-SAML object.
  SAML_BUNDLE_JSON='{}'
  if rsh "$HB_ID" "test -f $SAML_DIR/saml.env" >/dev/null 2>&1; then
    rsh "$HB_ID" "cat $SAML_DIR/sp.key"                              > "$WORK/saml-sp.key"
    rsh "$HB_ID" "cat $SAML_DIR/sp.crt"                              > "$WORK/saml-sp.crt"
    rsh "$HB_ID" "cat $SAML_DIR/idp-metadata.xml 2>/dev/null || true" > "$WORK/saml-idp.xml"
    eval "$(rsh "$HB_ID" "cat $SAML_DIR/saml.env")" # our file; sets SAML_ROLE_MAP/ENTITY_ID/GROUPS_ATTR/METADATA_URL
    SAML_BUNDLE_JSON="$(jq -n \
      --rawfile spk "$WORK/saml-sp.key" --rawfile spc "$WORK/saml-sp.crt" --rawfile idp "$WORK/saml-idp.xml" \
      --arg rm "$SAML_ROLE_MAP" --arg ent "${SAML_ENTITY_ID:-}" --arg grp "${SAML_GROUPS_ATTR:-}" --arg url "${SAML_METADATA_URL:-}" \
      '{saml_sp_key_pem:$spk, saml_sp_cert_pem:$spc, saml_idp_metadata:$idp,
        saml_role_map:$rm, saml_entity_id:$ent, saml_groups_attr:$grp, saml_metadata_url:$url}')"
  fi
  # ca.crt, config-signing.pub, harbor-collect.crt, gw-collect.crt, hmac.b64 are already in $WORK.
  HARBOR_BUNDLE_JSON="$(jq -n \
    --rawfile ca     "$WORK/ca.crt" \
    --rawfile cfgpub "$WORK/config-signing.pub" \
    --rawfile hkey   "$WORK/hb-host.key" \
    --rawfile hcrt   "$WORK/hb-host.crt" \
    --rawfile hcfg   "$WORK/hb-config.yml" \
    --rawfile hmac   "$WORK/hmac.b64" \
    --rawfile hccrt  "$WORK/harbor-collect.crt" \
    --rawfile hckey  "$WORK/harbor-collect.key" \
    --rawfile qkey   "$WORK/queue.b64" \
    --rawfile gwcrt  "$WORK/gw-collect.crt" \
    --rawfile acmeb64 "$WORK/acme.tgz.b64" \
    --argjson sso "$SSO_BUNDLE_JSON" \
    --argjson saml "$SAML_BUNDLE_JSON" \
    '{ca_crt_pem:$ca, config_signing_pub_pem:$cfgpub, host_key_pem:$hkey, host_crt_pem:$hcrt,
      host_config_yml:$hcfg, hmac_key_b64:($hmac|rtrimstr("\n")), harbor_collect_cert_pem:$hccrt,
      harbor_collect_key_pem:$hckey, queue_key_b64:($qkey|rtrimstr("\n")), gw_collect_cert_pem:$gwcrt,
      acme_cache_tgz_b64:($acmeb64|rtrimstr("\n"))} + $sso + $saml')"
  aws secretsmanager put-secret-value --region "$TF_REGION" \
    --secret-id "$HARBOR_CONFIG_ARN" --secret-string "$HARBOR_BUNDLE_JSON" >/dev/null
  echo "    snapshot stored — harbor is recoverable from Secrets Manager + KMS + Aurora$( [[ "$SSO_ENABLED" -eq 1 ]] && echo ' (incl. SSO material)')"
fi

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

# SSO status line for the summary. Empty (SSO off, the default) => the banner is byte-identical
# to the pre-SSO output. When on, remind the operator of the still-manual steps (the AD app +
# the user-trust config) — without them SSO is wired but cannot reach issuance.
SSO_NOTE=""
if [[ "$SSO_ENABLED" -eq 1 ]]; then
  SSO_NOTE="
 SSO (ADR 0004)    : enrollment portal ENABLED on the gateway — ACS $SSO_ACS_URL
                     STILL MANUAL: (1) register the SECOND SAML app in the IdP with
                       Identifier=$SSO_ENTITY_ID and Reply URL (ACS)=$SSO_ACS_URL (distinct
                       from the console app); (2) publish a user-trust config mapping AD groups
                       -> mesh groups + CIDR (\`harbor usertrust publish\` or the console's User
                       Trust page) — until then every SSO enrollment is denied (fail closed).
                     Enroll a laptop:  pilot enroll --sso -gateway $GW_URL -config-pub <pin> -name <host>"
fi

# On recover the cloud-trust step (which sets ACCOUNT/ROLE/REGION from the client IMDS) is skipped —
# that config already persists in Aurora — so default them here, or the summary trips set -u.
ACCOUNT="${ACCOUNT:-<unchanged; cloud-trust persists in Aurora>}"
ROLE="${ROLE:-<unchanged>}"
REGION="${REGION:-$TF_REGION}"
BANNER="$([[ "$MODE" == "recover" ]] && echo "HARBOR RECOVER COMPLETE  (restored from Secrets Manager + KMS + Aurora)" || echo "GENESIS BOOTSTRAP COMPLETE  (control plane + data plane)")"

# Lighthouse summary line(s): one per HA lighthouse (overlay @ underlay).
LH_SUMMARY=""
for i in "${!LH_NAMES[@]}"; do
  [[ "$i" == 0 ]] && LH_SUMMARY="${LH_NAMES[$i]} ${LH_OVERLAYS[$i]} @ ${LH_PUBADDRS[$i]}" \
    || LH_SUMMARY+="
                     ${LH_NAMES[$i]} ${LH_OVERLAYS[$i]} @ ${LH_PUBADDRS[$i]}"
done

cat <<EOF

────────────────────────────────────────────────────────────────────────────
 $BANNER
────────────────────────────────────────────────────────────────────────────
 Gateway (off-mesh): enroll(public) $GW_URL  ·  enroll(in-VPC) $GW_URL_INTERNAL
                     collect $GW_COLLECT  (Harbor-only, mTLS) — Harbor PULLS it, gateway
                     initiates nothing, no mesh identity (ADR 0005). In-VPC clients use the
                     INTERNAL enroll URL (a public NLB isn't reachable from inside the VPC).
 Lighthouse(s)     : $LH_SUMMARY  (pool $POOL)$( [[ "$LH_COUNT" -gt 1 ]] && echo " — HA: blip-free cert rotation" )
 Harbor (mesh)     : $HARBOR_OVERLAY  — core-api :$CORE_PORT, console :$ADMIN_PORT (mesh-only)$HARBOR_TLS_NOTE
 Config-signing pin: deploy/prod/terraform/app/config-signing.pub  (give this to clients)
 Cloud-trust       : account $ACCOUNT / role $ROLE -> groups [workloads], auto-issue$SSO_NOTE

 Enroll the CLOUD CLIENT — KEYLESS via aws-sigv4 attestation (its IAM role). It's IN the
 VPC, so it enrolls via the INTERNAL gateway URL:
   scp -i $SSH_KEY -o "$SSM_PROXY" deploy/prod/terraform/app/config-signing.pub $SSH_USER@$CL_ID:/tmp/
   ssh -i $SSH_KEY -o "$SSM_PROXY" $SSH_USER@$CL_ID \\
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
   ssh -i $SSH_KEY -o "$SSM_PROXY" $SSH_USER@$HB_ID \\
     'EID=\$(harbor enroll pending $HARBOR_DB_FLAGS_HINT | awk "/imac/{print \\\$1}"); \\
      harbor enroll approve \$EID -approver alice $HARBOR_DB_FLAGS_HINT \\
        -ca-cert ~/ncp/genesis/ca.crt $APPROVE_BACKEND \\
        -hmac-key ~/ncp/hmac.b64 -queue-dsn ~/ncp/queue.db -queue-key ~/ncp/queue.b64 \\
        -pool $POOL -lighthouse "$LH"'
   # then re-run the iMac enroll to fetch the bundle; supervise with -core as above.

 Open the ADMIN CONSOLE (mesh-only — reach it from an enrolled mesh member, e.g.
 the iMac once it has joined, in a browser):
     $ADMIN_URL    ($CONSOLE_LOGIN_NOTE; approve enrollments, see
                                            fleet health, policy, cloud-trust, etc.)
   Off-mesh convenience (out-of-band admin path): SSH-tunnel the console —
     ssh -i $SSH_KEY -o "$SSM_PROXY" -L $ADMIN_PORT:$HARBOR_OVERLAY:$ADMIN_PORT$IDP_TUNNEL $SSH_USER@$HB_ID
$TUNNEL_PRIV_NOTE
$TUNNEL_NOTE

 Verify: from any joined node,  ping $LH_OVERLAY  and  ping $HARBOR_OVERLAY ;
         the cloud client should appear in the console's fleet dashboard (heartbeat).
────────────────────────────────────────────────────────────────────────────
EOF
