#!/usr/bin/env bash
# snapshot-harbor.sh — refresh the ncp-harbor-config Secrets Manager bundle from harbor's CURRENT
# live state, WITHOUT a genesis ceremony. Run this after ANY imperative change to the harbor box
# (and/or on a timer), so a MODE=recover / instance-replace reproduces the LIVE harbor, not a
# point-in-time-stale genesis snapshot.
#
# The genesis bootstrap writes the bundle only once (step 9, genesis-only); this keeps it current.
# It MERGES the box-sourced fields (harbor's identity, config.yml, the ACME cert cache, the console
# SAML material, the collect mTLS / hmac / queue keys) OVER the existing bundle — so the genesis-only
# SSO ENROLLMENT-PORTAL material (the assertion PRIVATE key lives on the gateway, never on harbor) is
# PRESERVED from the current secret. Identity keys (host.key/CA) rarely change but are refreshed
# harmlessly; the CA private key stays in KMS and is never in the bundle.
#
# Usage:  [SSH_KEY=~/.ssh/absolute] bash deploy/prod/snapshot-harbor.sh        # run from app/ or repo root
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TFDIR="$ROOT/deploy/prod/terraform/app"
SSH_USER="${SSH_USER:-ec2-user}"
SAML_DIR="/home/$SSH_USER/ncp/saml"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/absolute.pub}"

for t in jq aws terraform ssh; do command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }; done
OUT="$(terraform -chdir="$TFDIR" output -json)"
val() { jq -r "$1 // \"\"" <<<"$OUT"; }
HB_ID="$(val '.instance_ids.value.harbor')"
TF_REGION="$(val '.region.value')"
ARN="$(val '.harbor_config_secret_arn.value')"
NAME_PREFIX="$(val '.name_prefix.value')"; NAME_PREFIX="${NAME_PREFIX:-ncp}"
[[ -n "$HB_ID" && -n "$ARN" ]] || { echo "FATAL: need instance_ids.harbor + harbor_config_secret_arn outputs" >&2; exit 1; }

SSM_PROXY="ProxyCommand=aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p${TF_REGION:+ --region $TF_REGION}"
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o "$SSM_PROXY" -i "$SSH_KEY")
rsh() { ssh "${SSH_OPTS[@]}" "$SSH_USER@$HB_ID" "$@"; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

echo "==> reading the EXISTING ${NAME_PREFIX}-harbor-config bundle (to preserve genesis-only SSO-portal fields)"
PREV="$(aws secretsmanager get-secret-value --region "$TF_REGION" --secret-id "$ARN" --query SecretString --output text)"
[[ -n "$PREV" && "$(jq -r '.ca_crt_pem // ""' <<<"$PREV")" != "" ]] \
  || { echo "FATAL: $ARN is empty — run a MODE=genesis bootstrap first to populate it" >&2; exit 1; }

echo "==> pulling harbor's CURRENT identity + config + keys off the box ($HB_ID via SSM)"
rsh 'sudo cat /etc/nebula/host.key'   > "$WORK/host.key"
rsh 'sudo cat /etc/nebula/host.crt'   > "$WORK/host.crt"
rsh 'sudo cat /etc/nebula/config.yml' > "$WORK/config.yml"           # current static_host_map + firewall
rsh 'cat ~/ncp/genesis/ca.crt'             > "$WORK/ca.crt"
rsh 'cat ~/ncp/genesis/config-signing.pub' > "$WORK/cfg.pub"
rsh 'cat ~/ncp/hmac.b64'              > "$WORK/hmac.b64"
rsh 'cat ~/ncp/harbor-collect.crt'    > "$WORK/hc.crt"
rsh 'cat ~/ncp/harbor-collect.key'    > "$WORK/hc.key"
rsh 'cat ~/ncp/queue.b64'             > "$WORK/queue.b64"
rsh 'cat ~/ncp/gw-collect.crt'        > "$WORK/gw.crt"
rsh 'cd ~/ncp && tar -czf - acme 2>/dev/null | base64 -w0 || true' > "$WORK/acme.b64"

# Console SAML (admin login) — refresh from the box if present (role-map/SP keypair/IdP metadata),
# else carry forward whatever the previous bundle had.
SAML_JSON='{}'
if rsh "test -f $SAML_DIR/saml.env" >/dev/null 2>&1; then
  echo "==> refreshing console SAML material from $SAML_DIR"
  rsh "cat $SAML_DIR/sp.key"                              > "$WORK/saml-sp.key"
  rsh "cat $SAML_DIR/sp.crt"                              > "$WORK/saml-sp.crt"
  rsh "cat $SAML_DIR/idp-metadata.xml 2>/dev/null || true" > "$WORK/saml-idp.xml"
  eval "$(rsh "cat $SAML_DIR/saml.env")"
  SAML_JSON="$(jq -n \
    --rawfile spk "$WORK/saml-sp.key" --rawfile spc "$WORK/saml-sp.crt" --rawfile idp "$WORK/saml-idp.xml" \
    --arg rm "${SAML_ROLE_MAP:-}" --arg ent "${SAML_ENTITY_ID:-}" --arg grp "${SAML_GROUPS_ATTR:-}" --arg url "${SAML_METADATA_URL:-}" \
    '{saml_sp_key_pem:$spk, saml_sp_cert_pem:$spc, saml_idp_metadata:$idp,
      saml_role_map:$rm, saml_entity_id:$ent, saml_groups_attr:$grp, saml_metadata_url:$url}')"
fi

echo "==> merging refreshed fields over the existing bundle + writing back"
# Start from PREV (keeps sso_* portal fields), overlay the refreshed box fields + SAML.
REFRESH="$(jq -n \
  --rawfile ca "$WORK/ca.crt" --rawfile cfgpub "$WORK/cfg.pub" \
  --rawfile hkey "$WORK/host.key" --rawfile hcrt "$WORK/host.crt" --rawfile hcfg "$WORK/config.yml" \
  --rawfile hmac "$WORK/hmac.b64" --rawfile hccrt "$WORK/hc.crt" --rawfile hckey "$WORK/hc.key" \
  --rawfile qkey "$WORK/queue.b64" --rawfile gwcrt "$WORK/gw.crt" --rawfile acmeb64 "$WORK/acme.b64" \
  '{ca_crt_pem:$ca, config_signing_pub_pem:$cfgpub, host_key_pem:$hkey, host_crt_pem:$hcrt,
    host_config_yml:$hcfg, hmac_key_b64:($hmac|rtrimstr("\n")), harbor_collect_cert_pem:$hccrt,
    harbor_collect_key_pem:$hckey, queue_key_b64:($qkey|rtrimstr("\n")), gw_collect_cert_pem:$gwcrt,
    acme_cache_tgz_b64:($acmeb64|rtrimstr("\n"))}')"
NEW="$(jq -n --argjson prev "$PREV" --argjson refresh "$REFRESH" --argjson saml "$SAML_JSON" '$prev + $refresh + $saml')"
aws secretsmanager put-secret-value --region "$TF_REGION" --secret-id "$ARN" --secret-string "$NEW" >/dev/null
echo "    snapshot refreshed — ${NAME_PREFIX}-harbor-config now reflects the live harbor (MODE=recover will reproduce it)$( [[ "$SAML_JSON" != '{}' ]] && echo ' (incl. console SAML)')"
