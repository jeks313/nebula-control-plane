#!/usr/bin/env bash
# rotate-lighthouse-cert.sh — scheduled, idempotent rotation of the Fargate lighthouse's
# nebula certificate. Installed on the HARBOR box (the only place with the CA backend via
# the instance role's KMS grant, the harbor binary, and Aurora access) and driven by
# harbor-lighthouse-rotate.timer.
#
# The Fargate lighthouse cannot self-renew: core-api's host-renew is authenticated by the
# caller's source overlay IP, and a re-mint happens off-box, before the new cert is on the
# mesh. So harbor re-signs the lighthouse cert operator-side against the CA, then re-injects
# it into the lighthouse's Secrets Manager secret and forces an ECS redeploy.
#
# For each configured lighthouse:
#   1. `harbor lighthouse rotate-cert -rotate-if-within $WITHIN` — re-mints in place (same
#      overlay IP, same groups, SAME key) ONLY if the current cert expires within $WITHIN;
#      otherwise it prints nothing and exits 0. So a monthly timer is a near-instant no-op
#      until the cert enters its rotation window.
#   2. If a new cert came back on stdout: patch ONLY host_crt_pem in that lighthouse's secret
#      (jq merge preserves ca_crt_pem + host_key_pem) and force a new ECS deployment so the
#      container restarts onto the fresh cert.
#
# No new cert => no secret write, no redeploy. Auth to KMS / Secrets Manager / ECS / Aurora
# is entirely via the harbor instance role — this script takes no credentials.
#
# Config comes from an env file (default /etc/nebula/lighthouse-rotate.env), written by
# bootstrap-genesis.sh. Override the path as $1 for testing.
set -uo pipefail

CONF="${1:-/etc/nebula/lighthouse-rotate.env}"
[ -r "$CONF" ] || { echo "FATAL: config $CONF not readable" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONF"

: "${REGION:?env: AWS region (for the Secrets Manager + ECS calls)}" \
  "${CA_CERT:?env: path to the public CA cert PEM}" \
  "${BACKEND_FLAGS:?env: harbor CA backend flags, e.g. '-backend kms -kms-key-id arn:... -kms-region ...'}" \
  "${POOL:?env: overlay pool CIDR}" \
  "${LIFETIME:?env: new-cert validity, e.g. 8760h}" \
  "${WITHIN:?env: rotate-if-within window, e.g. 2160h}" \
  "${HARBOR_DB_FLAGS:?env: harbor DB connection flags}" \
  "${LIGHTHOUSES:?env: space/newline-separated name:secret:cluster:service tuples}"
HARBOR_BIN="${HARBOR_BIN:-/usr/local/bin/harbor}"

rc=0
for tuple in $LIGHTHOUSES; do
  IFS=: read -r NAME SECRET CLUSTER SERVICE <<<"$tuple"
  if [ -z "$NAME" ] || [ -z "$SECRET" ] || [ -z "$CLUSTER" ] || [ -z "$SERVICE" ]; then
    echo "ERROR: malformed LIGHTHOUSES tuple '$tuple' (want name:secret:cluster:service)" >&2; rc=1; continue
  fi
  echo "==> $NAME: checking cert (re-sign only if expiring within $WITHIN)"

  # rotate-if-within makes this idempotent: empty stdout => not due => nothing to do.
  # DB + backend flags are deliberately unquoted-expanded: every flag/value is space-free.
  # shellcheck disable=SC2086
  if ! CRT="$("$HARBOR_BIN" lighthouse rotate-cert $HARBOR_DB_FLAGS $BACKEND_FLAGS \
        -ca-cert "$CA_CERT" -name "$NAME" -pool "$POOL" \
        -lifetime "$LIFETIME" -rotate-if-within "$WITHIN")"; then
    echo "  ERROR: rotate-cert failed for $NAME" >&2; rc=1; continue
  fi
  if [ -z "$CRT" ]; then
    echo "  not due — cert still comfortably valid, no rotation"
    continue
  fi

  echo "  re-signed; patching host_crt_pem in $SECRET + forcing ECS redeploy of $SERVICE"
  if ! CUR="$(aws secretsmanager get-secret-value --region "$REGION" \
        --secret-id "$SECRET" --query SecretString --output text)"; then
    echo "  ERROR: read secret $SECRET" >&2; rc=1; continue
  fi
  # Merge: keep ca_crt_pem + host_key_pem, overwrite ONLY host_crt_pem with the new cert.
  if ! NEW="$(jq -n --argjson cur "$CUR" --arg crt "$CRT" '$cur + {host_crt_pem:$crt}')"; then
    echo "  ERROR: jq merge for $SECRET (is the secret valid JSON?)" >&2; rc=1; continue
  fi
  if ! aws secretsmanager put-secret-value --region "$REGION" \
        --secret-id "$SECRET" --secret-string "$NEW" >/dev/null; then
    echo "  ERROR: put secret $SECRET" >&2; rc=1; continue
  fi
  if ! aws ecs update-service --region "$REGION" \
        --cluster "$CLUSTER" --service "$SERVICE" --force-new-deployment >/dev/null; then
    echo "  ERROR: ecs redeploy $SERVICE (secret WAS updated; container will pick up the new cert on next restart)" >&2; rc=1; continue
  fi
  echo "  rotated: $NAME secret updated + ECS redeploy forced"
done
exit $rc
