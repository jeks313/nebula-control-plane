#!/usr/bin/env bash
# Rotate the calling IAM user's AWS access key, safely:
#   1. create a new access key
#   2. verify it authenticates as the same identity (with retries for IAM propagation)
#   3. store the new secret ENCRYPTED (gpg to your own key, or the login keyring)
#   4. deactivate (or delete) the old key
#
# The new secret is NEVER printed and NEVER written unencrypted. If the new key
# fails to verify, the old key is left untouched and the new key is removed.
#
# Auth: pass the CURRENT (old) credentials in the environment, e.g.
#   AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_DEFAULT_REGION=ca-central-1 \
#     bash rotate-aws-key.sh -r you@example.com
#
# Flags:
#   -r <gpg-recipient>   encrypt the new secret to this gpg key/email (default store)
#   -K                   store via secret-tool (GNOME keyring) instead of a gpg file
#   -o <dir>             output dir for the encrypted file (default: $HOME)
#   -d                   DELETE the old key instead of just deactivating it
set -euo pipefail

RECIP=""; USE_KEYRING=0; OUTDIR="$HOME"; DELETE_OLD=0
while getopts "r:Ko:d" opt; do
  case "$opt" in
    r) RECIP="$OPTARG" ;;
    K) USE_KEYRING=1 ;;
    o) OUTDIR="$OPTARG" ;;
    d) DELETE_OLD=1 ;;
    *) echo "usage: $0 [-r gpg-recipient | -K] [-o outdir] [-d]" >&2; exit 2 ;;
  esac
done

need() { command -v "$1" >/dev/null || { echo "missing required tool: $1" >&2; exit 1; }; }
need aws; need jq
[[ -n "${AWS_ACCESS_KEY_ID:-}" && -n "${AWS_SECRET_ACCESS_KEY:-}" ]] || {
  echo "set AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY (the CURRENT key) in the env" >&2; exit 1; }
if [[ "$USE_KEYRING" -eq 1 ]]; then need secret-tool; else need gpg
  [[ -n "$RECIP" ]] || { echo "need -r <gpg-recipient> (or -K for the keyring)" >&2; exit 2; }
fi

OLD_KEY_ID="$AWS_ACCESS_KEY_ID"

echo "==> identity check (current key)"
CALLER="$(aws sts get-caller-identity --output json)"
ARN="$(jq -r .Arn <<<"$CALLER")"; ACCT="$(jq -r .Account <<<"$CALLER")"
USER_NAME="$(aws iam get-user --query 'User.UserName' --output text)"
echo "    account=$ACCT  user=$USER_NAME"

echo "==> creating a new access key for $USER_NAME"
NEW_JSON="$(aws iam create-access-key --user-name "$USER_NAME" --output json)"
NEW_ID="$(jq -r .AccessKey.AccessKeyId <<<"$NEW_JSON")"
NEW_SECRET="$(jq -r .AccessKey.SecretAccessKey <<<"$NEW_JSON")"
NEW_JSON=""
echo "    new access key id: $NEW_ID  (secret captured, not shown)"

echo "==> verifying the new key (IAM is eventually consistent; retrying)"
ok=0
for _ in $(seq 1 12); do
  if V="$(AWS_ACCESS_KEY_ID="$NEW_ID" AWS_SECRET_ACCESS_KEY="$NEW_SECRET" AWS_SESSION_TOKEN="" \
          aws sts get-caller-identity --output json 2>/dev/null)" \
     && [[ "$(jq -r .Arn <<<"$V")" == "$ARN" ]]; then ok=1; break; fi
  sleep 3
done
if [[ "$ok" -ne 1 ]]; then
  echo "!! new key did not verify — leaving the old key ACTIVE and removing the new key." >&2
  aws iam delete-access-key --user-name "$USER_NAME" --access-key-id "$NEW_ID" || true
  exit 1
fi
echo "    verified: new key authenticates as $ARN"

echo "==> storing the new secret (encrypted)"
if [[ "$USE_KEYRING" -eq 1 ]]; then
  printf '%s' "$NEW_SECRET" | secret-tool store --label="AWS $USER_NAME $NEW_ID" \
    service aws account "$ACCT" access-key-id "$NEW_ID"
  echo "    stored in the login keyring."
  echo "    retrieve: secret-tool lookup service aws access-key-id $NEW_ID"
else
  umask 077
  OUT="$OUTDIR/aws-key-$NEW_ID-$(date +%Y%m%d-%H%M%S).env.gpg"
  {
    printf 'AWS_ACCESS_KEY_ID=%s\n' "$NEW_ID"
    printf 'AWS_SECRET_ACCESS_KEY=%s\n' "$NEW_SECRET"
    printf 'AWS_DEFAULT_REGION=%s\n' "${AWS_DEFAULT_REGION:-ca-central-1}"
  } | gpg --batch --yes --trust-model always -r "$RECIP" --encrypt -o "$OUT"
  echo "    wrote $OUT (gpg-encrypted to $RECIP)"
  echo "    load it: export \$(gpg -d -q '$OUT' | xargs)"
fi
NEW_SECRET=""

echo "==> disabling the old key $OLD_KEY_ID"
if [[ "$DELETE_OLD" -eq 1 ]]; then
  aws iam delete-access-key --user-name "$USER_NAME" --access-key-id "$OLD_KEY_ID"
  echo "    DELETED old key $OLD_KEY_ID"
else
  aws iam update-access-key --user-name "$USER_NAME" --access-key-id "$OLD_KEY_ID" --status Inactive
  echo "    deactivated old key $OLD_KEY_ID"
  echo "    delete it once everything is migrated:"
  echo "      aws iam delete-access-key --user-name $USER_NAME --access-key-id $OLD_KEY_ID"
fi
echo "==> done — active new key: $NEW_ID"
