# shellcheck shell=bash
# init-secrets.sh — SOURCE this (do not execute) ONCE, before `terraform apply`.
#
# It does two things from your GPG-encrypted files, with NO secret ever touching argv,
# shell history, or disk:
#   1. Decrypts your AWS credentials and EXPORTS them into THIS shell, so `terraform`, `aws`,
#      and the genesis bootstrap authenticate without ~/.aws/credentials at rest.
#   2. Decrypts your scoped Cloudflare API token and CREATES (or updates) the Secrets Manager
#      secret `ncp-cloudflare-dns-token` with it — idempotently. Terraform does NOT own this
#      secret; it only LOOKS IT UP (data "aws_secretsmanager_secret" in acme.tf). That
#      inversion is what removes the chicken-and-egg: the secret exists before apply, the
#      token value never enters Terraform state, and there is no "source twice" / placeholder.
#
# Why sourced: a child process cannot export env vars back into your shell. Run it as
#   source deploy/prod/init-secrets.sh        (not `bash …`, which would export nothing)
#
# Inputs (override the paths if yours differ):
#   NCP_AWS_GPG        GPG file with AWS creds. Either shell env lines (AWS_ACCESS_KEY_ID=… /
#                      `export AWS_…`) or ~/.aws/credentials INI ([default] + aws_access_key_id=…).
#                      Default: ~/.config/ncp/aws-creds.gpg
#   NCP_CF_GPG         GPG file containing CLOUDFLARE_API_KEY=<scoped Zone.DNS:Edit API TOKEN>.
#                      Default: ~/.config/ncp/cloudflare.gpg
#   AWS_REGION         optional; default ca-central-1.
#   NCP_CF_SECRET_NAME optional; default ncp-cloudflare-dns-token. MUST equal
#                      "<name_prefix>-cloudflare-dns-token" — set it if you changed name_prefix.
#
# Flow (single, linear — no double-source):
#   source deploy/prod/init-secrets.sh
#   (cd deploy/prod/terraform/foundation && terraform apply)
#   (cd deploy/prod/terraform/app        && terraform apply)   # data source reads the secret
#   bash deploy/prod/bootstrap-genesis.sh

# --- sourced-guard: if executed, exports would vanish; tell the user and bail. ----------
if [ -n "${BASH_SOURCE:-}" ] && [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  echo "init-secrets.sh must be SOURCED, not executed: 'source ${0}'" >&2
  exit 1
fi

# All logic in a function so `local` works and exports still reach the sourced shell, while
# `return` (not `exit`) is used for errors so a failure never kills the interactive shell.
# No `set -e`/`set -u` here — that would alter the caller's shell options.
_ncp_init_secrets() {
  local aws_gpg="${NCP_AWS_GPG:-$HOME/.config/ncp/aws-creds.gpg}"
  local cf_gpg="${NCP_CF_GPG:-$HOME/.config/ncp/cloudflare.gpg}"
  local cf_name="${NCP_CF_SECRET_NAME:-ncp-cloudflare-dns-token}"

  command -v gpg >/dev/null || { echo "init-secrets: gpg not found" >&2; return 1; }
  command -v aws >/dev/null || { echo "init-secrets: aws CLI not found" >&2; return 1; }

  # ── 1. AWS credentials → exported into this shell ──────────────────────────────────────
  if [ ! -f "$aws_gpg" ]; then
    echo "init-secrets: AWS creds file not found: $aws_gpg (set NCP_AWS_GPG)" >&2
    return 1
  fi
  local aws_blob
  aws_blob="$(gpg --quiet --batch --decrypt "$aws_gpg" 2>/dev/null)" \
    || { echo "init-secrets: gpg failed to decrypt $aws_gpg" >&2; return 1; }

  if printf '%s' "$aws_blob" | grep -qi 'aws_access_key_id'; then
    # ~/.aws/credentials INI: take the first profile's keys.
    AWS_ACCESS_KEY_ID="$(printf '%s\n' "$aws_blob"  | sed -n 's/^[[:space:]]*aws_access_key_id[[:space:]]*=[[:space:]]*//p'      | head -n1)"
    AWS_SECRET_ACCESS_KEY="$(printf '%s\n' "$aws_blob" | sed -n 's/^[[:space:]]*aws_secret_access_key[[:space:]]*=[[:space:]]*//p' | head -n1)"
    AWS_SESSION_TOKEN="$(printf '%s\n' "$aws_blob" | sed -n 's/^[[:space:]]*aws_session_token[[:space:]]*=[[:space:]]*//p'       | head -n1)"
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
    [ -n "$AWS_SESSION_TOKEN" ] && export AWS_SESSION_TOKEN || unset AWS_SESSION_TOKEN
  else
    # Shell env lines (KEY=val or `export KEY=val`): auto-export every assignment.
    set -a
    # shellcheck disable=SC1090
    eval "$aws_blob"
    set +a
  fi
  if [ -z "${AWS_ACCESS_KEY_ID:-}" ] || [ -z "${AWS_SECRET_ACCESS_KEY:-}" ]; then
    echo "init-secrets: AWS creds file decrypted but AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY not found in it" >&2
    return 1
  fi
  export AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ca-central-1}}"
  echo "init-secrets: AWS credentials exported (key ${AWS_ACCESS_KEY_ID:0:4}…, region $AWS_REGION)"

  # ── 2. Cloudflare scoped API token → CREATE/UPDATE the Secrets Manager secret ──────────
  if [ ! -f "$cf_gpg" ]; then
    echo "init-secrets: Cloudflare token file not found: $cf_gpg (set NCP_CF_GPG) — skipping CF step" >&2
    return 0
  fi
  local cf_blob cf_token
  cf_blob="$(gpg --quiet --batch --decrypt "$cf_gpg" 2>/dev/null)" \
    || { echo "init-secrets: gpg failed to decrypt $cf_gpg" >&2; return 1; }
  # Value only (no eval): CLOUDFLARE_API_KEY (preferred) or a couple of common aliases.
  cf_token="$(printf '%s\n' "$cf_blob" | sed -n 's/^[[:space:]]*\(export[[:space:]]\+\)\?\(CLOUDFLARE_API_KEY\|CLOUDFLARE_DNS_API_TOKEN\|NCP_ACME_CLOUDFLARE_TOKEN\)[[:space:]]*=[[:space:]]*//p' | head -n1)"
  cf_token="${cf_token%\"}"; cf_token="${cf_token#\"}"; cf_token="${cf_token%\'}"; cf_token="${cf_token#\'}"
  if [ -z "$cf_token" ]; then
    echo "init-secrets: no CLOUDFLARE_API_KEY (scoped Zone.DNS:Edit token) found in $cf_gpg" >&2
    return 1
  fi

  # Hand the token to AWS via a 0600 temp file, shredded immediately — never on argv / in `ps`.
  local tmp; umask 077
  tmp="$(mktemp)" || { echo "init-secrets: mktemp failed" >&2; return 1; }
  printf '%s' "$cf_token" > "$tmp"
  local rc=0 err
  if aws secretsmanager describe-secret --region "$AWS_REGION" --secret-id "$cf_name" >/dev/null 2>&1; then
    if err="$(aws secretsmanager put-secret-value --region "$AWS_REGION" \
          --secret-id "$cf_name" --secret-string "file://$tmp" 2>&1 >/dev/null)"; then
      echo "init-secrets: Cloudflare token updated in Secrets Manager ($cf_name)"
    else
      echo "init-secrets: put-secret-value failed: $err" >&2; rc=1
    fi
  else
    if err="$(aws secretsmanager create-secret --region "$AWS_REGION" \
          --name "$cf_name" --secret-string "file://$tmp" \
          --description 'Scoped Cloudflare API token (Zone.DNS:Edit) for ACME DNS-01; created by init-secrets.sh, looked up by Terraform.' 2>&1 >/dev/null)"; then
      echo "init-secrets: Cloudflare token created in Secrets Manager ($cf_name)"
    else
      echo "init-secrets: create-secret failed: $err" >&2; rc=1
    fi
  fi
  command -v shred >/dev/null && shred -u "$tmp" 2>/dev/null || rm -f "$tmp"
  return $rc
}

_ncp_init_secrets
_ncp_init_rc=$?
unset -f _ncp_init_secrets
[ "${_ncp_init_rc:-0}" -eq 0 ] || echo "init-secrets: completed with errors (rc=$_ncp_init_rc)" >&2
unset _ncp_init_rc
