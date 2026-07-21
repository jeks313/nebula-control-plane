#!/usr/bin/env bash
# Build + hot-swap the Harbor control-plane binary on the live POC box, then recreate its
# transient systemd-run units (ncp-core / ncp-collect / ncp-admin). Idempotent; safe to re-run.
# See CLAUDE.md "Deploying to the POC" for the full story and the manual caveats (migrations,
# the gateway image — neither is handled here).
#
# Usage: deploy/scripts/deploy-harbor.sh [--skip-build] [--skip-changelog]
#   --skip-build      reuse the existing bin/harbor (skip changelog regen + make harbor-ui)
#   --skip-changelog  don't regenerate internal/version/changelog.json before building
#
# Requires: gpg-decryptable AWS creds at ~/aws-key-*.env.gpg (see the aws-creds-gpg-decrypt note),
# plus aws CLI, jq, and — unless --skip-build — npm + go. Transfer goes through the artifacts S3
# bucket (the box pulls it), so no SSH key / ProxyCommand is needed.
set -euo pipefail

# --- Live-environment identifiers -------------------------------------------------------------
# The real bucket / instance / region live in a LOCAL, gitignored file so this committed script
# carries only placeholders and the repo can stay public. Copy the example and fill in your own:
#   cp deploy/prod/env.local.example deploy/prod/env.local   # then edit
_NCP_ENV="$(cd "$(dirname "${BASH_SOURCE[0]}")/../prod" && pwd)/env.local"
# shellcheck disable=SC1090
[ -f "$_NCP_ENV" ] && . "$_NCP_ENV"

# --- POC environment (placeholders; overridden by env.local or NCP_* env vars) ----------------
REGION="${NCP_REGION:-ca-central-1}"
HARBOR_INSTANCE="${NCP_HARBOR_INSTANCE:-i-0123456789abcdef0}"   # harbor EC2 (set in env.local)
ARTIFACT_BUCKET="${NCP_ARTIFACT_BUCKET:-ncp-artifacts-123456789012}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

SKIP_BUILD=0; SKIP_CHANGELOG=0
for a in "$@"; do case "$a" in
  --skip-build) SKIP_BUILD=1 ;;
  --skip-changelog) SKIP_CHANGELOG=1 ;;
  -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
  *) echo "unknown arg: $a" >&2; exit 2 ;;
esac; done

log(){ printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }

# --- AWS creds (see the aws-creds-gpg-decrypt note) -------------------------------------------
CRED_GPG="${NCP_AWS_CRED_GPG:-$(ls -t "$HOME"/aws-key-*.env.gpg 2>/dev/null | head -1 || true)}"
[ -n "$CRED_GPG" ] && [ -f "$CRED_GPG" ] || { echo "FATAL: no AWS creds gpg (set NCP_AWS_CRED_GPG or place ~/aws-key-*.env.gpg)" >&2; exit 1; }
log "AWS creds: $CRED_GPG"
set -a; . <(gpg --batch -d "$CRED_GPG"); set +a
export AWS_PAGER="" AWS_DEFAULT_REGION="$REGION"
aws sts get-caller-identity --query Arn --output text >/dev/null || { echo "FATAL: AWS creds not working" >&2; exit 1; }

# --- build (changelog regen + UI + version stamp) ---------------------------------------------
if [ "$SKIP_BUILD" = 0 ]; then
  if [ "$SKIP_CHANGELOG" = 0 ]; then
    log "regenerate embedded changelog (git log -> internal/version/changelog.json)"
    bash deploy/scripts/gen-changelog.sh
  fi
  if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "NOTE: working tree not clean — the version stamp will carry '-dirty'. Commit for a clean deploy."
  fi
  log "build harbor (make harbor-ui = npm build + go build -tags ui, stamped via HARBOR_LDFLAGS)"
  make harbor-ui
fi
[ -x bin/harbor ] || { echo "FATAL: bin/harbor missing (don't pass --skip-build)" >&2; exit 1; }

VER="$(./bin/harbor version 2>&1 | awk '{print $NF}')"
SHA="$(sha256sum bin/harbor | cut -d' ' -f1)"
KEY="deploy/harbor-${VER}-${SHA:0:12}"
log "built ${VER}  sha=${SHA:0:12}"

# --- stage to S3 (the box has GetObject on this bucket; we have PutObject) ---------------------
log "stage -> s3://${ARTIFACT_BUCKET}/${KEY}"
aws s3 cp bin/harbor "s3://${ARTIFACT_BUCKET}/${KEY}" --only-show-errors

# --- remote: pull, verify, backup, atomic swap, recreate units, verify ------------------------
remote_sh="$(mktemp)"; trap 'rm -f "$remote_sh"' EXIT
{
  # Inject the 4 values, then a quoted heredoc body (no local expansion of $ / arrays / /proc).
  printf 'BUCKET=%q\nKEY=%q\nEXPECT_SHA=%q\nEXPECT_VER=%q\n' "$ARTIFACT_BUCKET" "$KEY" "$SHA" "$VER"
  cat <<'REMOTE'
set -uo pipefail

echo "=== 1. download from s3 + verify sha ==="
aws s3 cp "s3://$BUCKET/$KEY" /tmp/harbor.new --only-show-errors || { echo "ABORT: s3 download failed"; exit 1; }
GOT=$(sha256sum /tmp/harbor.new | cut -d' ' -f1)
[ "$GOT" = "$EXPECT_SHA" ] || { echo "ABORT: sha mismatch got=$GOT exp=$EXPECT_SHA"; rm -f /tmp/harbor.new; exit 1; }
echo "sha OK ($GOT)"

echo "=== 2. backup current + atomic same-fs rename swap ==="
TS=$(date -u +%Y%m%dT%H%M%SZ)
CUR_SHA=$(sudo sha256sum /usr/local/bin/harbor 2>/dev/null | cut -d' ' -f1 || echo none)
BAK="/usr/local/bin/harbor.bak-${CUR_SHA:0:12}-$TS"
sudo cp -p /usr/local/bin/harbor "$BAK" && echo "backup: $BAK"
sudo cp /tmp/harbor.new /usr/local/bin/.harbor.new
sudo chown root:root /usr/local/bin/.harbor.new
sudo chmod 0755 /usr/local/bin/.harbor.new
STAGED=$(sudo sha256sum /usr/local/bin/.harbor.new | cut -d' ' -f1)
[ "$STAGED" = "$EXPECT_SHA" ] || { echo "ABORT: staged sha mismatch"; sudo rm -f /usr/local/bin/.harbor.new; exit 1; }
sudo mv -f /usr/local/bin/.harbor.new /usr/local/bin/harbor   # rename avoids ETXTBSY on the running inode
command -v restorecon >/dev/null 2>&1 && sudo restorecon -v /usr/local/bin/harbor || true
rm -f /tmp/harbor.new
echo "installed: $(/usr/local/bin/harbor version 2>&1 | head -1)"
NEWVER=$(/usr/local/bin/harbor version 2>&1 | awk '{print $NF}')
[ "$NEWVER" = "$EXPECT_VER" ] || echo "WARN: version $NEWVER != expected $EXPECT_VER"

echo "=== 3. recreate transient units (argv captured live from /proc, NOT systemctl restart) ==="
recreate() {   # recreate <unit> [extra systemd-run props...]
  local unit="$1"; shift; local extra=("$@")
  local pid; pid=$(systemctl show -p MainPID --value "$unit")
  [ -n "$pid" ] && [ "$pid" != "0" ] || { echo "  $unit: no MainPID (not running?) — SKIP"; return 1; }
  local argv; mapfile -d '' -t argv < "/proc/$pid/cmdline"   # argv[0]=/usr/local/bin/harbor
  local args=("${argv[@]:1}")
  echo "  $unit: pid=$pid argc=${#args[@]} -> stop + systemd-run"
  sudo systemctl stop "$unit"
  sudo systemctl reset-failed "$unit" 2>/dev/null || true
  sudo systemd-run --uid=ec2-user --gid=ec2-user "${extra[@]}" --unit "$unit" --collect /usr/local/bin/harbor "${args[@]}" >/dev/null
}
recreate ncp-collect
recreate ncp-core
recreate ncp-admin -p AmbientCapabilities=CAP_NET_BIND_SERVICE   # console binds privileged :443
sleep 3

echo "=== 4. verify ==="
rc=0
for u in ncp-core ncp-collect ncp-admin; do
  st=$(systemctl is-active "$u"); printf "  %-12s %s\n" "$u" "$st"; [ "$st" = active ] || rc=1
done
echo "exe (must NOT be '(deleted)'):"
for p in $(pgrep -x harbor); do
  exe=$(sudo readlink -f "/proc/$p/exe" 2>/dev/null); echo "  pid $p -> $exe"
  case "$exe" in *"(deleted)") echo "    WARN: running a DELETED inode"; rc=1 ;; esac
done
echo "listening:"; sudo ss -ltnp 2>/dev/null | grep -E ':(443|8444|9445)\b' | awk '{print "  "$4}'
echo "fleet (new binary hits DB):"; harbor fleet 2>&1 | head -1 || rc=1
echo "=== DONE (rc=$rc) ==="
exit $rc
REMOTE
} > "$remote_sh"

B64="$(base64 -w0 "$remote_sh")"
CMD="printf %s '$B64' | base64 -d > /tmp/deploy-harbor.sh; sudo -iu ec2-user bash -l /tmp/deploy-harbor.sh; rm -f /tmp/deploy-harbor.sh"
params="$(jq -nc --arg c "$CMD" '{commands:[$c]}')"

log "SSM RunShellScript -> $HARBOR_INSTANCE"
CID="$(aws ssm send-command --instance-ids "$HARBOR_INSTANCE" --document-name AWS-RunShellScript \
  --comment "deploy harbor $VER" --parameters "$params" --query Command.CommandId --output text)"
echo "CommandId=$CID"

STATUS=Pending
for _ in $(seq 1 45); do
  sleep 4
  STATUS="$(aws ssm get-command-invocation --command-id "$CID" --instance-id "$HARBOR_INSTANCE" --query Status --output text 2>/dev/null || echo Pending)"
  case "$STATUS" in InProgress|Pending) ;; *) break ;; esac
done

log "remote status: $STATUS"
aws ssm get-command-invocation --command-id "$CID" --instance-id "$HARBOR_INSTANCE" --query StandardOutputContent --output text || true
ERR="$(aws ssm get-command-invocation --command-id "$CID" --instance-id "$HARBOR_INSTANCE" --query StandardErrorContent --output text 2>/dev/null || true)"
[ -z "$ERR" ] || { echo "--- stderr ---"; echo "$ERR"; }
[ "$STATUS" = Success ] || { echo "DEPLOY FAILED ($STATUS)"; exit 1; }
log "deploy OK: $VER is live on $HARBOR_INSTANCE"
