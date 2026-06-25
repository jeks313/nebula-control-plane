#!/usr/bin/env bash
# Cut a versioned pilot release: build + publish the pilot binary for every fleet arch — each
# stamped with main.version (so `pilot version` reports the real version, not "dev") — to the
# artifact bucket, then print the harbor register/release next-steps.
#
# Version source: the repo-root VERSION file. Override with `release-pilot.sh <version>`.
# To bump: edit VERSION (e.g. 0.1.0 -> 0.1.1), commit + tag v<version>, then run this.
#
# This BUILDS + PUBLISHES only (on your laptop, with AWS creds). REGISTER + RELEASE run on the
# control-plane host with the DB flags — see "Runbook - Publishing pilot and nebula releases".
# nebula is NOT built here (it's slackhq's prebuilt binary): publish it with
# `publish.sh nebula <slackhq-version>` per its own release cadence.
#
# Requires: aws, terraform, go (and the artifacts bucket applied — artifacts_bucket_name set).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VER="${1:-$(cat "$ROOT/VERSION" 2>/dev/null || true)}"
[[ -n "$VER" ]] || { echo "no version: set the repo-root VERSION file or pass one as \$1" >&2; exit 1; }

# Fleet platforms. SAFE_PLATFORMS[0] is registered as the generation's DEFAULT artifact (harbor
# pilot add); the rest are add-artifacts. Extend SAFE_PLATFORMS as the fleet grows (e.g. linux/arm64).
# The SAFE lanes are pure cgo-free cross-compiles (go only) and publish FATALLY.
SAFE_PLATFORMS=("linux/amd64" "darwin/arm64")
# windows/amd64 is published EMBEDDED (publish.sh builds it with -tags embed_nebula so the pilot.exe
# carries nebula + Wintun and self-stages the data plane — install.sh is POSIX-only and Windows
# self-update no-ops, so a non-embedded Windows pilot would be useless on a fresh host). It needs
# make+curl+unzip+network, so it runs LAST and NON-FATALLY: a publishing-host hiccup (or slackhq not
# shipping a windows zip for this nebula version) must not strand the safe lanes or the installer.
WINDOWS_PLATFORMS=("windows/amd64")

echo "==> releasing pilot $VER for: ${SAFE_PLATFORMS[*]} ${WINDOWS_PLATFORMS[*]}"
for plat in "${SAFE_PLATFORMS[@]}"; do
  echo "─── ${plat} ───"
  GOOS="${plat%/*}" GOARCH="${plat#*/}" "$ROOT/deploy/prod/artifacts/publish.sh" pilot "$VER"
done

# Sync the bucket's installers (curl|sudo bash) to this version NOW — BEFORE the failure-prone
# Windows lane — so a Windows hiccup can never leave them stale (they're POSIX-only and unaffected
# by Windows anyway). We publish ONE template (install.sh, METHOD=auto) plus three per-method
# variants — install-{joinkey,sso,cloud}.sh — derived from it by baking METHOD + this harbor's
# gateway/core URLs (from terraform), so a node operator never has to supply an address.
TF=(terraform -chdir="$ROOT/deploy/prod/terraform/app" output -raw)
BUCKET="$("${TF[@]}" artifacts_bucket 2>/dev/null || true)"
REGION="$("${TF[@]}" region 2>/dev/null || echo ca-central-1)"
GATEWAY_URL="$("${TF[@]}" gateway_url 2>/dev/null || true)"; [[ "$GATEWAY_URL" == "null" ]] && GATEWAY_URL=""
# gateway_url is taken verbatim from terraform; reject a malformed empty-host shape
# (http(s)://:PORT — only possible mid-apply on the EC2 gateway before its EIP is in state)
# rather than baking a broken address into every installer. Empty => install.sh's built-in default.
[[ "$GATEWAY_URL" =~ ^https?://:[0-9]+ ]] && { echo "WARN: terraform gateway_url is malformed ($GATEWAY_URL) — leaving installers on their built-in default" >&2; GATEWAY_URL=""; }
HARBOR_DOMAIN="$("${TF[@]}" harbor_domain 2>/dev/null || true)"
CORE_URL=""; [[ -n "$HARBOR_DOMAIN" && "$HARBOR_DOMAIN" != "null" ]] && CORE_URL="https://${HARBOR_DOMAIN}:${CORE_PORT:-8444}"

if [[ -n "$BUCKET" && "$BUCKET" != "null" ]]; then
  # Common substitutions: pin the pilot default to $VER and bake the gateway/core URLs (only when
  # terraform resolved them — else leave install.sh's built-in defaults). Use '|' as the sed
  # delimiter since the URLs contain '/'.
  SED_COMMON=(-E -e "s|^PILOT_VER=.*|PILOT_VER=\"\${NCP_PILOT_VERSION:-$VER}\"|")
  [[ -n "$GATEWAY_URL" ]] && SED_COMMON+=(-e "s|^GATEWAY_URL=.*|GATEWAY_URL=\"\${NCP_GATEWAY_URL:-$GATEWAY_URL}\"|")
  [[ -n "$CORE_URL"    ]] && SED_COMMON+=(-e "s|^CORE_URL=.*|CORE_URL=\"\${NCP_CORE_URL:-$CORE_URL}\"|")

  gen_installer() { # gen_installer <method> <s3-key> — bake METHOD + common subs, upload
    local method="$1" key="$2"
    sed "${SED_COMMON[@]}" -e "s|^METHOD=.*|METHOD=\"\${NCP_METHOD:-$method}\"|" \
      "$ROOT/deploy/prod/artifacts/install.sh" \
      | aws s3 cp - "s3://$BUCKET/$key" --region "$REGION" --content-type text/x-shellscript --only-show-errors
    echo "synced $key (method=$method)"
  }

  gen_installer auto    install.sh
  gen_installer joinkey install-joinkey.sh
  gen_installer sso     install-sso.sh
  gen_installer cloud   install-cloud.sh
  echo "installers -> s3://$BUCKET/  (pilot default $VER; gateway ${GATEWAY_URL:-<built-in default>}, core ${CORE_URL:-<built-in default>})"
fi

# Windows lane: embedded, non-fatal. Collect failures and report; never abort the run after the
# safe lanes + installer are already published.
WIN_FAILED=()
for plat in "${WINDOWS_PLATFORMS[@]}"; do
  echo "─── ${plat} (embedded nebula + Wintun) ───"
  if ! ( GOOS="${plat%/*}" GOARCH="${plat#*/}" "$ROOT/deploy/prod/artifacts/publish.sh" pilot "$VER" ); then
    echo "WARN: ${plat} lane failed — needs make+curl+unzip+network (or slackhq has no windows zip for nebula ${NEBULA_VERSION:-1.10.3}). Safe lanes + install.sh are published; re-run windows when fixed." >&2
    WIN_FAILED+=("$plat")
  fi
done

cat <<EOF
===================================================================
pilot $VER built (version-stamped) + published for all platforms above.

Next — on the control-plane (harbor) host, with this mesh's DB flags (see the runbook):
  1. harbor pilot add          -version $VER -os ${SAFE_PLATFORMS[0]%/*} -arch ${SAFE_PLATFORMS[0]#*/} -sha256 <sha> -url <url>   # creates gen N; first platform = the gen default
  2. harbor pilot add-artifact -gen N        -os <os> -arch <arch> -sha256 <sha> -url <url>                            # for each remaining platform
  3. harbor pilot release -gen N                                                                                       # stage canary -> fleet
Then watch: harbor rollout status / harbor fleet.

(publish.sh printed the exact add/add-artifact line per platform above — copy the sha + url from each.)
EOF

if [[ ${#WIN_FAILED[@]} -gt 0 ]]; then
  echo "NOTE: windows lane(s) failed: ${WIN_FAILED[*]} — the safe lanes + install.sh ARE published; re-run \`release-pilot.sh $VER\` (or just the windows publish) once make/curl/unzip/network is available." >&2
  exit 1
fi
