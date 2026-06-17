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

# Fleet platforms. The FIRST is registered as the generation's DEFAULT artifact (harbor pilot add);
# each remaining one is an add-artifact. Extend this list as the fleet grows (e.g. linux/arm64).
PLATFORMS=("linux/amd64" "darwin/arm64")

echo "==> releasing pilot $VER for: ${PLATFORMS[*]}"
for plat in "${PLATFORMS[@]}"; do
  echo "─── ${plat} ───"
  GOOS="${plat%/*}" GOARCH="${plat#*/}" "$ROOT/deploy/prod/artifacts/publish.sh" pilot "$VER"
done

# Keep the bucket's off-cloud installer (install.sh, curl|bash) in sync — default its pilot version
# to the one just released, so a fresh `curl … install.sh | bash` installs this release.
BUCKET="$(terraform -chdir="$ROOT/deploy/prod/terraform/app" output -raw artifacts_bucket 2>/dev/null || true)"
REGION="$(terraform -chdir="$ROOT/deploy/prod/terraform/app" output -raw region 2>/dev/null || echo ca-central-1)"
if [[ -n "$BUCKET" && "$BUCKET" != "null" ]]; then
  sed -E "s/^PILOT_VER=.*/PILOT_VER=\"\${NCP_PILOT_VERSION:-$VER}\"/" "$ROOT/deploy/prod/artifacts/install.sh" \
    | aws s3 cp - "s3://$BUCKET/install.sh" --region "$REGION" --content-type text/x-shellscript --only-show-errors
  echo "synced install.sh -> s3://$BUCKET/install.sh (pilot default $VER)"
fi

cat <<EOF
===================================================================
pilot $VER built (version-stamped) + published for all platforms above.

Next — on the control-plane (harbor) host, with this mesh's DB flags (see the runbook):
  1. harbor pilot add          -version $VER -os ${PLATFORMS[0]%/*} -arch ${PLATFORMS[0]#*/} -sha256 <sha> -url <url>   # creates gen N; first platform = the gen default
  2. harbor pilot add-artifact -gen N        -os <os> -arch <arch> -sha256 <sha> -url <url>                            # for each remaining platform
  3. harbor pilot release -gen N                                                                                       # stage canary -> fleet
Then watch: harbor rollout status / harbor fleet.

(publish.sh printed the exact add/add-artifact line per platform above — copy the sha + url from each.)
EOF
