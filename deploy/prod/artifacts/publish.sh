#!/usr/bin/env bash
# Build + publish the pilot / nebula data-plane binaries to the artifact bucket
# (deploy/prod/terraform/app/artifacts.tf) and print the `harbor ... release` registry commands
# that advertise them to the self-update lanes (ADR 0003). Run after `terraform apply` with
# artifacts_bucket_name set.
#
#   publish.sh pilot  <version>                 # build cmd/pilot, upload the raw binary
#   publish.sh nebula <version>                 # fetch the GitHub nebula tarball, extract + upload the RAW binary
#   publish.sh both   <pilot-ver> <nebula-ver>  # both
#
# Binaries are uploaded RAW (not tarballs): both pilotupdate and nebulaupdate sha256 the raw bytes
# and chmod 0755 them directly — there is no untar step on the host. The registry records the sha
# of the raw binary (printed below); the pilot verifies it before swap/re-exec, so the bucket being
# public-read is safe (a tampered object fails the hash).
#
# Platform: defaults to linux/amd64 (the cloud fleet the rollout drives). Override with
# GOOS=… GOARCH=… to publish another platform (e.g. the off-cloud iMac: GOOS=darwin GOARCH=arm64).
# A release GENERATION carries a binary PER (goos, goarch): publish each platform, register the
# first with `harbor <c> add -os/-arch …` (it becomes the generation's default artifact) and each
# additional platform with `harbor <c> add-artifact -gen <gen> -os/-arch …`, then `release -gen
# <gen>` stages the whole generation — Core serves each host the artifact matching its reported
# arch. (This script prints the exact add/add-artifact commands below.)
#
# Requires: aws, terraform; go (pilot); curl, tar, sha256sum|shasum (nebula). The printed
# `harbor …` commands run where Harbor + its DB are reachable (the control-plane host), NOT here.
set -euo pipefail

usage() { echo "usage: $0 pilot <version> | nebula <version> | both <pilot-ver> <nebula-ver>" >&2; exit 1; }
COMPONENT="${1:-}"; [[ -n "$COMPONENT" ]] || usage

# This script lives three levels deep (deploy/prod/artifacts/), so ../../.. is the repo root.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TFDIR="$ROOT/deploy/prod/terraform/app" # the app stack holds the artifacts bucket + region outputs

GOOS="${GOOS:-linux}"
GOARCH="${GOARCH:-amd64}"
PLAT="${GOOS}-${GOARCH}"

for t in aws terraform; do command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }; done
BUCKET="$(terraform -chdir="$TFDIR" output -raw artifacts_bucket 2>/dev/null || true)"
[[ -n "$BUCKET" && "$BUCKET" != "null" ]] || { echo "no artifacts_bucket output — set artifacts_bucket_name and 'terraform apply' first" >&2; exit 1; }
REGION="$(terraform -chdir="$TFDIR" output -raw region 2>/dev/null)"
BASE_URL="https://${BUCKET}.s3.${REGION}.amazonaws.com"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

sha256_of() { # portable raw-bytes sha256 (Linux: sha256sum; macOS: shasum)
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

upload() { # upload <localfile> <key>
  echo "==> s3://$BUCKET/$2"
  aws s3 cp "$1" "s3://$BUCKET/$2" --region "$REGION" --content-type application/octet-stream --only-show-errors
}

publish_pilot() {
  local ver="$1" key bin sha
  [[ -n "$ver" ]] || { echo "pilot: version required" >&2; usage; }
  command -v go >/dev/null || { echo "missing tool: go" >&2; exit 1; }
  key="pilot/${ver}/pilot-${PLAT}"
  bin="$TMP/pilot"
  echo "==> building pilot ${ver} (${PLAT}, cgo-free)"
  (cd "$ROOT" && GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=${ver}" -o "$bin" ./cmd/pilot)
  sha="$(sha256_of "$bin")"
  upload "$bin" "$key"
  echo
  echo "register it (run where Harbor + its DB are reachable):"
  echo "  # FIRST platform of ${ver} — creates the generation:"
  echo "  harbor pilot add          -version ${ver} -os ${GOOS} -arch ${GOARCH} -sha256 ${sha} -url ${BASE_URL}/${key}"
  echo "  # ADDITIONAL platform of an existing generation (use the gen from the first add):"
  echo "  harbor pilot add-artifact -gen <gen>      -os ${GOOS} -arch ${GOARCH} -sha256 ${sha} -url ${BASE_URL}/${key}"
  echo "  # once every arch is registered: harbor pilot release -gen <gen>   (stages the whole gen as a canary)"
  echo
}

publish_nebula() {
  local ver="$1" asset archive key bin sha
  [[ -n "$ver" ]] || { echo "nebula: version required" >&2; usage; }
  command -v curl >/dev/null || { echo "missing tool: curl" >&2; exit 1; }
  # slackhq/nebula ships a UNIVERSAL darwin ZIP (no arch suffix) and arch-suffixed linux tarballs.
  if [[ "$GOOS" == "darwin" ]]; then
    asset="nebula-darwin.zip"; archive="$TMP/nebula.zip"
    command -v unzip >/dev/null || { echo "missing tool: unzip (needed to extract the darwin asset)" >&2; exit 1; }
  else
    asset="nebula-${GOOS}-${GOARCH}.tar.gz"; archive="$TMP/nebula.tgz"
    command -v tar >/dev/null || { echo "missing tool: tar" >&2; exit 1; }
  fi
  key="nebula/${ver}/nebula-${PLAT}"
  echo "==> fetching nebula ${ver} (${asset}) from GitHub"
  curl -fsSL -o "$archive" "https://github.com/slackhq/nebula/releases/download/v${ver}/${asset}"
  if [[ -n "${NEBULA_ARCHIVE_SHA256:-}" ]]; then
    echo "${NEBULA_ARCHIVE_SHA256}  $archive" | sha256_check # verify the download (optional supply-chain pin)
  fi
  # Extract the RAW nebula binary (the registry sha is of THIS, not the archive). The darwin zip
  # is a universal binary; the linux tarball is per-arch. Both carry a top-level `nebula` entry.
  if [[ "$GOOS" == "darwin" ]]; then unzip -o -d "$TMP" "$archive" nebula >/dev/null; else tar -xzf "$archive" -C "$TMP" nebula; fi
  bin="$TMP/nebula"
  sha="$(sha256_of "$bin")"
  upload "$bin" "$key"
  echo
  echo "register it (run where Harbor + its DB are reachable):"
  echo "  # FIRST platform of ${ver} — creates the generation:"
  echo "  harbor nebula add          -version ${ver} -os ${GOOS} -arch ${GOARCH} -sha256 ${sha} -url ${BASE_URL}/${key}"
  echo "  # ADDITIONAL platform of an existing generation (use the gen from the first add):"
  echo "  harbor nebula add-artifact -gen <gen>      -os ${GOOS} -arch ${GOARCH} -sha256 ${sha} -url ${BASE_URL}/${key}"
  echo "  # once every arch is registered: harbor nebula release -gen <gen>   (stages the whole gen as a canary)"
  echo
}

sha256_check() { # verify "<sha>  <file>" on stdin, portably
  if command -v sha256sum >/dev/null; then sha256sum -c -
  else local line; read -r line; local want="${line%% *}" f="${line##* }"; [[ "$(sha256_of "$f")" == "$want" ]] || { echo "nebula tarball sha mismatch" >&2; exit 1; }; fi
}

case "$COMPONENT" in
  pilot)  publish_pilot "${2:-}" ;;
  nebula) publish_nebula "${2:-}" ;;
  both)   publish_pilot "${2:-}"; publish_nebula "${3:-}" ;;
  *)      usage ;;
esac

echo "==> done. Bucket: $BASE_URL"
