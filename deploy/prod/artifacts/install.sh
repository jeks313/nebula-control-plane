#!/usr/bin/env bash
# Off-cloud node installer for the poc mesh. Detects this host's OS/arch, fetches the matching
# pilot + nebula binaries and the config-signing pin from the public artifact bucket, sha256-
# verifies each binary against its published .sha256 sidecar (FAIL CLOSED), installs them to
# /usr/local/bin, drops the pin, and prints the enroll command. Hosted at the bucket root:
#
#   curl -fsSL https://ncp-artifacts-308040853462.s3.ca-central-1.amazonaws.com/install.sh | bash
#
# No AWS credentials needed — the bucket is public-read.
#
# Overrides (env): NCP_ARTIFACTS_BASE, NCP_PILOT_VERSION, NCP_NEBULA_VERSION, NCP_GATEWAY_URL,
#                  NCP_CORE_URL, NCP_INSTALL_DIR (default /usr/local/bin), NCP_DIR (default ~/.nebula).
#
# TRUST: the bucket is public-READ and write-protected (uploads need AWS creds), and integrity is
# the published sha256 — verified here AND re-verified by harbor/pilot on every governed self-update.
# As with any `curl | bash`, read this script before piping it to a shell.
set -euo pipefail

BASE="${NCP_ARTIFACTS_BASE:-https://ncp-artifacts-308040853462.s3.ca-central-1.amazonaws.com}"
PILOT_VER="${NCP_PILOT_VERSION:-0.1.0}"
NEBULA_VER="${NCP_NEBULA_VERSION:-1.10.3}"
GATEWAY_URL="${NCP_GATEWAY_URL:-https://poc-gateway.mesh.failsafe.net:8443}"
CORE_URL="${NCP_CORE_URL:-https://poc-harbor.mesh.failsafe.net:8444}"
DEST="${NCP_INSTALL_DIR:-/usr/local/bin}"
NDIR="${NCP_DIR:-$HOME/.nebula}"

command -v curl >/dev/null || { echo "install: need curl" >&2; exit 1; }
if   command -v sha256sum >/dev/null; then SHACMD="sha256sum"
elif command -v shasum    >/dev/null; then SHACMD="shasum -a 256"
else echo "install: need sha256sum or shasum" >&2; exit 1; fi

# Detect platform -> goos/goarch (matches the artifact key naming).
os="$(uname -s)"; arch="$(uname -m)"
case "$os"   in Linux) goos=linux;; Darwin) goos=darwin;; *) echo "install: unsupported OS $os" >&2; exit 1;; esac
case "$arch" in x86_64|amd64) goarch=amd64;; arm64|aarch64) goarch=arm64;; *) echo "install: unsupported arch $arch" >&2; exit 1;; esac
plat="${goos}-${goarch}"
echo "==> poc mesh install for $plat  (pilot $PILOT_VER, nebula $NEBULA_VER)"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

fetch_verify() { # fetch_verify <url> <out> — download <url> + <url>.sha256, verify FAIL CLOSED
  local url="$1" out="$2" want got
  echo "    download $url"
  curl -fSL --retry 2 "$url" -o "$out" || { echo "install: download failed: $url" >&2; exit 1; }
  want="$(curl -fsSL "$url.sha256" 2>/dev/null | tr -d '[:space:]')"
  [ -n "$want" ] || { echo "install: no published sha256 sidecar for $url — refusing (fail closed)" >&2; exit 1; }
  got="$($SHACMD "$out" | cut -d' ' -f1)"
  [ "$want" = "$got" ] || { echo "install: sha256 MISMATCH for $url (want $want, got $got)" >&2; exit 1; }
  echo "      verified ($got)"
}

fetch_verify "$BASE/pilot/$PILOT_VER/pilot-$plat"     "$TMP/pilot"
fetch_verify "$BASE/nebula/$NEBULA_VER/nebula-$plat"  "$TMP/nebula"
echo "    download $BASE/config-signing.pub"
curl -fsSL "$BASE/config-signing.pub" -o "$TMP/config-signing.pub" || { echo "install: pin download failed" >&2; exit 1; }

SUDO=""; [ -w "$DEST" ] || SUDO="sudo"
chmod +x "$TMP/pilot" "$TMP/nebula"
$SUDO install -m 0755 "$TMP/pilot"  "$DEST/pilot"
$SUDO install -m 0755 "$TMP/nebula" "$DEST/nebula"
mkdir -p "$NDIR"; install -m 0644 "$TMP/config-signing.pub" "$NDIR/config-signing.pub"
echo "==> installed: $("$DEST/pilot" version 2>/dev/null || echo pilot), nebula -> $DEST ; pin -> $NDIR/config-signing.pub"

cat <<EOF

==================================================================
Next — enroll this node (off-cloud: join key + manual approval).

1) On harbor, mint a join key for this node (with the DB flags — see the publishing runbook):
     harbor joinkey create -name <node-name> -groups laptops  <DB FLAGS>
2) Enroll (paste the njk_... key):
     sudo pilot enroll -dir $NDIR -gateway $GATEWAY_URL \\
       -join-key <njk_...> -config-pub $NDIR/config-signing.pub -name <node-name>
3) Approve it (admin console, or 'harbor enroll approve <id>' with DB flags), then re-run the
   enroll above to fetch the bundle, then bring up the data plane:
     sudo pilot supervise -dir $NDIR -config $NDIR/config.yml \\
       -core $CORE_URL -config-pub $NDIR/config-signing.pub
EOF
