#!/usr/bin/env bash
# Node installer for the poc mesh. Detects this host's OS/arch, fetches the matching pilot + nebula
# binaries and the config-signing pin from the public artifact bucket, sha256-verifies each binary
# against its published .sha256 sidecar (FAIL CLOSED), installs them to /usr/local/bin, drops the
# pin, then hands off to `pilot install` to enroll + bring up the data plane in one shot.
#
#   curl -fsSL https://ncp-artifacts-123456789012.s3.ca-central-1.amazonaws.com/install.sh | sudo bash
#
# RUN AS ROOT. This script contains NO `sudo` itself (so it never re-prompts mid-run on hosts that
# ask for the password each time) — pipe it to `sudo bash`, or run it as root. No AWS credentials
# needed for the download — the bucket is public-read.
#
# METHOD (how this node authenticates its enrollment) — set NCP_METHOD or use a per-method script:
#   auto     (default) bootstrap binaries + pin only, then print the enroll next-steps. No enroll.
#   joinkey  enroll with a join key (njk_…). Key from $NCP_JOIN_KEY, then $1, then a /dev/tty prompt.
#   sso      enroll via browser SSO (--sso): opens your browser to the IdP; admin approves.
#   cloud    enroll via this instance's cloud IAM role (auto-detects AWS via IMDS; -aws-sigv4).
# The release pipeline publishes install-joinkey.sh / install-sso.sh / install-cloud.sh — the same
# script with METHOD + the gateway/core URLs baked in (see release-pilot.sh).
#
# Overrides (env): NCP_METHOD, NCP_JOIN_KEY, NCP_NAME, NCP_GROUPS, NCP_MESH (default "default"),
#   NCP_ARTIFACTS_BASE, NCP_PILOT_VERSION, NCP_NEBULA_VERSION, NCP_GATEWAY_URL, NCP_CORE_URL,
#   NCP_INSTALL_DIR (default /usr/local/bin), NCP_DIR (pin staging, default /etc/nebula),
#   NCP_SKIP_CLOCK (set to skip the pre-flight NTP clock check on airgapped hosts).
#
# TRUST: the bucket is public-READ and write-protected (uploads need AWS creds), and integrity is
# the published sha256 — verified here AND re-verified by harbor/pilot on every governed self-update.
# As with any `curl | bash`, read this script before piping it to a shell.
set -euo pipefail

METHOD="${NCP_METHOD:-auto}"
BASE="${NCP_ARTIFACTS_BASE:-https://ncp-artifacts-123456789012.s3.ca-central-1.amazonaws.com}"
PILOT_VER="${NCP_PILOT_VERSION:-0.1.0}"
NEBULA_VER="${NCP_NEBULA_VERSION:-1.10.3}"
GATEWAY_URL="${NCP_GATEWAY_URL:-https://poc-gateway.mesh.failsafe.net:8443}"
CORE_URL="${NCP_CORE_URL:-https://poc-harbor.mesh.failsafe.net:8444}"
DEST="${NCP_INSTALL_DIR:-/usr/local/bin}"
NDIR="${NCP_DIR:-/etc/nebula}"
MESH="${NCP_MESH:-default}"
NAME="${NCP_NAME:-$(hostname -s 2>/dev/null || hostname)}"
GROUPS="${NCP_GROUPS:-}"

die() { echo "install: $*" >&2; exit 1; }

case "$METHOD" in auto|joinkey|sso|cloud) ;; *) die "unknown NCP_METHOD '$METHOD' (auto|joinkey|sso|cloud)";; esac

# Root is required for: installing to $DEST, writing $NDIR, and `pilot install` (writes /var/lib/pilot
# + the systemd/launchd unit). Fail closed with the fix rather than half-installing — and never call
# sudo ourselves (re-prompts on some hosts); the operator pipes us to `sudo bash`.
[ "$(id -u)" = "0" ] || die "must run as root — pipe to 'sudo bash' (e.g. curl -fsSL $BASE/install.sh | sudo bash)"

command -v curl >/dev/null || die "need curl"
if   command -v sha256sum >/dev/null; then SHACMD="sha256sum"
elif command -v shasum    >/dev/null; then SHACMD="shasum -a 256"
else die "need sha256sum or shasum"; fi

# Detect platform -> goos/goarch (matches the artifact key naming).
os="$(uname -s)"; arch="$(uname -m)"
case "$os"   in Linux) goos=linux;; Darwin) goos=darwin;; *) die "unsupported OS $os";; esac
case "$arch" in x86_64|amd64) goarch=amd64;; arm64|aarch64) goarch=arm64;; *) die "unsupported arch $arch";; esac
plat="${goos}-${goarch}"
echo "==> poc mesh install for $plat  (method=$METHOD, pilot $PILOT_VER, nebula $NEBULA_VER)"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

fetch_verify() { # fetch_verify <url> <out> — download <url> + <url>.sha256, verify FAIL CLOSED
  local url="$1" out="$2" want got
  echo "    download $url"
  curl -fSL --retry 2 "$url" -o "$out" || die "download failed: $url"
  want="$(curl -fsSL "$url.sha256" 2>/dev/null | tr -d '[:space:]')"
  [ -n "$want" ] || die "no published sha256 sidecar for $url — refusing (fail closed)"
  got="$($SHACMD "$out" | cut -d' ' -f1)"
  [ "$want" = "$got" ] || die "sha256 MISMATCH for $url (want $want, got $got)"
  echo "      verified ($got)"
}

fetch_verify "$BASE/pilot/$PILOT_VER/pilot-$plat"     "$TMP/pilot"
fetch_verify "$BASE/nebula/$NEBULA_VER/nebula-$plat"  "$TMP/nebula"
echo "    download $BASE/config-signing.pub"
curl -fsSL "$BASE/config-signing.pub" -o "$TMP/config-signing.pub" || die "pin download failed"

chmod +x "$TMP/pilot" "$TMP/nebula"
install -m 0755 "$TMP/pilot"  "$DEST/pilot"
install -m 0755 "$TMP/nebula" "$DEST/nebula"
mkdir -p "$NDIR"; install -m 0644 "$TMP/config-signing.pub" "$NDIR/config-signing.pub"
PIN="$NDIR/config-signing.pub"
echo "==> installed: $("$DEST/pilot" version 2>/dev/null || echo pilot), nebula -> $DEST ; pin -> $PIN"

# aws_present / azure_present — best-effort cloud IMDS probes (short timeouts, never block).
aws_present() {
  local tok
  tok="$(curl -fsS -X PUT "http://169.254.169.254/latest/api/token" \
           -H "X-aws-ec2-metadata-token-ttl-seconds: 60" --max-time 2 2>/dev/null || true)"
  [ -n "$tok" ] && curl -fsS -H "X-aws-ec2-metadata-token: $tok" --max-time 2 \
           "http://169.254.169.254/latest/meta-data/instance-id" >/dev/null 2>&1
}
azure_present() {
  curl -fsS -H "Metadata: true" --max-time 2 \
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01" >/dev/null 2>&1
}

# auto: no credential — bootstrap only, then print the enroll next-steps and stop.
if [ "$METHOD" = "auto" ]; then
  cat <<EOF

==================================================================
Binaries + pin installed. To enroll this node, run ONE of:

  # join key (off-cloud; mint 'harbor joinkey create', paste njk_… here):
  pilot install -mesh $MESH -gateway $GATEWAY_URL -core $CORE_URL \\
    -config-pub $PIN -join-key njk_… -name $NAME${GROUPS:+ -groups $GROUPS}

  # browser SSO (admin approves in the console):
  pilot install -mesh $MESH -gateway $GATEWAY_URL -core $CORE_URL \\
    -config-pub $PIN --sso -name $NAME${GROUPS:+ -groups $GROUPS}

  # cloud IAM (on an AWS instance with an enrollable role):
  pilot install -mesh $MESH -gateway $GATEWAY_URL -core $CORE_URL \\
    -config-pub $PIN -aws-sigv4 -name $NAME${GROUPS:+ -groups $GROUPS}

Then: pilot status -mesh $MESH
EOF
  exit 0
fi

# Assemble the `pilot install` argv in one always-non-empty array (so "${ARGS[@]}" is safe even on
# macOS's bash 3.2, where expanding an EMPTY array under `set -u` is an "unbound variable" error).
ARGS=(install -mesh "$MESH" -gateway "$GATEWAY_URL" -core "$CORE_URL" -config-pub "$PIN"
      -nebula "$DEST/nebula" -name "$NAME")
[ -n "$GROUPS" ] && ARGS+=(-groups "$GROUPS")
[ -n "${NCP_SKIP_CLOCK:-}" ] && ARGS+=(-skip-clock-check)

# Append the per-method credential flag.
case "$METHOD" in
  joinkey)
    KEY="${NCP_JOIN_KEY:-${1:-}}"
    if [ -z "$KEY" ]; then
      [ -r /dev/tty ] || die "joinkey: no key — set NCP_JOIN_KEY, pass it as the first arg, or run on a terminal"
      printf 'Paste the join key (njk_…): ' > /dev/tty
      read -r KEY < /dev/tty
    fi
    [ -n "$KEY" ] || die "joinkey: empty key"
    ARGS+=(-join-key "$KEY")
    ;;
  sso)
    ARGS+=(--sso)
    ;;
  cloud)
    if aws_present; then
      echo "==> cloud: AWS instance detected — enrolling via IAM role (-aws-sigv4)"
      ARGS+=(-aws-sigv4)
    elif azure_present; then
      die "cloud: this is an Azure instance — Azure enrollment is not supported yet (use -join-key for now)"
    else
      die "cloud: no supported cloud metadata service found (AWS IMDS) — use the join-key or sso installer"
    fi
    ;;
esac

echo "==> enrolling (method=$METHOD) via $GATEWAY_URL"
exec "$DEST/pilot" "${ARGS[@]}"
