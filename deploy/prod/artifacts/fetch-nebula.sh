#!/usr/bin/env bash
# fetch-nebula.sh <version> <goos> <goarch> <outdir>
#
# The single source of truth for obtaining a slackhq/nebula release binary for a given
# platform. slackhq ships DIFFERENT archive shapes per OS, which is the whole reason the
# Windows data plane was un-stageable before this:
#
#   linux   : nebula-<os>-<arch>.tar.gz   (per-arch tarball; top-level entry `nebula`)
#   darwin  : nebula-darwin.zip           (universal zip;     top-level entry `nebula`)
#   windows : nebula-windows-<arch>.zip   (zip of nebula.exe + nebula-cert.exe + dist/),
#             where the Wintun TUN driver nebula loads at runtime lives at
#             dist/windows/wintun/bin/<arch>/wintun.dll
#
# It writes the RAW binary to <outdir>/nebula (no extension, regardless of OS — the .exe-ness
# is in the bytes + the eventual destination filename) and, for windows ONLY, the matching
# <outdir>/wintun.dll. Callers (the embed build in the Makefile + publish.sh) decide what to
# do with them (gzip into the embed asset / upload to the artifact bucket).
#
# Wintun is WireGuard's Windows TUN driver; we redistribute the exact copy slackhq bundles in
# their release zip (the same provenance as nebula.exe itself).
set -euo pipefail

ver="${1:-}"; goos="${2:-}"; goarch="${3:-}"; out="${4:-}"
[[ -n "$ver" && -n "$goos" && -n "$goarch" && -n "$out" ]] || {
  echo "usage: $0 <version> <goos> <goarch> <outdir>" >&2; exit 1; }
command -v curl >/dev/null || { echo "fetch-nebula: need curl" >&2; exit 1; }

mkdir -p "$out"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
base="https://github.com/slackhq/nebula/releases/download/v${ver}"

case "$goos" in
  windows)
    command -v unzip >/dev/null || { echo "fetch-nebula: need unzip (windows asset is a .zip)" >&2; exit 1; }
    # Wintun bundles the 32-bit driver under bin/x86 (not bin/386); match nebula's own
    # GOARCH->arch remap (overlay/tun_windows.go). amd64/arm64/arm pass through.
    zarch="$goarch"; [[ "$goarch" == "386" ]] && zarch="x86"
    echo "==> fetching nebula ${ver} windows/${goarch} (zip: nebula.exe + Wintun bin/${zarch})" >&2
    curl -fsSL -o "$tmp/n.zip" "${base}/nebula-windows-${goarch}.zip"
    # -j junks the in-zip paths so each lands flat in $tmp.
    unzip -o -j "$tmp/n.zip" "nebula.exe" -d "$tmp" >/dev/null
    unzip -o -j "$tmp/n.zip" "dist/windows/wintun/bin/${zarch}/wintun.dll" -d "$tmp" >/dev/null
    [[ -f "$tmp/nebula.exe" && -f "$tmp/wintun.dll" ]] || {
      echo "fetch-nebula: windows zip missing nebula.exe or wintun.dll (dist/windows/wintun/bin/${zarch}/)" >&2; exit 1; }
    install -m0755 "$tmp/nebula.exe" "$out/nebula"
    install -m0644 "$tmp/wintun.dll" "$out/wintun.dll"
    ;;
  darwin)
    command -v unzip >/dev/null || { echo "fetch-nebula: need unzip (darwin asset is a .zip)" >&2; exit 1; }
    echo "==> fetching nebula ${ver} darwin (universal zip)" >&2
    curl -fsSL -o "$tmp/n.zip" "${base}/nebula-darwin.zip"
    unzip -o -j "$tmp/n.zip" nebula -d "$tmp" >/dev/null
    install -m0755 "$tmp/nebula" "$out/nebula"
    ;;
  *)
    command -v tar >/dev/null || { echo "fetch-nebula: need tar" >&2; exit 1; }
    echo "==> fetching nebula ${ver} ${goos}/${goarch} (tarball)" >&2
    curl -fsSL -o "$tmp/n.tgz" "${base}/nebula-${goos}-${goarch}.tar.gz"
    tar -xzf "$tmp/n.tgz" -C "$tmp" nebula
    install -m0755 "$tmp/nebula" "$out/nebula"
    ;;
esac

echo "fetched: $out/nebula$( [[ "$goos" == windows ]] && echo ' + '"$out"'/wintun.dll' )" >&2
