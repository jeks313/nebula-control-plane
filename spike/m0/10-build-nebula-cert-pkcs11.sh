#!/usr/bin/env bash
# M0.3 prep — build a pkcs11-enabled nebula-cert from source.
#
# Stock nebula-cert is built WITHOUT PKCS#11 (it's a CGO build tag). To sign
# with a key that lives in SoftHSM/an HSM, we need nebula-cert built with
# `-tags pkcs11`. This compiles it into spike/m0/tools/nebula-cert.
#
# Ref: https://github.com/slackhq/nebula/pull/1153
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

command -v go >/dev/null || die "go not found"
# Pin the build to the INSTALLED nebula version so nebula-cert flags + cert
# format match the runtime nebula (master drifts, e.g. -ip -> -networks).
PIN_VERSION="${NEBULA_VERSION:-}"
if [[ -z "$PIN_VERSION" ]] && command -v nebula >/dev/null; then
  v="$(nebula -version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
  [[ -n "$v" ]] && PIN_VERSION="v$v" && log "auto-pinning build to installed nebula ${PIN_VERSION}"
fi

SRC="${TOOLS}/nebula-src"
if [[ ! -d "$SRC" ]]; then
  log "cloning slackhq/nebula..."
  git clone --depth 1 ${PIN_VERSION:+--branch "$PIN_VERSION"} \
    https://github.com/slackhq/nebula "$SRC"
fi

log "building nebula-cert with -tags pkcs11 (CGO)..."
( cd "$SRC" && CGO_ENABLED=1 go build -trimpath -tags pkcs11 \
    -o "${TOOLS}/nebula-cert" ./cmd/nebula-cert )

log "built: ${TOOLS}/nebula-cert"
"${TOOLS}/nebula-cert" ca -h 2>&1 | grep -qi pkcs11 \
  && log "pkcs11 support present ✔" \
  || warn "pkcs11 flag not on 'ca' — check the build / nebula version"
