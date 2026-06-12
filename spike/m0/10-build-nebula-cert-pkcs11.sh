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
PIN_VERSION="${NEBULA_VERSION:-}"   # e.g. NEBULA_VERSION=v1.9.5 to pin

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
"${TOOLS}/nebula-cert" -h 2>&1 | grep -qi pkcs11 \
  && log "pkcs11 support present ✔" \
  || warn "pkcs11 flag not visible in help — check the build / nebula version"
