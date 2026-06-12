#!/usr/bin/env bash
# M0.3 — create a SoftHSM token holding a P256 CA key (the AWS-KMS stand-in).
# The key is generated INSIDE the token and never exported — same property we
# want from KMS. No root required.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

command -v softhsm2-util >/dev/null || die "softhsm2-util not found (pacman -S softhsm)"
command -v pkcs11-tool   >/dev/null || die "pkcs11-tool not found (pacman -S opensc)"
[[ -f "$PKCS11_MODULE" ]] || die "libsofthsm2.so not found at $PKCS11_MODULE"

# isolate SoftHSM state under run/ so we don't touch any system token store
export SOFTHSM2_CONF="${RUN}/softhsm2.conf"
TOKENDIR="${RUN}/softhsm-tokens"
mkdir -p "$TOKENDIR"
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = ${TOKENDIR}
objectstore.backend = file
log.level = INFO
EOF

if softhsm2-util --show-slots | grep -q "$SOFTHSM_TOKEN"; then
  log "token '$SOFTHSM_TOKEN' already exists"
else
  log "initialising token '$SOFTHSM_TOKEN'..."
  softhsm2-util --init-token --free \
    --label "$SOFTHSM_TOKEN" --pin "$SOFTHSM_PIN" --so-pin "$SOFTHSM_SO_PIN"
fi

if pkcs11-tool --module "$PKCS11_MODULE" --token-label "$SOFTHSM_TOKEN" \
     --pin "$SOFTHSM_PIN" --list-objects 2>/dev/null | grep -q "$CA_KEY_LABEL"; then
  log "CA key '$CA_KEY_LABEL' already present"
else
  log "generating P256 CA keypair in the token..."
  pkcs11-tool --module "$PKCS11_MODULE" --token-label "$SOFTHSM_TOKEN" \
    --login --pin "$SOFTHSM_PIN" \
    --keypairgen --key-type EC:prime256v1 \
    --label "$CA_KEY_LABEL" --id "$CA_KEY_ID"
fi

log "SoftHSM CA ready."
log "  SOFTHSM2_CONF=$SOFTHSM2_CONF"
log "  module=$PKCS11_MODULE  token=$SOFTHSM_TOKEN  key=$CA_KEY_LABEL"
log "Next: bash 31-gen-certs-hsm.sh   (or: make m0-hsm)"
