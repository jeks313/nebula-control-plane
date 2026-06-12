#!/usr/bin/env bash
# M0.3 — the feasibility test: sign Nebula certs with the SoftHSM-held P256 CA
# key (never exported), then the netns lab should form tunnels exactly as with a
# local CA. This is the local proof of the "CA key lives in KMS/HSM" model.
#
# Requires: a pkcs11-enabled nebula-cert (run 10-build...) and the SoftHSM CA
# (run 20-softhsm-ca.sh). PKCS#11 in Nebula requires P256 / cert v2.
#
# NOTE: the exact -pkcs11 flag/URI syntax is what this step exists to nail down.
# Check `tools/nebula-cert ca -h` / `sign -h`; adjust the URI below as needed.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

CERT="${TOOLS}/nebula-cert"
[[ -x "$CERT" ]] || die "pkcs11 nebula-cert missing — run: make m0-build"
export SOFTHSM2_CONF="${RUN}/softhsm2.conf"
[[ -f "$SOFTHSM2_CONF" ]] || die "SoftHSM not set up — run: bash 20-softhsm-ca.sh"

# PKCS#11 URI for the CA key in SoftHSM. RFC 7512 style.
P11_URI="pkcs11:token=${SOFTHSM_TOKEN};object=${CA_KEY_LABEL};type=private?module-path=${PKCS11_MODULE}&pin-value=${SOFTHSM_PIN}"

if [[ -f "${RUN}/ca.crt" ]]; then
  log "ca.crt exists — skipping CA creation"
else
  log "creating CA cert from the HSM-held P256 key (key stays in the token)..."
  # CA private key is in the HSM, so we only get a ca.crt out (no ca.key file).
  # -curve selects the CA curve; sign() infers curve from the CA (no -curve there).
  "$CERT" ca -curve P256 -pkcs11 "$P11_URI" \
    -name "Harbor M0 HSM CA" -out-crt "${RUN}/ca.crt"
fi

sign() { # name overlay_ip groups
  local name="$1" ip="$2" groups="${3:-}"
  if [[ -f "${RUN}/${name}.crt" ]]; then log "${name}.crt exists — skipping"; return; fi
  # P1: the HOST keypair is generated locally (key never touches the CA/HSM).
  log "keygen ${name} (host private key stays local)"
  "$CERT" keygen -curve P256 -out-key "${RUN}/${name}.key" -out-pub "${RUN}/${name}.pub"
  # The HSM-held CA signs the host's PUBLIC key only (-in-pub).
  log "HSM-signing ${name} (${ip}${groups:+ groups=$groups})"
  "$CERT" sign -pkcs11 "$P11_URI" \
    -ca-crt "${RUN}/ca.crt" -in-pub "${RUN}/${name}.pub" \
    -name "$name" -ip "$ip" ${groups:+-groups "$groups"} \
    -out-crt "${RUN}/${name}.crt"
}

sign lh "100.64.0.1/16"
sign n1 "100.64.0.11/16" "a"
sign n2 "100.64.0.12/16" "b"

log "HSM-signed certs in ${RUN}/. Verify chain:"
"$CERT" print -path "${RUN}/n1.crt" || true
log "If a tunnel forms with these (make m0-up && make m0-test), M0.3 is PROVEN."
