#!/usr/bin/env bash
# M0.1 — generate a local-CA cert set (default curve) for the netns lab.
# Simple path: proves the data plane (M0.2) without the HSM.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ -x "$NEBULA_CERT" ]] || die "nebula-cert not found — run: make m0-prereqs"

if [[ -f "${RUN}/ca.crt" ]]; then
  log "ca.crt already exists in run/ — delete run/ to regenerate. skipping CA."
else
  log "creating local CA..."
  "$NEBULA_CERT" ca -name "Harbor M0 Spike CA" \
    -out-crt "${RUN}/ca.crt" -out-key "${RUN}/ca.key"
fi

sign() { # name overlay_ip/cidr groups
  local name="$1" ip="$2" groups="${3:-}"
  log "signing ${name} (${ip}${groups:+ groups=$groups})"
  "$NEBULA_CERT" sign \
    -ca-crt "${RUN}/ca.crt" -ca-key "${RUN}/ca.key" \
    -name "$name" -ip "$ip" ${groups:+-groups "$groups"} \
    -out-crt "${RUN}/${name}.crt" -out-key "${RUN}/${name}.key"
}

sign lh "100.64.0.1/16"
sign n1 "100.64.0.11/16" "a"
sign n2 "100.64.0.12/16" "b"

log "certs in ${RUN}/ :"
ls -1 "${RUN}"/*.crt
log "fingerprints (note n2's for the M0.5 blocklist test):"
for c in lh n1 n2; do printf '  %-3s ' "$c"; "$NEBULA_CERT" print -json -path "${RUN}/${c}.crt" 2>/dev/null | grep -o '"fingerprint":"[a-f0-9]*"' || "$NEBULA_CERT" print -path "${RUN}/${c}.crt"; done
