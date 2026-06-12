#!/usr/bin/env bash
# M0.0 — check tooling and print the install command (CachyOS/Arch).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

missing=()
have() { command -v "$1" >/dev/null 2>&1; }

log "checking tooling..."
for t in nebula nebula-cert ip; do have "$t" || missing+=("$t"); done
have softhsm2-util || missing+=("softhsm2-util")
have pkcs11-tool   || missing+=("pkcs11-tool")
[[ -f "$PKCS11_MODULE" ]] || warn "libsofthsm2.so not found at $PKCS11_MODULE (will appear after install)"
[[ -e /dev/net/tun ]] || warn "/dev/net/tun missing — load the tun module: sudo modprobe tun"

if ((${#missing[@]})); then
  warn "missing: ${missing[*]}"
  cat <<EOF

Install on CachyOS/Arch:

  # nebula + nebula-cert (AUR):
  paru -S nebula
  # SoftHSM2 + PKCS#11 tooling (extra):
  sudo pacman -S --needed softhsm opensc

Tip: from the Claude Code prompt you can run these inline with the '!' prefix, e.g.
  ! sudo pacman -S --needed softhsm opensc

After installing, re-run: make m0-prereqs
EOF
  exit 1
fi

log "all M0 tooling present."
log "nebula:      $NEBULA_BIN"
log "nebula-cert: $NEBULA_CERT"
log "pkcs11 mod:  $PKCS11_MODULE"
