#!/usr/bin/env bash
# Tear down the M0 netns lab. Run as root. (Leaves run/ certs in place.)
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
[[ $EUID -eq 0 ]] || die "run as root (make m0-down)"

for entry in "${NODES[@]}"; do
  read -r name _ <<<"$entry"
  [[ -f "${RUN}/${name}.pid" ]] && { kill "$(cat "${RUN}/${name}.pid")" 2>/dev/null || true; rm -f "${RUN}/${name}.pid"; }
  ip netns del "m0-${name}" 2>/dev/null || true
  ip link del "v-${name}" 2>/dev/null || true
done
ip link del "$BRIDGE" 2>/dev/null || true
log "torn down. (certs/logs remain in ${RUN}; 'rm -rf ${RUN}' to wipe)"
