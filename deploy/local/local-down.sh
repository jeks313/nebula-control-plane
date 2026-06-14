#!/usr/bin/env bash
# Stop the local single-instance deploy started by local-up.sh.
#   local-down.sh           stop the services, keep state (genesis/DB) for next time
#   local-down.sh --purge   stop AND delete the run dir (full reset)
set -euo pipefail

RUN="${NCP_LOCAL_DIR:-$HOME/.ncp-local}"
PURGE=0
[[ "${1:-}" == "--purge" ]] && PURGE=1

if [[ -f "$RUN/ncp.pids" ]]; then
  while read -r name pid; do
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      echo "stopping $name ($pid)"
      kill "$pid" 2>/dev/null || true
    fi
  done < "$RUN/ncp.pids"
  rm -f "$RUN/ncp.pids"
else
  echo "no pid file at $RUN/ncp.pids — nothing running (or already stopped)"
fi

if [[ "$PURGE" -eq 1 ]]; then
  echo "purging $RUN"
  rm -rf "$RUN"
fi
