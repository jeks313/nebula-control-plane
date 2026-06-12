#!/usr/bin/env bash
# Remove the Pilot systemd service. Run as root.
# By default leaves $CONF_DIR and the service account in place (they hold the
# host key/cert); pass --purge to remove them too.
set -euo pipefail

SVC_USER="nebula-pilot"
PREFIX="/usr/local/bin"
UNIT_DST="/etc/systemd/system/pilot.service"
CONF_DIR="/etc/nebula-control-plane"
PURGE=0
[[ "${1:-}" == "--purge" ]] && PURGE=1

if [[ $EUID -ne 0 ]]; then
  echo "error: must run as root" >&2
  exit 1
fi

systemctl disable --now pilot.service 2>/dev/null || true
rm -f "$UNIT_DST"
systemctl daemon-reload
rm -f "$PREFIX/pilot"

if [[ $PURGE -eq 1 ]]; then
  echo "==> purging $CONF_DIR and user $SVC_USER"
  rm -rf "$CONF_DIR"
  userdel "$SVC_USER" 2>/dev/null || true
  groupdel "$SVC_USER" 2>/dev/null || true
  rm -f "$PREFIX/nebula"
else
  echo "Left $CONF_DIR and user $SVC_USER intact (use --purge to remove)."
fi
echo "Done."
