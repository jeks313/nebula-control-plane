#!/usr/bin/env bash
# Install Pilot as a hardened systemd service (implementation-plan M1.9).
# Run as root on a Linux host with systemd. Idempotent.
set -euo pipefail

SVC_USER="nebula-pilot"
PREFIX="/usr/local/bin"
UNIT_DST="/etc/systemd/system/pilot.service"
CONF_DIR="/etc/nebula-control-plane"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "error: must run as root" >&2
  exit 1
fi
if ! command -v systemctl >/dev/null; then
  echo "error: systemd (systemctl) not found" >&2
  exit 1
fi

echo "==> dedicated least-privilege service account: $SVC_USER"
if ! getent group "$SVC_USER" >/dev/null; then
  groupadd --system "$SVC_USER"
fi
if ! getent passwd "$SVC_USER" >/dev/null; then
  useradd --system --gid "$SVC_USER" --no-create-home \
          --home-dir /nonexistent --shell /usr/sbin/nologin "$SVC_USER"
fi

echo "==> installing binaries into $PREFIX"
# Prefer freshly built binaries from the repo; fall back to building.
PILOT_SRC="$REPO_ROOT/bin/pilot"
if [[ ! -x "$PILOT_SRC" ]]; then
  echo "    building pilot..."
  ( cd "$REPO_ROOT" && make build )
fi
install -m 0755 "$PILOT_SRC" "$PREFIX/pilot"

# nebula itself: copy whatever is on PATH so the unit's fixed path resolves.
if [[ ! -x "$PREFIX/nebula" ]]; then
  if command -v nebula >/dev/null; then
    install -m 0755 "$(command -v nebula)" "$PREFIX/nebula"
  else
    echo "    WARNING: nebula not found on PATH and $PREFIX/nebula missing." >&2
    echo "             Place a verified nebula binary there before starting." >&2
  fi
fi

echo "==> laying out $CONF_DIR (0700, owned by $SVC_USER)"
install -d -m 0700 -o "$SVC_USER" -g "$SVC_USER" "$CONF_DIR"

echo "==> generating host key + rendering config (pilot init, as $SVC_USER)"
VALUES_ARG=()
if [[ -f "$CONF_DIR/values.yml" ]]; then
  VALUES_ARG=(-values "$CONF_DIR/values.yml")
fi
runuser -u "$SVC_USER" -- "$PREFIX/pilot" init -dir "$CONF_DIR" "${VALUES_ARG[@]}"

echo "==> installing unit -> $UNIT_DST"
install -m 0644 "$HERE/pilot.service" "$UNIT_DST"
systemctl daemon-reload
systemctl enable pilot.service

cat <<EOF

Done. Pilot is installed and enabled (not started).

Before first start, place the enrollment material in $CONF_DIR:
  - ca.crt    (CA trust bundle)
  - host.crt  (certificate signed for $CONF_DIR/host.pub)
Until enrollment (M3) exists, sign host.pub with your CA manually, e.g.:
  nebula-cert sign -ca-crt ca.crt -ca-key ca.key \\
    -in-pub $CONF_DIR/host.pub -name <host> -networks <overlay-ip>/<mask> \\
    -out-crt $CONF_DIR/host.crt

Then:
  systemctl start pilot
  systemctl status pilot
  journalctl -u pilot -f
EOF
