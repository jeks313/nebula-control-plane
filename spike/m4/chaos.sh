#!/usr/bin/env bash
# M4.9 P3 chaos drill: take Harbor offline under a running supervised node and
# assert the DATA PLANE is unaffected — Pilot keeps nebula up and retries the
# control-plane calls instead of tearing the tunnel down.
#
# Uses a fake `nebula` (a process that just stays up, ignoring SIGHUP reloads) so
# it runs root-free; the point is Pilot's behavior, not a live overlay.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$(mktemp -d)"; RUN="$(mktemp -d)"
PORT="${NCP_CORE_PORT:-18490}"
CORE=""; PILOT=""

cleanup() {
  [[ -n "$PILOT" ]] && kill "$PILOT" 2>/dev/null || true
  [[ -n "$CORE"  ]] && kill "$CORE"  2>/dev/null || true
  rm -rf "$BIN" "$RUN"
}
trap cleanup EXIT

echo "==> building"
( cd "$ROOT" && go build -o "$BIN/harbor" ./cmd/harbor && go build -o "$BIN/pilot" ./cmd/pilot )
H="$RUN/h.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"

# A fake nebula: stays up, survives SIGHUP (reload), exits on SIGTERM.
cat > "$BIN/fake-nebula" <<'EOF'
#!/bin/sh
trap '' HUP
trap 'exit 0' TERM INT
while true; do sleep 1; done
EOF
chmod +x "$BIN/fake-nebula"

echo "==> genesis + issue a host certificate"
"$BIN/pilot" init -dir "$RUN/lh" >/dev/null
"$BIN/harbor" genesis -dsn "$H" -out "$RUN/G" -operator-a alice -operator-b bob \
  -lighthouse-pub "$RUN/lh/host.pub" -lighthouse-addr 1.2.3.4:4242 >/dev/null
"$BIN/pilot" init -dir "$RUN/d1" >/dev/null
"$BIN/harbor" issue-cert -dsn "$H" -ca-cert "$RUN/G/ca.crt" -ca-key "$RUN/G/ca.key" \
  -in-pub "$RUN/d1/host.pub" -name host-x -groups web -out "$RUN/d1/host.crt" >/dev/null
cp "$RUN/G/ca.crt" "$RUN/d1/ca.crt"

echo "==> start Core API + supervised node (renewal/heartbeat enabled)"
"$BIN/harbor" core-api -addr "127.0.0.1:${PORT}" -dsn "$H" \
  -ca-cert "$RUN/G/ca.crt" -ca-key "$RUN/G/ca.key" -config-key "$RUN/G/config-signing.key" \
  -lighthouse "100.64.0.1=1.2.3.4:4242" >"$RUN/core.log" 2>&1 & CORE=$!
"$BIN/pilot" supervise -nebula "$BIN/fake-nebula" -config "$RUN/d1/config.yml" \
  -core "http://127.0.0.1:${PORT}" -config-pub "$RUN/G/config-signing.pub" -dir "$RUN/d1" \
  >"$RUN/pilot.log" 2>&1 & PILOT=$!
sleep 1.5

NEB="$(pgrep -P "$PILOT" || true)"
[[ -n "$NEB" ]] || { echo "FAIL: supervised nebula did not start"; cat "$RUN/pilot.log"; exit 1; }
kill -0 "$NEB" 2>/dev/null || { echo "FAIL: nebula not running"; exit 1; }
echo "    [ok] data plane up — supervised nebula pid $NEB"

echo "==> CHAOS: take Harbor offline"
kill "$CORE" 2>/dev/null; CORE=""
sleep 4

echo "==> assert the data plane survived"
kill -0 "$NEB" 2>/dev/null || { echo "FAIL: nebula died when Harbor went down (P3 violated!)"; exit 1; }
STILL="$(pgrep -P "$PILOT" || true)"
[[ "$STILL" == "$NEB" ]] || { echo "FAIL: nebula was restarted (pid $NEB -> $STILL)"; exit 1; }
echo "    [ok] nebula pid $NEB unchanged + alive with Harbor down"

if grep -qiE "heartbeat|renew" "$RUN/pilot.log"; then
  echo "    [ok] Pilot logged control-plane retries (graceful):"
  grep -iE "heartbeat|renew" "$RUN/pilot.log" | tail -2 | sed 's/^/        /'
fi

echo
echo "M4.9 P3 chaos drill: PASS (Harbor outage did not perturb the data plane)"
