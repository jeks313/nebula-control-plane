#!/usr/bin/env bash
# M3 end-to-end demo / harness (implementation-plan 3.8), local-first edition:
# SQLite + software CA + real separate processes (gateway, Core worker, pilot).
# Spins genesis -> gateway -> worker, then drives the full join flow and asserts:
#   1. auto-issue join key  -> host joins straight away
#   2. default join key     -> PENDING (manual approval)
#   3. harbor enroll approve -> issued
#   4. pilot resumes its ticket -> joins
#   5. audit chain intact; enrolled config is nebula -startable
# One command, self-contained, cleans up after itself. Exit 0 = PASS.
#
# (The faithful Postgres + KMS + multi-VM variant lives with the infra plan; this
#  is the zero-setup local harness suitable for CI/nightly.)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$(mktemp -d)"
RUN="$(mktemp -d)"
PORT="${NCP_GW_PORT:-18480}"
GWURL="http://127.0.0.1:${PORT}"
GW=""; WK=""

cleanup() {
  [[ -n "$GW" ]] && kill "$GW" 2>/dev/null || true
  [[ -n "$WK" ]] && kill "$WK" 2>/dev/null || true
  rm -rf "$BIN" "$RUN"
}
trap cleanup EXIT

genkey() { head -c 32 /dev/urandom | basenc --base64url | tr -d '='; }
assert() { # haystack needle label
  if ! grep -q -- "$2" <<<"$1"; then
    echo "FAIL ($3): expected '$2' in:"; echo "$1"
    echo "--- gateway log ---"; cat "$RUN/gw.log" 2>/dev/null
    echo "--- worker log ---"; cat "$RUN/wk.log" 2>/dev/null
    exit 1
  fi
}

echo "==> building binaries"
( cd "$ROOT" && go build -o "$BIN/harbor" ./cmd/harbor && go build -o "$BIN/pilot" ./cmd/pilot && go build -o "$BIN/gateway" ./cmd/gateway )

H="$RUN/h.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
Q="$RUN/q.db?_pragma=busy_timeout(5000)"
LH="100.64.0.1=1.2.3.4:4242"
genkey > "$RUN/hmac.b64"; genkey > "$RUN/queue.b64"

echo "==> genesis (CA + config-signing key + first lighthouse)"
"$BIN/pilot" init -dir "$RUN/lh" >/dev/null
"$BIN/harbor" genesis -dsn "$H" -out "$RUN/G" -operator-a alice -operator-b bob \
  -lighthouse-pub "$RUN/lh/host.pub" -lighthouse-addr 1.2.3.4:4242 >/dev/null

CI="$("$BIN/harbor" joinkey create -dsn "$H" -name ci -groups web -auto-issue -quota 100 2>/dev/null | grep -o 'njk_[A-Za-z0-9_-]*')"
ONPREM="$("$BIN/harbor" joinkey create -dsn "$H" -name onprem -groups web 2>/dev/null | grep -o 'njk_[A-Za-z0-9_-]*')"

echo "==> starting gateway + Core worker"
"$BIN/gateway" -addr "127.0.0.1:${PORT}" -hmac-key "$RUN/hmac.b64" \
  -queue-dsn "$Q" -queue-key "$RUN/queue.b64" >"$RUN/gw.log" 2>&1 & GW=$!
"$BIN/harbor" enroll worker -dsn "$H" -ca-cert "$RUN/G/ca.crt" -ca-key "$RUN/G/ca.key" \
  -config-key "$RUN/G/config-signing.key" -hmac-key "$RUN/hmac.b64" \
  -queue-dsn "$Q" -queue-key "$RUN/queue.b64" -lighthouse "$LH" >"$RUN/wk.log" 2>&1 & WK=$!

# wait for the gateway to accept connections (the worker has no HTTP probe, so
# give both a brief settle once the gateway is up).
for _ in $(seq 1 50); do
  if curl -sf "${GWURL}/v1/nonce?binding=ping" >/dev/null 2>&1; then break; fi
  sleep 0.1
done
sleep 1

echo "==> 1. enroll with an auto-issue join key"
OUT="$("$BIN/pilot" enroll -dir "$RUN/d1" -gateway "$GWURL" -join-key "$CI" \
  -config-pub "$RUN/G/config-signing.pub" -name host-ci -timeout 10s)"
assert "$OUT" "enrolled: overlay IP" "auto-issue"
echo "    [ok] $(grep -o 'overlay IP .*' <<<"$OUT")"

echo "==> 2. enroll with a default join key (manual approval)"
OUT="$("$BIN/pilot" enroll -dir "$RUN/d2" -gateway "$GWURL" -join-key "$ONPREM" \
  -config-pub "$RUN/G/config-signing.pub" -name host-onprem -timeout 3s)"
assert "$OUT" "awaiting manual approval" "pending"
echo "    [ok] host-onprem is PENDING"

echo "==> 3. admin approves the pending host"
EID="$("$BIN/harbor" enroll pending -dsn "$H" | awk '/host-onprem/{print $1}')"
[[ -n "$EID" ]] || { echo "FAIL: no pending enrollment found"; exit 1; }
OUT="$("$BIN/harbor" enroll approve "$EID" -approver alice -dsn "$H" \
  -ca-cert "$RUN/G/ca.crt" -ca-key "$RUN/G/ca.key" -config-key "$RUN/G/config-signing.key" \
  -hmac-key "$RUN/hmac.b64" -queue-dsn "$Q" -queue-key "$RUN/queue.b64" -lighthouse "$LH")"
assert "$OUT" "issued" "approve"
echo "    [ok] approved $EID"

echo "==> 4. host resumes its ticket and joins"
OUT="$("$BIN/pilot" enroll -dir "$RUN/d2" -gateway "$GWURL" -join-key "$ONPREM" \
  -config-pub "$RUN/G/config-signing.pub" -timeout 10s)"
assert "$OUT" "enrolled: overlay IP" "resume"
echo "    [ok] $(grep -o 'overlay IP .*' <<<"$OUT")"

echo "==> 5. audit chain"
OUT="$("$BIN/harbor" audit verify -dsn "$H")"
assert "$OUT" "chain verified" "audit"
echo "    [ok] $OUT"

if command -v nebula >/dev/null 2>&1; then
  echo "==> 6. enrolled node config is startable"
  nebula -test -config "$RUN/d1/config.yml" >/dev/null 2>&1
  echo "    [ok] nebula -test accepts the enrolled config"
fi

echo
echo "M3 E2E demo: PASS"
