#!/usr/bin/env bash
# Control-plane feature walkthrough (a narrated, self-asserting demo of the M5/M6
# capabilities that sit on top of the M3 enrollment spine). Zero setup: builds
# the harbor binary, drives a fresh local SQLite DB, asserts each outcome, and
# cleans up after itself. Exit 0 = PASS, so it doubles as a smoke test.
#
#   make demo        # enrollment spine (m3) + this walkthrough
#   bash spike/demo/walkthrough.sh
#
# Covers: dual-control policy publish (6.5/2.11), lighthouse fleet + the
# discovery-never-lost invariant (6.8), canary rollout auto-rollback (6.6), AWS
# SigV4 attestation (5.1/5.2, via the package tests), and the tamper-evident
# hash-chained audit log (2.2).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
DB="$TMP/demo.db"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

H() { "$TMP/harbor" "$@" -dsn "$DB"; }
rule() { printf '\n\033[1m════════════════════════════════════════════════════════════════\033[0m\n'; printf ' \033[1m%s\033[0m\n' "$1"; printf '\033[1m════════════════════════════════════════════════════════════════\033[0m\n'; }
say() { printf '\033[36m$ %s\033[0m\n' "$1"; }
assert() { # haystack needle label
  if ! grep -q -- "$2" <<<"$1"; then
    echo "FAIL ($3): expected '$2' in:"; echo "$1"; exit 1
  fi
}

echo "==> building harbor"
( cd "$ROOT" && go build -o "$TMP/harbor" ./cmd/harbor )
H migrate up >/dev/null
echo "    schema migrated (local SQLite, the same code runs on Postgres)"

# ───────────────────────────────────────────────────────────────────────────
rule "1. CENTRAL FIREWALL — dual-control publish (6.5 / 2.11)"
printf 'allow web -> db tcp 5432\nallow any -> web tcp 443\n' > "$TMP/p.txt"
say "harbor policy propose p.txt -proposer alice"
H policy propose "$TMP/p.txt" -proposer alice
say "harbor policy approve 1 -approver alice   # proposer self-approves -> BLOCKED"
out="$(H policy approve 1 -approver alice 2>&1 || true)"; echo "  $out"
assert "$out" "two-person rule" "self-approval must be blocked"
say "harbor policy approve 1 -approver bob     # distinct second approver"
out="$(H policy approve 1 -approver bob)"; echo "$out"
assert "$out" "committed" "two distinct approvers must publish"
say "harbor policy active"
H policy active
echo "  compiled firewall for a 'web' host (mandatory control-plane + ICMP baseline injected):"
"$TMP/harbor" policy compile -groups web "$TMP/p.txt" | sed 's/^/  /'

# ───────────────────────────────────────────────────────────────────────────
rule "2. LIGHTHOUSE FLEET — live topology, discovery never lost (6.8)"
say "harbor lighthouse add -ip 100.64.0.1 -addrs 1.2.3.4:4242"
H lighthouse add -ip 100.64.0.1 -name lh1 -addrs 1.2.3.4:4242 -actor alice
say "harbor lighthouse remove -ip 100.64.0.1   # removing the LAST one -> BLOCKED"
out="$(H lighthouse remove -ip 100.64.0.1 -actor alice 2>&1 || true)"; echo "  $out"
assert "$out" "last active lighthouse" "removing the last lighthouse must be blocked"
say "harbor lighthouse add -ip 100.64.0.2 -addrs 5.6.7.8:4242   # add replacement first"
H lighthouse add -ip 100.64.0.2 -name lh2 -addrs 5.6.7.8:4242 -actor alice
say "harbor lighthouse remove -ip 100.64.0.1   # now safe to retire the old one"
H lighthouse remove -ip 100.64.0.1 -actor alice
out="$(H lighthouse list)"; echo "$out"
assert "$out" "removed" "retired lighthouse should show removed"

# ───────────────────────────────────────────────────────────────────────────
rule "3. CANARY ROLLOUT — auto-rollback on a bad canary (6.6)"
say "harbor rollout start -target 2 -prev 1 -hosts 100.64.0.10,100.64.0.11,100.64.0.12 -canary 1"
H rollout start -target 2 -prev 1 -hosts 100.64.0.10,100.64.0.11,100.64.0.12 -canary 1 -actor alice
echo "  canary host applies v2 but reports UNHEALTHY (simulated heartbeat):"
if command -v python3 >/dev/null; then
  python3 - "$DB" <<'PY'
import sqlite3, sys, time
c = sqlite3.connect(sys.argv[1])
c.execute("INSERT INTO heartbeats (overlay_ip,device_name,applied_bundle_version,health,last_seen)"
          " VALUES ('100.64.0.10','canary',2,'unhealthy',?)", (int(time.time()*1e9),))
c.commit()
PY
  say "harbor rollout step    # Core evaluates the heartbeat -> auto-rollback + freeze"
  out="$(H rollout step)"; echo "$out"
  assert "$out" "rolledback" "a bad canary must auto-roll-back"
  assert "$out" "auto-rollback" "rollback reason should be recorded"
else
  echo "  (python3 not found — skipping the simulated-heartbeat step; engine is unit-tested)"
fi

# ───────────────────────────────────────────────────────────────────────────
rule "4. AWS SIGV4 ATTESTATION (5.1 sign / 5.2 verify)"
echo "  the SigV4 math is pinned to AWS's published get-vanilla known-answer vector,"
echo "  and Core-verify is proven against a fake STS (binding / SSRF / allowlist):"
( cd "$ROOT" && go test ./internal/awsattest/ ) | sed 's/^/  /'

# ───────────────────────────────────────────────────────────────────────────
rule "5. TAMPER-EVIDENT AUDIT (2.2) — every privileged action is hash-chained"
say "harbor audit verify    # the chain so far (policy/lighthouse/rollout all logged)"
out="$(H audit verify)"; echo "  $out"
assert "$out" "intact" "clean chain must verify"
echo "  ...an attacker edits a committed audit row directly in the DB..."
if command -v python3 >/dev/null; then
  python3 - "$DB" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("UPDATE audit_log SET target='admin-backdoor' WHERE seq=2")
c.commit()
PY
  say "harbor audit verify    # tamper detected, points at the exact row"
  out="$(H audit verify 2>&1 || true)"; echo "  $out"
  assert "$out" "hash mismatch" "tampering must be detected"
fi

printf '\n\033[1;32mControl-plane walkthrough: PASS\033[0m\n'
