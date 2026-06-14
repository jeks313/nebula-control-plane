#!/usr/bin/env bash
# Lightweight SINGLE-INSTANCE local deploy of the Nebula control plane — for
# personal use / dogfooding, maximally simplified:
#
#   * one box, everything on localhost; SQLite; a SOFTWARE CA (no HSM)
#   * CO-LOCATED enrollment: gateway + enroll worker share one local queue
#     (the simple model — NOT the ADR-0005 off-mesh pull split, which is for the
#     multi-host AWS demo)
#   * the admin CONSOLE logs in with your GITHUB account (OAuth); you are admin
#   * device JOINs are GitHub-gated: mint a join key while you're the admin, the
#     device enrolls, and you approve it in the GitHub-authenticated console (or
#     use the auto-issue key for a one-step join)
#
# It starts the services in the background and leaves them running (this is a
# deploy, not a throwaway demo); `local-down.sh` stops them. No AWS, no SSH, and
# no mesh/nebula needed to enroll — the data-plane tunnel is an optional add-on
# (see the README "Add the mesh" section).
#
# Requires locally: go, curl, openssl. Optional: a GitHub OAuth app (below).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN="${NCP_LOCAL_DIR:-$HOME/.ncp-local}"
BIN="$RUN/bin"
DSN="$RUN/harbor.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
QDSN="$RUN/queue.db?_pragma=busy_timeout(5000)"

# Binds: the gateway can face your LAN so other devices enroll (NCP_BIND=0.0.0.0
# or your LAN IP); the admin console stays 127.0.0.1 — GitHub login grants admin,
# which is only safe because it's local-only (see README to expose it).
BIND="${NCP_BIND:-127.0.0.1}"
GW_PORT="${NCP_GW_PORT:-8443}"
ADMIN_PORT="${NCP_ADMIN_PORT:-8445}"
MOCK_PORT="${NCP_MOCK_IDP_PORT:-8446}" # dev mock-IdP (only used when no GitHub app is set)
POOL="${POOL:-10.44.0.0/16}"
LH_OVERLAY="${LH_OVERLAY:-10.44.0.1}"
LH_ADDR="${LH_ADDR:-127.0.0.1:4242}" # placeholder until you add the mesh

# GitHub OAuth app (see README). If unset, fall back to the in-process mock IdP so
# the deploy still runs end to end for testing.
GH_ID="${NCP_GITHUB_CLIENT_ID:-}"
GH_SECRET="${NCP_GITHUB_CLIENT_SECRET:-}"

for t in go curl openssl; do command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }; done
genkey() { openssl rand 32 | basenc --base64url | tr -d '='; }

mkdir -p "$RUN" "$BIN"
if [[ -f "$RUN/ncp.pids" ]]; then
  echo "a local deploy looks to be running (pid file $RUN/ncp.pids) — run local-down.sh first" >&2
  exit 1
fi

echo "==> building pilot + gateway"
( cd "$ROOT" && go build -o "$BIN/pilot" ./cmd/pilot && go build -o "$BIN/gateway" ./cmd/gateway )
# Build harbor WITH the React admin console (-tags ui) when npm is available — so
# you get the real GitHub-login console — falling back to the API-only build (a
# "console not built" placeholder page) when it isn't.
if command -v npm >/dev/null 2>&1 && ( cd "$ROOT" && npm --prefix ui install --no-audit --no-fund --silent && npm --prefix ui run build ) >"$RUN/ui-build.log" 2>&1; then
  echo "==> building harbor WITH the admin console UI (-tags ui)"
  ( cd "$ROOT" && go build -tags ui -o "$BIN/harbor" ./cmd/harbor )
else
  echo "==> building harbor API-only (no npm, or UI build failed — see $RUN/ui-build.log; run 'make harbor-ui' for the full console)"
  ( cd "$ROOT" && go build -o "$BIN/harbor" ./cmd/harbor )
fi

# ── genesis: CA + config-signing key + a (single-box) lighthouse identity ────
if [[ ! -f "$RUN/G/config-signing.key" ]]; then
  echo "==> genesis (CA + config-signing key + lighthouse)"
  "$BIN/pilot" init -dir "$RUN/lh" >/dev/null
  "$BIN/harbor" migrate up -dsn "$DSN" >/dev/null
  "$BIN/harbor" genesis -dsn "$DSN" -out "$RUN/G" -operator-a "$(whoami)" -operator-b "$(whoami)-2" \
    -pool "$POOL" -lighthouse-pub "$RUN/lh/host.pub" -lighthouse-ip "$LH_OVERLAY" -lighthouse-addr "$LH_ADDR" >/dev/null
  genkey > "$RUN/hmac.b64"
  genkey > "$RUN/queue.b64"
else
  echo "==> reusing existing genesis in $RUN/G"
fi
G="$RUN/G"
LH="$LH_OVERLAY=$LH_ADDR"

# ── services: gateway + enroll worker + admin console ────────────────────────
echo "==> starting gateway (http://$BIND:$GW_PORT) + enroll worker"
: > "$RUN/ncp.pids"
"$BIN/gateway" -insecure -addr "$BIND:$GW_PORT" -hmac-key "$RUN/hmac.b64" \
  -queue-dsn "$QDSN" -queue-key "$RUN/queue.b64" -log-level info >"$RUN/gateway.log" 2>&1 &
echo "gateway $!" >> "$RUN/ncp.pids"
"$BIN/harbor" enroll worker -dsn "$DSN" -ca-cert "$G/ca.crt" -ca-key "$G/ca.key" \
  -config-key "$G/config-signing.key" -hmac-key "$RUN/hmac.b64" \
  -queue-dsn "$QDSN" -queue-key "$RUN/queue.b64" -lighthouse "$LH" -pool "$POOL" >"$RUN/worker.log" 2>&1 &
echo "worker $!" >> "$RUN/ncp.pids"

# Admin console auth: GitHub OAuth when configured, else the dev mock IdP.
auth_args=(-default-roles admin -base-url "http://127.0.0.1:$ADMIN_PORT")
if [[ -n "$GH_ID" ]]; then
  echo "==> admin console with GITHUB login (http://127.0.0.1:$ADMIN_PORT)"
  auth_args+=(-github-client-id "$GH_ID" -github-client-secret "$GH_SECRET")
else
  echo "==> admin console with the DEV MOCK IdP (set NCP_GITHUB_CLIENT_ID/SECRET for real GitHub login)"
  auth_args+=(-mock-idp -mock-idp-addr "127.0.0.1:$MOCK_PORT")
fi
"$BIN/harbor" admin-api -dsn "$DSN" -addr "127.0.0.1:$ADMIN_PORT" \
  -ca-cert "$G/ca.crt" -ca-key "$G/ca.key" -config-key "$G/config-signing.key" \
  -hmac-key "$RUN/hmac.b64" -queue-dsn "$QDSN" -queue-key "$RUN/queue.b64" -pool "$POOL" \
  "${auth_args[@]}" >"$RUN/admin.log" 2>&1 &
echo "admin $!" >> "$RUN/ncp.pids"

# ── health check: fail LOUDLY if a service didn't come up (e.g. a port clash) ─
GWURL="http://$BIND:$GW_PORT"
abort() {
  echo "" >&2
  echo "ERROR: $1" >&2
  echo "  (a port is likely already in use — set NCP_GW_PORT / NCP_ADMIN_PORT / NCP_MOCK_IDP_PORT)" >&2
  for svc in gateway admin worker; do
    echo "  --- $svc.log (tail) ---" >&2
    tail -n 4 "$RUN/$svc.log" 2>/dev/null >&2
  done
  NCP_LOCAL_DIR="$RUN" bash "$(dirname "${BASH_SOURCE[0]}")/local-down.sh" >/dev/null 2>&1 || true
  exit 1
}
# Wait until a URL RESPONDS at all (any HTTP status = the server is listening; no
# -f, since the console root may 302/404 while perfectly up). ~30s — the -tags-ui
# admin binary (embedded SPA + session store + mock-IdP) can take a few seconds.
wait_up() {
  for _ in $(seq 1 150); do
    curl -s -o /dev/null "$1" 2>/dev/null && return 0
    sleep 0.2
  done
  return 1
}
wait_up "$GWURL/v1/nonce?binding=ping" || abort "the gateway never came up at $GWURL"
wait_up "http://127.0.0.1:$ADMIN_PORT/" || abort "the admin console never came up at http://127.0.0.1:$ADMIN_PORT"

# One auto-issue key (one-step join) + one manual-approval key (GitHub-gated).
AUTO="$("$BIN/harbor" joinkey create -dsn "$DSN" -name laptop-auto -groups laptops -auto-issue -max-uses 0 2>/dev/null | grep -o 'njk_[A-Za-z0-9_-]*' || true)"
MANUAL="$("$BIN/harbor" joinkey create -dsn "$DSN" -name laptop -groups laptops -max-uses 0 2>/dev/null | grep -o 'njk_[A-Za-z0-9_-]*' || true)"

cat <<EOF

────────────────────────────────────────────────────────────────────────────
 NEBULA CONTROL PLANE — local single-instance deploy is UP
────────────────────────────────────────────────────────────────────────────
 Run dir       : $RUN     (logs: gateway.log / worker.log / admin.log)
 Admin console : http://127.0.0.1:$ADMIN_PORT   $( [[ -n "$GH_ID" ]] && echo "(log in with GitHub)" || echo "(DEV mock-IdP — set NCP_GITHUB_CLIENT_ID/SECRET for GitHub)" )
 Gateway       : $GWURL   (public enroll; set NCP_BIND=<LAN IP> to let other devices reach it)
 Config pin    : $G/config-signing.pub   (give this to devices that enroll)

 Join a device — GitHub-GATED APPROVAL (you approve in the console):
   pilot enroll -dir ~/.nebula -gateway $GWURL -join-key ${MANUAL:-<run: harbor joinkey create>} \\
     -config-pub $G/config-signing.pub -name my-laptop
   # lands PENDING -> open the console (GitHub login) -> approve it -> re-run to fetch the cert

 Or one-step (auto-issue key, no approval):
   pilot enroll -dir ~/.nebula -gateway $GWURL -join-key ${AUTO:-<auto key>} \\
     -config-pub $G/config-signing.pub -name my-laptop

 Stop: deploy/local/local-down.sh      (add --purge to also delete $RUN)
 Add the mesh (real tunnels): see deploy/local/README.md "Add the mesh".
────────────────────────────────────────────────────────────────────────────
EOF
