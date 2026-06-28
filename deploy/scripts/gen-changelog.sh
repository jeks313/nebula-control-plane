#!/usr/bin/env bash
# Generate internal/version/changelog.json from git log (newest first). Embedded into harbor at
# build time (-tags ui) and served at GET /admin/v1/version for the console's changelog page.
#
# Usage: deploy/scripts/gen-changelog.sh [limit]   (default 500 commits)
# Tolerant: with no git or no jq it writes an empty array so `go build` still embeds something valid.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/internal/version/changelog.json"
LIMIT="${1:-500}"
mkdir -p "$(dirname "$OUT")"

if ! command -v jq >/dev/null 2>&1 || ! git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  printf '[]\n' > "$OUT"
  echo "gen-changelog: no jq or not a git repo — wrote empty changelog"
  exit 0
fi

# %h short hash, %cs committer date (YYYY-MM-DD), %s subject. Split on the unit separator (0x1f)
# and let jq do the JSON escaping of subjects.
TMP="$OUT.tmp"
git -C "$ROOT" log -n "$LIMIT" --no-merges --pretty=format:'%h%x1f%cs%x1f%s' \
  | jq -R -s 'split("\n") | map(select(length>0) | split("") | {hash: .[0], date: .[1], subject: .[2]})' \
  > "$TMP"
mv "$TMP" "$OUT"

echo "gen-changelog: wrote $(jq length "$OUT") commits to ${OUT#"$ROOT"/}"
