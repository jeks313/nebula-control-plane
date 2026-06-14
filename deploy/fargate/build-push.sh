#!/usr/bin/env bash
# Build a Fargate container image and push it to the ECR repo terraform created. Run
# after `terraform apply` (with the matching *_runtime=fargate), then force a new ECS
# deployment (printed at the end). The genesis bootstrap calls this for you.
#
#   build-push.sh gateway      # cmd/gateway — static Go binary + alpine   [default]
#   build-push.sh lighthouse   # tun.disabled nebula (downloaded in-image)
#
# Requires: docker, terraform, aws  (+ go for the gateway).
set -euo pipefail

COMPONENT="${1:-gateway}"
case "$COMPONENT" in gateway | lighthouse) ;; *) echo "usage: $0 [gateway|lighthouse]" >&2; exit 1 ;; esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TFDIR="$ROOT/deploy/terraform"

for t in docker terraform aws; do command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }; done

REPO="$(terraform -chdir="$TFDIR" output -raw "${COMPONENT}_ecr_repo" 2>/dev/null || true)"
[[ -n "$REPO" && "$REPO" != "null" ]] || { echo "no ${COMPONENT}_ecr_repo output — run 'terraform apply' with ${COMPONENT}_runtime=fargate first" >&2; exit 1; }
REGION="$(terraform -chdir="$TFDIR" output -raw region 2>/dev/null)"
REGISTRY="${REPO%/*}"

echo "==> ECR login: $REGISTRY"
aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$REGISTRY"

if [[ "$COMPONENT" == "gateway" ]]; then
  command -v go >/dev/null || { echo "missing tool: go" >&2; exit 1; }
  echo "==> building static gateway (linux/amd64, cgo-free)"
  (cd "$ROOT" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$HERE/gateway" ./cmd/gateway)
  docker build -t "$REPO:latest" -f "$HERE/Dockerfile" "$HERE"
  rm -f "$HERE/gateway"
else
  echo "==> building lighthouse image (nebula ${NEBULA_VERSION:-1.10.3}, tun.disabled)"
  docker build -t "$REPO:latest" -f "$HERE/nebula.Dockerfile" \
    --build-arg NEBULA_VERSION="${NEBULA_VERSION:-1.10.3}" \
    --build-arg NEBULA_SHA256="${NEBULA_SHA256:-99ac335caeb69d02a6b6b00a3d4b5d0a36ec3971df480a1cc50e6db378342955}" \
    "$HERE"
fi

docker push "$REPO:latest"
echo "==> pushed $REPO:latest"
echo "    force a new deployment once the config secret is populated (the bootstrap does both):"
echo "    aws ecs update-service --cluster ${NAME_PREFIX:-ncp}-$COMPONENT --service ${NAME_PREFIX:-ncp}-$COMPONENT --force-new-deployment --region $REGION"
