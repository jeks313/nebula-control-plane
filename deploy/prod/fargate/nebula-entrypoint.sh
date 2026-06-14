#!/bin/sh
# Fargate lighthouse entrypoint. ECS injects the nebula identity from Secrets Manager
# as env vars; nebula reads ca/cert/key from FILE paths, so materialize them, render a
# `tun.disabled` lighthouse config, then exec nebula.
#
# tun.disabled: a lighthouse passes no data-plane traffic to/from itself, so it needs
# no TUN device (hence no CAP_NET_ADMIN / privilege — Fargate-friendly). It still does
# the cert-authenticated Nebula handshake and serves discovery + hole-punch over UDP.
set -eu

d="$(mktemp -d)"
printf '%s' "${CA_CRT_PEM:?missing CA_CRT_PEM}"     > "$d/ca.crt"
printf '%s' "${HOST_CRT_PEM:?missing HOST_CRT_PEM}" > "$d/host.crt"
printf '%s' "${HOST_KEY_PEM:?missing HOST_KEY_PEM}" > "$d/host.key"

NEBULA_PORT="${NEBULA_PORT:-4242}"
NCP_STATS_PORT="${NCP_STATS_PORT:-8080}"

cat > "$d/config.yml" <<YAML
pki:
  ca: $d/ca.crt
  cert: $d/host.crt
  key: $d/host.key
static_host_map: {}
lighthouse:
  am_lighthouse: true
listen:
  host: 0.0.0.0
  port: ${NEBULA_PORT}
punchy:
  punch: true
  respond: true
tun:
  disabled: true
# Prometheus stats on a TCP port — used ONLY as the NLB's health check target (UDP
# target groups cannot be UDP-health-checked). Not a public surface (SG: NLB only).
stats:
  type: prometheus
  listen: 0.0.0.0:${NCP_STATS_PORT}
  path: /metrics
  namespace: nebula
  subsystem: lighthouse
  interval: 10s
firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      host: any
YAML

exec /usr/local/bin/nebula -config "$d/config.yml"
