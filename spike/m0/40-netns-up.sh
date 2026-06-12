#!/usr/bin/env bash
# M0.2 — build the underlay (bridge + netns) and start nebula in each namespace.
# Run as root (needs netns, veth, tun).  Uses whatever certs are in run/.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
[[ $EUID -eq 0 ]] || die "run as root (make m0-up)"
[[ -x "$NEBULA_BIN" ]] || die "nebula not found — run: make m0-prereqs"
[[ -f "${RUN}/ca.crt" ]] || die "no certs — run: make m0-certs (or make m0-hsm)"

log "creating bridge ${BRIDGE} (${UNDERLAY_CIDR})"
ip link add "$BRIDGE" type bridge 2>/dev/null || true
ip addr add "${UNDERLAY_GW}/24" dev "$BRIDGE" 2>/dev/null || true
ip link set "$BRIDGE" up

for entry in "${NODES[@]}"; do
  read -r name uip oip am_lh groups <<<"$entry"
  ns="m0-${name}"
  veth="v-${name}"; peer="p-${name}"

  log "netns ${ns}: underlay ${uip}  overlay ${oip}  lighthouse=${am_lh}"
  ip netns add "$ns" 2>/dev/null || true
  ip link add "$veth" type veth peer name "$peer" 2>/dev/null || true
  ip link set "$veth" master "$BRIDGE"
  ip link set "$veth" up
  ip link set "$peer" netns "$ns"
  ip netns exec "$ns" ip addr add "${uip}/24" dev "$peer" 2>/dev/null || true
  ip netns exec "$ns" ip link set "$peer" up
  ip netns exec "$ns" ip link set lo up
  # ensure /dev/net/tun is reachable inside the netns
  ip netns exec "$ns" mkdir -p /dev/net 2>/dev/null || true

  # pick inbound policy: n2 gets the group-restricted rule for M0.6, others any
  if [[ "$name" == "n2" ]]; then inbound="$INBOUND_GROUP_A"; else inbound="$INBOUND_ANY"; fi
  write_config "$name" "$oip" "$am_lh" "$inbound"

  log "  starting nebula in ${ns}"
  ip netns exec "$ns" "$NEBULA_BIN" -config "${RUN}/${name}.yml" \
    >"${RUN}/${name}.log" 2>&1 &
  echo $! > "${RUN}/${name}.pid"
done

sleep 2
log "up. logs in ${RUN}/*.log"
log "  n1 overlay=100.64.0.11  n2 overlay=100.64.0.12 (n2 firewall: only group 'a' may ICMP)"
log "next: make m0-test"
