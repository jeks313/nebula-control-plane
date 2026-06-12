---
created: 2026-06-12
source: claude-chat
status: v1
project: nebula-control-plane
tags: [networking, nebula, security, runbook, chaos, outage, resilience]
---

# Nebula Control Plane — Harbor Outage Runbook (P3)

Implementation-plan **4.9**. Design principle **P3**: the control plane (Harbor)
is **off the data path**. This runbook states exactly what survives a Harbor
outage, the genuine worst case, and the emergency response. See design §3 (data
plane) and §10 (break-glass).

## The invariant: Harbor down ≠ mesh down

The Nebula data plane is **peer-to-peer**: tunnels are established directly
between hosts, gated by the **certificate** each host already holds. None of that
touches Harbor. Pilot **keeps nebula running** through a Harbor outage — a failed
renewal or heartbeat is logged and retried; it **never** tears down, restarts, or
reloads the data plane on a control-plane error.

*Proven (M4.9):* `internal/renew` — a failing renewal is retried but **never
triggers a reload** (`TestRenewFailureNeverReloads`); `internal/heartbeat` — a
down Core **never fires a command** (`TestReporterToleratesCoreDown`). The
multi-process drill (`spike/m4/chaos.sh`) kills Harbor under a running supervised
node and confirms the node stays up.

### Survives a Harbor outage
- **Existing tunnels** and all peer-to-peer traffic.
- **Hosts with a valid (unexpired) certificate** — they keep handshaking with peers.
- **Lighthouse discovery** — lighthouses are data-plane nodes, not Harbor.

### Degrades during a Harbor outage
- **No new enrollments** (gateway/Core unreachable) — new hosts can't join.
- **No renewals** — certs march toward expiry.
- **No policy/firewall updates, no heartbeat visibility** (the dashboard goes stale).

## The genuine worst case

**Harbor down *longer than the certificate lifetime* → hosts age out.** Once a
cert expires, that host can no longer complete handshakes and falls off the mesh.

The controls that bound this:

- **Cert lifetime *is* your outage budget.** A 30-day lifetime tolerates a ~20-day
  outage (renewal targets ⅔ life, leaving ~⅓-life of margin); a 24-hour lifetime
  tolerates only hours. Pick lifetime as a deliberate trade between blast radius
  (shorter = faster revocation) and outage tolerance (longer = more slack).
- **Proactive renewal at ⅔ life with jitter (4.4)** gives a full ⅓-life of margin
  before expiry and spreads the recovery load.
- **The expiry alert (4.7) is the early warning.** `harbor fleet -alert` reports
  "% of fleet expiring within N days" and exits non-zero — wire it to paging so a
  prolonged outage is caught *days* before mass expiry, not at it.

## Emergency response

1. **Restore Harbor**, prioritizing the **Signer/KMS path** (renewals) and the
   DB. The CA key lives in KMS, independent of Harbor Core — Core can be
   redeployed (9.9) against the same CA without re-genesis.
2. **Watch the expiry alert.** If the fleet is approaching mass expiry faster than
   Harbor can be restored, escalate to break-glass.
3. **Break-glass signing (§10):** two operators with separate IAM roles sign
   critical hosts directly via `nebula-cert-kms` (out-of-band, loudly alarmed,
   reconciled afterward) to buy time. Reserve for genuine emergencies.
4. **Pre-emptively, if an outage is foreseeable:** raise the issued cert lifetime
   for upcoming renewals to widen the budget; revert after.
5. **On recovery — expect a renewal storm.** The 4.4 jitter spreads it, but watch
   the **signing circuit-breaker (2.5)** and **KMS throttling (9.8)**; the breaker
   may trip if a large cohort renews at once — clear it deliberately, don't raise
   the ceiling blindly.

## Detection signals (→ SIEM, §7.1)
- `harbor fleet` expiry-% and **stale heartbeats** (silent hosts = can't reach Core).
- Signing-rate anomalies after recovery (renewal storm vs. abuse).
- Enrollment failures spiking (gateway/Core down).
