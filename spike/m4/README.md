# M4 chaos drill (implementation-plan 4.9)

`chaos.sh` (`make m4-chaos`) proves **P3**: a Harbor outage does not perturb the
data plane.

It issues a host cert, runs `pilot supervise` over a **fake nebula** (a process
that just stays up, ignoring SIGHUP — so it runs root-free) with renewal +
heartbeat enabled against a live Core API, then **kills Harbor** and asserts the
supervised nebula is **still the same PID, still alive** — Pilot logged its
control-plane retries instead of tearing down the tunnel.

```bash
make m4-chaos        # or: bash spike/m4/chaos.sh
```

The data-plane-independence property is also covered deterministically in the Go
suite: `internal/renew` `TestRenewFailureNeverReloads` (a failed renewal never
reloads) and `internal/heartbeat` `TestReporterToleratesCoreDown` (a down Core
never fires a command). The worst case + emergency response are in
`docs/Nebula Control Plane - Chaos and Outage Runbook.md`.
