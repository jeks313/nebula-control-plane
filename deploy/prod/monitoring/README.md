# Control-plane monitoring (ADR 0007 Phase 7b)

Self-hosted **Prometheus + Alertmanager + Grafana** for the Nebula control plane. This dir
holds the config; it runs on a **dedicated mesh-member monitoring node** (a small EC2
instance enrolled into the mesh, no special privilege) so Prometheus can reach the
**mesh-only** `/metrics` of core-api/admin-api over the overlay, plus the lighthouse stats
and (optionally) the gateway's internal obs port over the VPC.

```
monitoring node (mesh member, VPC)
  ├─ Prometheus  ── scrape ──► core-api  10.44.0.2:8444/metrics   (overlay, mesh-only)
  │                          ├► admin-api 10.44.0.2:443/metrics   (overlay, mesh-only)
  │                          └► lighthouse 10.44.0.1:8080/metrics (overlay)
  │     (auto-TLS: targets the overlay IP, validates the LE cert via tls_config.server_name)
  ├─ alert rules (alerts.yml) ──► Alertmanager ──► [receiver: placeholder]
  ├─ Loki  ◄── push ── Grafana Alloy on harbor (journald)   [VPC :3100, SG-locked to harbor]
  └─ Grafana (datasources: Prometheus + Loki)
```

Logs (Phase 7c): harbor's `core-api`/`admin-api`/`collect`/`nebula` run via `systemd-run
--collect` (journald); **Grafana Alloy** (promtail's supported successor) on the harbor node
tails the journal and pushes to **Loki** on the monitoring node over the VPC (SG-restricted to
the harbor SG). Query them in Grafana via the Loki datasource (filter by the `unit` label). The
Fargate gateway/lighthouse already ship to CloudWatch via the awslogs driver. (Future hardening:
ship over the overlay instead of the VPC — needs a nebula-policy inbound rule on the monitoring node.)

## Files

| File | Purpose |
|------|---------|
| `prometheus.yml` | scrape config (reference; the bootstrap renders the real overlay IPs + scheme) |
| `alerts.yml` | alert rules on the Phase 7a metrics (breaker open/trips, audit tamper/fail/stale, target down) |
| `alertmanager.yml` | routing — **placeholder `null` receiver** until a real destination is wired |
| `loki-config.yml` | Loki (single-binary, filesystem storage, 30d retention) — the log store |
| `config.alloy` | Grafana Alloy (reference) — runs on harbor, tails journald → Loki; deploy.sh renders the Loki URL |
| `compose.yml` | the Prometheus + Alertmanager + Loki + Grafana stack (`podman compose up -d`) |
| `grafana/provisioning/` | Grafana datasources (Prometheus + Loki) |
| `deploy.sh` | enrolls the node, renders prometheus.yml, deploys the stack + harbor Alloy |

## Deploy

The genesis bootstrap (Phase 7b part 2 — node terraform + enrollment, pending) enrolls the
monitoring node into the mesh, renders `prometheus.yml` with the real overlay IPs + scheme
(`https://<mesh_name>-harbor.<mesh_domain>` when harbor's auto-TLS is on, else http over the
overlay IP), drops this dir, and runs `podman compose up -d`.

## Access

The UIs (Prometheus 9090, Alertmanager 9093, Grafana 3000) are **not public** — the
monitoring node's security group allows only SSH + Nebula UDP (no UI ingress), and the
containers bind on the node's localhost. Reach them via an SSH tunnel to the node:

```
ssh -i <key> -L 3000:localhost:3000 -L 9090:localhost:9090 -L 9093:localhost:9093 ec2-user@<monitoring-ip>
# then http://localhost:3000 (Grafana), :9090 (Prometheus), :9093 (Alertmanager)
```

Set the Grafana admin password out-of-band via `GF_ADMIN_PASSWORD` before running `deploy.sh`
(it lands in a `0600 /opt/ncp-monitoring/.env` on the node, never on a command line or in git).

## Wire a real alert receiver

`alertmanager.yml` currently routes everything to a `null` receiver — alerts fire and are
visible in the UIs but go nowhere. Add a receiver (Slack webhook / email via SES/SMTP /
PagerDuty routing key), supplying the secret out-of-band (an EnvironmentFile / mounted file,
like the Cloudflare token), and point the route (and the `severity="critical"` sub-route) at
it. See the comments in `alertmanager.yml`.
