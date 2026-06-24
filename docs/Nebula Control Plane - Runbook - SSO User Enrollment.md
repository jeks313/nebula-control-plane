---
title: "Runbook — SSO User Enrollment"
created: 2026-06-24
status: living
tags: [nebula, runbook, sso, enrollment, usertrust, adr-0004, operations]
---

# Runbook — SSO User Enrollment

Let directory-group members enroll devices into the mesh through the browser SSO flow
([[Nebula Control Plane - ADR 0004 - SSO-Driven User Enrollment|ADR 0004]]), and publish the
**user-trust** config that authorizes them and assigns their mesh groups.

## How it works (the trust chain)

```
client: pilot enroll --sso
   └─ loopback → gateway /v1/sso/start → IdP (Entra) → gateway /v1/sso/acs
        gateway validates the SAML assertion, signs a SHORT-LIVED assertion with its
        dedicated assert key (NOT a CA), and enqueues the enrollment candidate
   └─ harbor collect PULLS the candidate (ADR 0005)
        ├─ verifies the gateway's signature with  -sso-assert-pub <pub>
        ├─ usertrust.Match(assertion.issuer, assertion.groups) from  -usertrust-db
        └─ issues a cert  (auto_issue=true)  OR  queues for admin approval (auto_issue=false)
```

Two **independent** toggles — both must be on:

- **Gateway side** (the public portal): the gateway's `sso_*` secret fields. The presence of
  `sso_acs_url` enables the portal.
- **Harbor side** (the consumer): `ncp-collect` (issuance) and `ncp-core` / `ncp-admin` (the
  approve path) must run with `-usertrust-db -sso-assert-pub <pub>`, **and** a user-trust config
  must be published. Without these the gateway accepts the SSO login but **no cert is ever issued**.

## The values that matter

| Field | What | Live POC value (2026-06-24) |
|---|---|---|
| **realm** | matched EXACTLY (case + trailing slash) against the assertion `iss`; = the gateway's `sso_issuer` | `https://sts.windows.net/44444444-4444-4444-4444-444444444444/` |
| **directory_group** | the IdP group's **object-ID GUID** (Entra emits GUIDs in the groups claim, not display names) | admins = `55555555-5555-5555-5555-555555555555` |
| **mesh_groups / default_groups** | nebula groups granted (mesh on top of default); don't grant a reserved group (e.g. `control-plane`) with auto_issue | e.g. default `laptops` |
| **auto_issue** | false → queue for admin approval (recommended for first test); true → issue immediately | false |
| gateway base URL | where the client points `pilot enroll --sso` | `https://poc-gateway.mesh.failsafe.net:8443` |

## Prerequisites

1. **Gateway SSO portal enabled.** Verify:
   ```bash
   aws secretsmanager get-secret-value --secret-id ncp-gateway-config --query SecretString --output text \
     | jq '{sso_acs_url, sso_issuer, sso_groups_attr,
            idp:(.sso_idp_metadata!=null), assert:(.sso_assert_key_pem!=null),
            sp_cert:(.sso_sp_cert_pem!=null), sp_key:(.sso_sp_key_pem!=null)}'
   ```
   All present ⇒ the portal answers `/v1/sso/*`.
2. **The enrollment Entra app emits the groups claim.** The gateway uses a SEPARATE Enterprise App
   from the console (SP entityID `…/v1/sso/metadata`). Set that app's **Groups claim** to
   **"Groups assigned to the application"** — this both keeps the admin group present and dodges the
   >150-group **overage** (which sends a `groups.link` instead of inline GUIDs → claim is null →
   `usertrust.Match` finds nothing). Same gotcha that bit the console roles.
3. **Harbor-side consumer wired** (Step 1).

## Step 1 — Wire the harbor-side consumer (one-time)

The bootstrap does this automatically when SSO is enabled at genesis
(`CORE_SSO_FLAGS="-sso-assert-pub $G/sso-assert.pub -usertrust-db"`). For a mesh genesis'd BEFORE
SSO (or after a harbor replace whose snapshot predated SSO — the POC's case), do it by hand:

**a. Put the gateway's assertion-signing PUBLIC key on harbor** (`~/ncp/genesis/sso-assert.pub`).
The gateway secret holds only the PRIVATE half, so derive the public from it:
```bash
aws secretsmanager get-secret-value --secret-id ncp-gateway-config --query SecretString --output text \
  | jq -r .sso_assert_key_pem > /tmp/sso-assert.key
openssl pkey -in /tmp/sso-assert.key -pubout > /tmp/sso-assert.pub   # EC P-256 public half
scp /tmp/sso-assert.pub  ec2-user@<harbor>:/home/ec2-user/ncp/genesis/sso-assert.pub
shred -u /tmp/sso-assert.key /tmp/sso-assert.pub
```

**b. Add the flags and recreate the transient units.** `ncp-collect`/`ncp-core`/`ncp-admin` are
transient (`/run/systemd/transient/…`), so a flag change = recreate with the captured argv plus the
new flags. Append to each:
```
-usertrust-db -sso-assert-pub /home/ec2-user/ncp/genesis/sso-assert.pub
```
Recreate pattern (per unit; mirrors *Runbook — UI redeploy*), healthz-gated with rollback:
```bash
U=ncp-collect; PID=$(systemctl show -p MainPID --value $U)
mapfile -d '' A < /proc/$PID/cmdline
SU=$(systemctl show -p User --value $U); CAP=$(systemctl show -p AmbientCapabilities --value $U)
A+=( -usertrust-db -sso-assert-pub /home/ec2-user/ncp/genesis/sso-assert.pub )
sudo systemctl stop $U; sudo systemctl reset-failed $U
sudo systemd-run --unit $U --collect --uid="$SU" ${CAP:+-p AmbientCapabilities=$CAP} "${A[@]}"
```
- `ncp-collect` is the gateway-SSO **issuance** path (required).
- `ncp-admin` + `ncp-core` get them for the **approve** path (manual approval of a pending SSO host)
  and renewals.

**c. Persist for recover.** Refresh the harbor snapshot bundle (`snapshot-harbor.sh`) so a future
harbor replace keeps `sso-assert.pub` and the flags — otherwise the next replace silently drops
SSO again.

## Step 2 — Publish the user-trust config

Config JSON — `{default_groups, idp_entries:[{realm, directory_group, mesh_groups, auto_issue, netblock}]}`:
```json
{
  "default_groups": ["laptops"],
  "idp_entries": [
    {
      "realm": "https://sts.windows.net/44444444-4444-4444-4444-444444444444/",
      "directory_group": "55555555-5555-5555-5555-555555555555",
      "mesh_groups": [],
      "auto_issue": false,
      "netblock": ""
    }
  ]
}
```
Publish — **CLI** (two-operator bootstrap/break-glass path; the operators must differ — propose-as-A,
approve-as-B):
```bash
. /etc/profile.d/harbor-cli.sh          # sets HARBOR_DB_* env; the EC2 role fetches the DB secret
harbor usertrust publish -config /tmp/usertrust.json -operator-a chris -operator-b cli-bootstrap \
  -description "admins may SSO-enroll; default group laptops"
```
Or the **console** (day-to-day path, real two-admin dual-control): **User Trust → Add IdP entries**.

Validation (server + console): ≥1 entry; each needs realm + directory_group; `(realm,
directory_group)` unique; an entry must grant something (its `mesh_groups` or non-empty
`default_groups`); an `auto_issue` entry must not grant a reserved group.

## Step 3 — Test the enrollment

On an un-enrolled client:
```bash
pilot enroll -gateway https://poc-gateway.mesh.failsafe.net:8443 -config-pub <config-signing.pub> \
  --sso -name <device-name> [-dir /etc/nebula]
```
- Opens your browser to Entra — sign in as a directory-group member (an admin).
- With `auto_issue=false`: prints **"submitted — awaiting admin approval"** and queues the device.
  Approve it in the console **Enrollments / Approvals**, then re-run `pilot enroll --sso` to fetch the
  issued cert.
- Verify: the device appears in **Devices** / `harbor fleet` carrying the granted group(s) (`laptops`).

## Troubleshooting

- **SSO login succeeds but no enrollment appears / no cert:** `ncp-collect` is missing
  `-usertrust-db`/`-sso-assert-pub`, or `sso-assert.pub` doesn't match the gateway's assert key.
- **Enrollment appears but is denied / no match:** realm mismatch (exact, **trailing slash**); or the
  groups claim is empty (overage → set "Groups assigned to the application"); or `directory_group`
  was a display name, not the GUID.
- **Stuck "awaiting admin approval":** `auto_issue=false` and nobody approved — approve in the console.
- **Reserved-group refusal on publish:** an `auto_issue` entry granted `control-plane` (or via
  `default_groups`) — set `auto_issue=false` for privileged groups (an admin approves instead).

## Related

- [[Nebula Control Plane - ADR 0004 - SSO-Driven User Enrollment|ADR 0004]] — the SSO enrollment design.
- [[Nebula Control Plane - ADR 0005 - Pull-Based Enrollment Gateways|ADR 0005]] — why `harbor collect` (not Core) issues the gateway's candidates.
- [[Nebula Control Plane - ADR 0009 - Control-Plane Trust-Zone Separation|ADR 0009]] — issuance-mode guard.
- [[Nebula Control Plane - Runbook - Entra ID SAML SSO for the Console]] — the console-login SAML app (distinct from the enrollment app).
