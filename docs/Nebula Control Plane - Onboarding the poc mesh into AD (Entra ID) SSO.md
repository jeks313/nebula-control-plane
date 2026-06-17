# Onboarding the `poc` mesh into AD (Entra ID) SSO

Concrete, copy-paste steps to switch **this running mesh's** admin console from the dev
**mock-IdP** to **"sign in with your Microsoft/AD work account"** (SAML SSO).

This is the *live-flip* companion to the general runbook (`Nebula Control Plane - Runbook -
Entra ID SAML SSO for the Console.md`) — read that for the concepts/glossary. Here we use this
deployment's **actual** values and **restart only the console** (`ncp-admin`); the lighthouse,
core-api, gateway, Aurora, and the already-enrolled client are untouched. It's a **config-only**
change — no code, no re-genesis, no re-enrollment.

> Current state: the console is live at **https://poc-harbor.mesh.failsafe.net** (mesh-only, 443,
> Let's Encrypt cert) running `harbor admin-api … -mock-idp -environment development`. We replace
> the mock flags with the SAML flags and flip `-environment` to `production`.

---

## This mesh's exact values (no guessing)

| Thing | Value |
|---|---|
| Console base URL | `https://poc-harbor.mesh.failsafe.net` |
| **Entity ID / Identifier** (paste into Entra) | `https://poc-harbor.mesh.failsafe.net/admin/v1/auth/saml/metadata` |
| **Reply URL / ACS** (paste into Entra) | `https://poc-harbor.mesh.failsafe.net/admin/v1/auth/saml/acs` |
| Group claim name (Harbor default) | `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` |
| Console roles | `admin`, `operator`, `viewer` (unmapped → `viewer`, read-only) |
| Harbor node (SSH) | `ec2-user@16.52.238.152` |
| Harbor overlay / console bind | `10.44.0.2:443` |
| Aurora DSN | `postgres://ncp-aurora.cluster-c3sz1gv66azn.ca-central-1.rds.amazonaws.com:5432/harbor?sslmode=require` |
| DB secret ARN | `arn:aws:secretsmanager:ca-central-1:308040853462:secret:rds!cluster-989db997-7db1-47a7-a3a2-8f76813085d8-ed3Wrl` |
| KMS CA key | `arn:aws:kms:ca-central-1:308040853462:key/df747692-cac2-40f9-a91d-b9df7ab7fd55` |
| KMS config-signing key | `arn:aws:kms:ca-central-1:308040853462:key/74ec14a5-5e42-4a7c-bbe0-3b9c8bef81e9` |
| Region | `ca-central-1` |

HTTPS is already satisfied (the console has a real LE cert for `poc-harbor.mesh.failsafe.net`), so
the SAML `Secure` cookie requirement is met — no blockers.

---

## Part A — Register Harbor in Entra/AD

In `entra.microsoft.com` (need *Application/Cloud Application Administrator*):

1. **Enterprise applications → New application → Create your own → Non-gallery** → name it
   `Nebula Harbor Console (poc)` → Create.
2. **Single sign-on → SAML → Basic SAML Configuration → Edit**, paste **verbatim**:
   - **Identifier (Entity ID):** `https://poc-harbor.mesh.failsafe.net/admin/v1/auth/saml/metadata`
   - **Reply URL (ACS):** `https://poc-harbor.mesh.failsafe.net/admin/v1/auth/saml/acs`
   - Save.
3. **Attributes & Claims → Add a group claim → Security groups → Source: Group ID → Save.**
   (Emits the claim under the name Harbor already expects — no change needed.)
4. **Copy the `App Federation Metadata Url`** (looks like
   `https://login.microsoftonline.com/<tenant>/federationmetadata/2007-06/federationmetadata.xml?appid=<app-id>`).
5. **Users and groups → Add** your admin security group (and optional operator/viewer groups).
6. Note each group's **Object ID (GUID)** (Groups → *group* → Object Id).

Leave Entra with: the **Federation Metadata URL** + the **admin group GUID** (and any others).

> ADFS instead of Entra? Same flow — use ADFS's federation metadata URL and its group claim name
> (set `-saml-groups-attr` to whatever claim ADFS emits group SIDs/names under).

---

## Part B — Flip the live console to SAML (on the Harbor node)

### B.1 Make the SP signing keypair — **must be RSA**

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout sp.key -out sp.crt -days 825 -subj "/CN=poc-harbor-sp"
```

(An EC key is rejected at startup. Custody `sp.key` like a production secret.)

### B.2 Deliver the keypair to the node (0600, never on argv)

```bash
ssh -i ~/.ssh/absolute ec2-user@16.52.238.152 'umask 077; mkdir -p ~/ncp/saml'
scp -i ~/.ssh/absolute sp.key ec2-user@16.52.238.152:~/ncp/saml/sp.key
scp -i ~/.ssh/absolute sp.crt ec2-user@16.52.238.152:~/ncp/saml/sp.crt
ssh -i ~/.ssh/absolute ec2-user@16.52.238.152 'chmod 600 ~/ncp/saml/sp.key; chmod 644 ~/ncp/saml/sp.crt'
```

### B.3 Save the current (mock) command — your rollback

On the node, capture what `ncp-admin` runs now, so you can restore it if SSO misbehaves:

```bash
systemctl show ncp-admin -p ExecStart   # copy this somewhere; it ends with the mock IdP flags
```

### B.4 Restart `ncp-admin` with SAML (production)

Stop the mock console and relaunch with the SAML flags. Everything except the IdP block is this
mesh's existing config. Fill in **`<FEDERATION-METADATA-URL>`** and **`<ADMIN-GROUP-GUID>`**:

```bash
ssh -i ~/.ssh/absolute ec2-user@16.52.238.152 'bash -s' <<"REMOTE"
set -e
sudo systemctl stop ncp-admin 2>/dev/null || true
sudo systemctl reset-failed ncp-admin 2>/dev/null || true
sudo systemd-run --uid=ec2-user --gid=ec2-user -p AmbientCapabilities=CAP_NET_BIND_SERVICE \
  --unit ncp-admin --collect /usr/local/bin/harbor admin-api \
  -driver postgres \
  -dsn 'postgres://ncp-aurora.cluster-c3sz1gv66azn.ca-central-1.rds.amazonaws.com:5432/harbor?sslmode=require' \
  -db-secret-arn 'arn:aws:secretsmanager:ca-central-1:308040853462:secret:rds!cluster-989db997-7db1-47a7-a3a2-8f76813085d8-ed3Wrl' \
  -db-secret-region ca-central-1 \
  -ca-cert ~/ncp/genesis/ca.crt \
  -backend kms \
  -kms-ca-key-id arn:aws:kms:ca-central-1:308040853462:key/df747692-cac2-40f9-a91d-b9df7ab7fd55 \
  -kms-config-key-id arn:aws:kms:ca-central-1:308040853462:key/74ec14a5-5e42-4a7c-bbe0-3b9c8bef81e9 \
  -kms-region ca-central-1 \
  -hmac-key ~/ncp/hmac.b64 -queue-dsn ~/ncp/queue.db -queue-key ~/ncp/queue.b64 -pool '10.44.0.0/16' \
  -addr 10.44.0.2:443 -base-url https://poc-harbor.mesh.failsafe.net \
  -environment production \
  -saml-idp-metadata-url '<FEDERATION-METADATA-URL>' \
  -saml-sp-key ~/ncp/saml/sp.key -saml-sp-cert ~/ncp/saml/sp.crt \
  -saml-groups-attr 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups' \
  -role-map '<ADMIN-GROUP-GUID>=admin'
echo started
REMOTE
```

- **What changed vs. the mock unit:** dropped `-mock-idp -mock-idp-addr 10.44.0.2:8446`, flipped
  `-environment development` → `production`, added the four `-saml-*` flags. **Diff your saved
  ExecStart (B.3) against this** — every non-IdP flag should be identical (DSN/KMS/addr/base-url).
- **Role map:** `;` separates groups (`GUID=admin;GUID2=operator`); a `,` would mean multiple roles
  for one group. **Pin at least one group to `admin`** or nobody can administer.
- **ACME flags:** if your saved ExecStart had `-acme-domain …` (it should — that's what serves the
  LE cert), append the same `-acme-domain poc-harbor.mesh.failsafe.net -acme-cloudflare-token-file
  ~/ncp/cf-token -acme-cache ~/ncp/acme -acme-email chyde@absolute.com` block here too. Without it the
  console can't serve HTTPS and SAML's Secure cookie fails.

---

## Verify (before you rely on it)

From a mesh member (e.g. the enrolled client `10.44.0.3`, or the iMac):

```bash
curl -sk https://poc-harbor.mesh.failsafe.net/admin/v1/auth/saml/metadata    # returns SP XML
```

Then in a browser on a mesh member:
1. Open `https://poc-harbor.mesh.failsafe.net/` → you're redirected to Microsoft → sign in as an
   **admin-group** member → you land in the console **as admin** (and it's in the audit log).
2. Sign in as someone **not** in any mapped group → you land as **viewer** (fail-closed proof).

## If it breaks

- **Everyone is `viewer`, even admins** → role map mismatch: GUIDs must be the assigned groups'
  **Object IDs**, use **`;`** between groups, and confirm the group claim is emitted (Part A.3).
- **`admin-api: SAML SP key must be RSA`** → you made an EC key; redo B.1 with `rsa:2048`.
- **Login loops / cookie error** → the browser URL must match the registered ACS **exactly** (host +
  no port, since 443), and must be HTTPS.
- **"Reply URL/Identifier doesn't match"** → a character differs between Entra and the values above.

## Rollback / break-glass

- **Roll back** by re-running B.4 with your **saved mock ExecStart** (B.3) — i.e. `-mock-idp
  -mock-idp-addr 10.44.0.2:8446 -environment development` instead of the SAML/production block.
- Keep a **non-interactive bearer admin token** (minted out-of-band) so you can administer even if
  SSO is down. **Validate SSO end-to-end before discarding it.**
- Sessions live server-side in **Aurora**, so they survive an `ncp-admin` restart.
