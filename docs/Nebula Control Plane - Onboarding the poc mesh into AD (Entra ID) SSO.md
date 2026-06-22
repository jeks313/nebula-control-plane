# Onboarding the `poc` mesh into AD (Entra ID) SSO

This mesh has **two** distinct SSO surfaces, so AD/Entra needs **two separate SAML Enterprise
Applications** — one per surface. This is not optional duplication: the two surfaces have
different Reply URLs (ACS) and **must** carry distinct SP entity IDs, or the SAML audience check
collapses and a login assertion minted for one surface could be replayed at the other (ADR 0009
trust-zone separation). The bootstrap enforces it — it aborts if enrollment SSO is enabled
without an entity ID distinct from the console's.

| # | SSO surface | What it's for | Where it lives | Current `poc` state |
|---|---|---|---|---|
| 1 | **Admin Console** | operators sign in to *manage* the mesh | mesh-only, on Harbor (`poc-harbor.mesh.failsafe.net:443`) | **dev mock-IdP** — flip to Entra with Parts A–B below |
| 2 | **Enrollment Portal** (ADR 0004) | end users *self-enroll a device* into the mesh via SSO | **public**, on the off-mesh gateway (`poc-gateway.mesh.failsafe.net:8443`) | **OFF** (fail-closed-disabled) — see the last section |

The two apps share the **same tenant, the same users, and the same directory groups** — same
people, same group claim. Only the **app registration** (ACS, entity ID, SP cert) and the
**group → X mapping** differ: the console maps groups → console RBAC roles (`admin`/`operator`/
`viewer`); the portal maps groups → mesh groups + netblock via a published `user-trust` config.

> Most of this doc is **App 1 — the Console flip** (the live, actionable change today). **App 2 —
> the Enrollment Portal** is currently **off** on the poc; its section explains the second app,
> what enabling it entails (a bootstrap re-run, not a hand-restart), and cross-references ADR 0004
> for the full operator threading.

---

## App 1 — Admin Console SSO (the live flip)

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

### This mesh's exact values (no guessing)

| Thing | Value |
|---|---|
| Console base URL | `https://poc-harbor.mesh.failsafe.net` |
| **Entity ID / Identifier** (paste into Entra) | `https://poc-harbor.mesh.failsafe.net/admin/v1/auth/saml/metadata` |
| **Reply URL / ACS** (paste into Entra) | `https://poc-harbor.mesh.failsafe.net/admin/v1/auth/saml/acs` |
| Group claim name (Harbor default) | `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` |
| Console roles | `admin`, `operator`, `viewer` (unmapped → `viewer`, read-only) |
| Harbor node | EC2 instance `i-0dfc8bfb6d0873954` — reached over **SSM**, not a public IP (see the access note) |
| Harbor overlay / console bind | `10.44.0.2:443` |
| Aurora DSN | `postgres://ncp-aurora.cluster-c3sz1gv66azn.ca-central-1.rds.amazonaws.com:5432/harbor?sslmode=require` |
| DB secret ARN | `arn:aws:secretsmanager:ca-central-1:308040853462:secret:rds!cluster-989db997-7db1-47a7-a3a2-8f76813085d8-ed3Wrl` |
| KMS CA key | `arn:aws:kms:ca-central-1:308040853462:key/df747692-cac2-40f9-a91d-b9df7ab7fd55` |
| KMS config-signing key | `arn:aws:kms:ca-central-1:308040853462:key/74ec14a5-5e42-4a7c-bbe0-3b9c8bef81e9` |
| Region | `ca-central-1` |

HTTPS is already satisfied (the console has a real LE cert for `poc-harbor.mesh.failsafe.net`), so
the SAML `Secure` cookie requirement is met — no blockers.

> **Node access on this poc is SSM-only.** The harbor/client/monitoring nodes have **no public
> IP**; you reach them by SSH tunnelled through SSM Session Manager, targeting the **instance ID**
> (not an IP). Set this up once in your shell (needs `session-manager-plugin`, the EC2 key pair,
> and AWS creds for `ca-central-1`):
> ```bash
> cd /path/to/nebula-control-plane/deploy/prod/terraform/app
> HB_ID=$(terraform output -json instance_ids | jq -r .harbor)   # currently i-0dfc8bfb6d0873954
> SSM_PROXY="ProxyCommand=aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p --region ca-central-1"
> ```
> Every `ssh`/`scp` below uses `-o "$SSM_PROXY"` and `$HB_ID` as the host. This mirrors how
> `bootstrap-genesis.sh` reaches the nodes — **derive the instance ID from terraform, never
> hardcode a public IP** (it changes on instance replacement).

### Part A — Register the **Console** app in Entra/AD

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

### Part B — Flip the live console to SAML (on the Harbor node)

(Assumes you've exported `$HB_ID` and `$SSM_PROXY` per the access note above.)

#### B.1 Make the SP signing keypair — **must be RSA**

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout sp.key -out sp.crt -days 825 -subj "/CN=poc-harbor-sp"
```

(An EC key is rejected at startup. Custody `sp.key` like a production secret.)

#### B.2 Deliver the keypair to the node (0600, never on argv)

```bash
ssh -i ~/.ssh/absolute -o "$SSM_PROXY" ec2-user@$HB_ID 'umask 077; mkdir -p ~/ncp/saml'
scp -i ~/.ssh/absolute -o "$SSM_PROXY" sp.key ec2-user@$HB_ID:~/ncp/saml/sp.key
scp -i ~/.ssh/absolute -o "$SSM_PROXY" sp.crt ec2-user@$HB_ID:~/ncp/saml/sp.crt
ssh -i ~/.ssh/absolute -o "$SSM_PROXY" ec2-user@$HB_ID 'chmod 600 ~/ncp/saml/sp.key; chmod 644 ~/ncp/saml/sp.crt'
```

#### B.3 Save the current (mock) command — your rollback

Capture what `ncp-admin` runs now, so you can restore it if SSO misbehaves:

```bash
ssh -i ~/.ssh/absolute -o "$SSM_PROXY" ec2-user@$HB_ID 'systemctl show ncp-admin -p ExecStart'
# copy this somewhere; it ends with the mock IdP flags
```

#### B.4 Restart `ncp-admin` with SAML (production)

Stop the mock console and relaunch with the SAML flags. Everything except the IdP block is this
mesh's existing config. Fill in **`<FEDERATION-METADATA-URL>`** and **`<ADMIN-GROUP-GUID>`**:

```bash
ssh -i ~/.ssh/absolute -o "$SSM_PROXY" ec2-user@$HB_ID 'bash -s' <<"REMOTE"
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
- **If App 2 (the portal) is also enabled**, the bootstrap additionally puts `-sso-assert-pub
  ~/ncp/genesis/sso-assert.pub -usertrust-db` on `ncp-admin` (so it can approve pending SSO
  enrollments). On the poc today the portal is **off**, so those flags are absent — leave them out.
  If you later enable the portal, do it through the bootstrap (App 2 section), which re-derives this
  whole ExecStart; don't hand-merge the SSO flags.

---

### Verify (before you rely on it)

From any enrolled mesh member (the client node, or your off-mesh iMac once it's enrolled):

```bash
curl -sk https://poc-harbor.mesh.failsafe.net/admin/v1/auth/saml/metadata    # returns SP XML
```

Then in a browser on a mesh member:
1. Open `https://poc-harbor.mesh.failsafe.net/` → you're redirected to Microsoft → sign in as an
   **admin-group** member → you land in the console **as admin** (and it's in the audit log).
2. Sign in as someone **not** in any mapped group → you land as **viewer** (fail-closed proof).

### If it breaks

- **Everyone is `viewer`, even admins** → role map mismatch: GUIDs must be the assigned groups'
  **Object IDs**, use **`;`** between groups, and confirm the group claim is emitted (Part A.3).
- **`admin-api: SAML SP key must be RSA`** → you made an EC key; redo B.1 with `rsa:2048`.
- **Login loops / cookie error** → the browser URL must match the registered ACS **exactly** (host +
  no port, since 443), and must be HTTPS.
- **"Reply URL/Identifier doesn't match"** → a character differs between Entra and the values above.

### Rollback / break-glass

- **Roll back** by re-running B.4 with your **saved mock ExecStart** (B.3) — i.e. `-mock-idp
  -mock-idp-addr 10.44.0.2:8446 -environment development` instead of the SAML/production block.
- Keep a **non-interactive bearer admin token** (minted out-of-band) so you can administer even if
  SSO is down. **Validate SSO end-to-end before discarding it.**
- Sessions live server-side in **Aurora**, so they survive an `ncp-admin` restart.

---

## App 2 — Enrollment Portal SSO (ADR 0004) — currently OFF on the `poc`

The second SAML app is for **user self-enrollment**: someone with a brand-new laptop that isn't on
the mesh yet signs in with their AD account at a **public** portal and gets a device enrollment
that an admin then approves. It is a fundamentally different surface from the console:

- The console is **mesh-only** — you must already be on the mesh to reach it. A new laptop can't.
- So the portal lives on the **off-mesh gateway** (`poc-gateway.mesh.failsafe.net:8443`, the same
  public surface used for enroll), as HTTP routes `/v1/sso/start` + `/v1/sso/acs`. It holds the
  IdP metadata + an assertion-signing key but **no CA** — Core still issues every cert (ADR 0004 /
  ADR 0009).

**Current `poc` state: OFF (fail-closed-disabled).** The code is shipped and the bootstrap is fully
wired for it, but no second SAML app is registered, no `user-trust` config is published, and
`SSO_ACS_URL` is empty — so the gateway runs with `Config.SSO == nil` and the portal routes are
dark. There's nothing to roll back; it simply isn't serving.

### The second Entra app — this mesh's values

Register a **second**, separate Enterprise App (same flow as Part A, same tenant/users/groups),
distinct from the console app:

| Thing | Value |
|---|---|
| App name (suggestion) | `Nebula Enrollment Portal (poc)` |
| **Reply URL / ACS** | `https://poc-gateway.mesh.failsafe.net:8443/v1/sso/acs` |
| **Identifier (Entity ID)** | operator-chosen, **must differ from the console's**; e.g. `https://poc-gateway.mesh.failsafe.net:8443/v1/sso/metadata` |
| Group claim | same as the console (`http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`) — same claim, different mapping |
| Issuer / realm | the IdP's issuer (Entra's `entityID`), fed to Core's `user-trust` match |

> **Why a second app and not "reuse the console's":** the IdP only POSTs a SAML response to a
> *registered* ACS, and the two ACS URLs differ (one mesh-only console, one public gateway). The
> SP entity IDs **must** also differ so the SAML audience check stops a console assertion being
> replayed at the portal (or vice-versa) — trust-zone separation per ADR 0009. One app cannot
> serve both, and the bootstrap **aborts** if you enable portal SSO without an entity ID distinct
> from the console's.

### Turning it on (a bootstrap re-run, not a hand-restart)

Unlike the console flip, the portal lives on the **Fargate** gateway — there's no shell to
hand-edit. You enable it by re-running `deploy/prod/bootstrap-genesis.sh` with the `SSO_*`
environment set. The bootstrap then distributes the genesis-minted assertion keypair (private half
→ gateway secret, public half pinned on Core), mints + snapshots a **stable** RSA SP keypair (the
Entra app pins this SP cert, so it must survive recreates), wires the gateway secret / task-def
`-sso-*` env, and adds `-sso-assert-pub -usertrust-db` to **core-api and admin-api** so a pending
SSO enrollment can be approved. The minimum env (full list in ADR 0004 → *Operator setup (live
rollout)*):

```bash
export SSO_ACS_URL='https://poc-gateway.mesh.failsafe.net:8443/v1/sso/acs'         # the enable TRIGGER
export SSO_ENTITY_ID='https://poc-gateway.mesh.failsafe.net:8443/v1/sso/metadata'  # MUST differ from the console's
export SSO_ISSUER='<the Entra app issuer / entityID>'                              # fed to Core's usertrust.Match
export SSO_IDP_METADATA_URL='<the SECOND app's App Federation Metadata Url>'       # or SSO_IDP_METADATA_FILE=<path>
# then re-run bootstrap-genesis.sh the usual way (with creds for ca-central-1)
```

You also need a **published `user-trust` config** mapping `AD group → mesh groups + netblock +
admission posture` (default **pending approval**; never auto-issue admin groups). Today that's a
dual-control publish (`harbor usertrust publish`, or the console's user-trust editor) — see ADR
0004 and `docs/SSO-DECISIONS.md`. (ADR 0011 Phase 2 will move this to declarative
Terraform-managed config; until then it's the dual-control publish.)

> ⚠️ **Interaction with the console flip (App 1):** a bootstrap re-run re-derives the **console's**
> IdP flags too. If you've already hand-flipped the console to Entra SAML (Part B) and *then*
> enable the portal via bootstrap, pass the `SAML_*` env (per the console runbook) in the **same**
> run — otherwise the bootstrap restarts `ncp-admin` back on the **mock-IdP** default. Easiest
> path: set both the `SAML_*` (console) and `SSO_*` (portal) env and let one bootstrap run
> configure both apps coherently.

### Full design + threading

- **ADR 0004 — SSO-Driven User Enrollment** (`docs/Nebula Control Plane - ADR 0004 - SSO-Driven
  User Enrollment.md`): the portal architecture, the pubkey/nonce binding + anti-relay security,
  and the *Operator setup (live rollout)* checklist (every `SSO_*` / `-sso-*` flag + the assertion
  keypair distribution).
- **`docs/SSO-DECISIONS.md`** — the decision log (dedicated ECDSA assertion key, default-pending,
  trust-zone separation).
- **`deploy/prod/bootstrap-genesis.sh`** — the actual threading: empty `SSO_ACS_URL` ⇒ none of the
  SSO wiring fires (gateway/Core/recover are byte-for-behavior unchanged).
