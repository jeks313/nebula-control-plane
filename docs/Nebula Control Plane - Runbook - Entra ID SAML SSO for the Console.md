---
title: "Runbook — Log into the Harbor console with Microsoft Entra ID (SAML SSO)"
created: 2026-06-14
status: active
tags: [nebula, runbook, saml, entra-id, azure-ad, sso, idp, adminauth, production]
---

# Runbook — Log into the Harbor console with Microsoft Entra ID (SAML SSO)

**Status (2026-06-18):** PLANNED — not yet performed. Harbor's SAML code path is shipped and the genesis
bootstrap is fully wired to drive it (the steps below are accurate against current code), but the live poc/prod
console still runs the **dev mock-IdP**. Switching it to real Entra SAML is the remaining prod-grade console-auth
gap; this runbook is the procedure to close it, and the first round-trip has not been exercised on real AWS yet.

This guide switches the Harbor admin console from its built-in **fake login** (the "mock IdP",
fine for a demo) to **"sign in with your Microsoft work account."** It assumes **no prior SAML
knowledge** — every term is explained, and every value you need is spelled out.

> **Scope — this is one of two SAML apps.** This runbook sets up the **admin console** app only
> (operators signing in to manage the mesh). The mesh has a second, separate SSO surface — the
> **enrollment portal** where end users self-enroll a device (ADR 0004), on the public off-mesh
> gateway. It needs its **own** Entra app with a **distinct** Entity ID and ACS (`/v1/sso/acs` on
> :8443); the bootstrap aborts if its Entity ID isn't distinct from the console's (SAML audience
> separation, ADR 0009). It's currently **off** on the poc. See ADR 0004 and the *Onboarding the
> poc mesh into AD (Entra ID) SSO* doc for both apps.

You do **not** write any code. Harbor already speaks SAML; you (1) tell Microsoft about Harbor,
(2) tell Harbor about Microsoft, and (3) re-run the genesis bootstrap with a few environment
variables set. That's it.

---

## Plain-English glossary (read this once)

- **SSO (Single Sign-On):** log in once with your company account instead of a console-specific password.
- **IdP (Identity Provider):** the system that knows who your people are and which groups they're in. Here that's **Microsoft Entra ID** (the new name for Azure AD).
- **SP (Service Provider):** the app that trusts the IdP to vouch for you. Here that's the **Harbor admin console**.
- **SAML:** the standard "language" the IdP and SP use to pass a signed *"yes, this is Alice, and she's in the Admins group"* message.
- **Entity ID (a.k.a. "Identifier"):** a unique name for the SP, written as a URL. Both sides must use the *exact same string* or they won't recognize each other. *(This mesh has two SPs — the console and the enrollment portal — so each is a separate Entra app and the two Entity IDs must **differ** from each other; "same string" means matching the console's two sides, not reusing the console's app for the portal.)*
- **ACS (Assertion Consumer Service) URL, a.k.a. "Reply URL":** the console address where Entra sends your browser back to (carrying the signed login message) after you authenticate. Must match on both sides.
- **SP metadata:** a little XML file Harbor publishes that describes itself (its Entity ID, its ACS, its signing certificate). Optional convenience — you can import it into Entra instead of typing values.
- **Federation metadata (URL or XML):** the *IdP's* equivalent — Entra publishes it so Harbor can learn Entra's sign-in address and signing certificate. You give this URL to Harbor.
- **Claim:** a fact in the signed message (e.g. your username, your group memberships). The **group claim** is the one that drives your role.
- **Group Object ID (GUID):** Entra identifies each group by a long unique id like `11111111-2222-3333-4444-555555555555` (not the human name). You'll copy this for the admin group.
- **Role map:** Harbor's table of *"this Entra group → this console role."* Roles are `admin`, `operator`, `viewer`. Unmapped people get `viewer` only (read-only) — this is deliberate and safe.

## How the login will actually work (the "dance")

1. You open the console in a browser. It says "you're not logged in" and **bounces your browser to Microsoft**.
2. You sign in at Microsoft (with MFA, etc. — Microsoft's normal flow).
3. Microsoft **sends your browser back to the console's ACS URL** carrying a signed message that says who you are and which groups you're in.
4. The console checks Microsoft's signature, looks up your group in its **role map**, and logs you in **with that role**.

Harbor never sees your password — only Microsoft's signed "yes." Microsoft never contacts the console directly; it just redirects *your browser*, so the console can stay private to the mesh.

---

## Before you start

- **The mesh is already stood up** — terraform applied and `bootstrap-genesis.sh` run at least once (see ADR 0007 and the Genesis Runbook). If your console currently shows the mock login, you're here.
- **HTTPS is mandatory** — and this is the #1 gotcha. SAML's return trip sets a browser cookie that browsers will only send over **HTTPS** (it's a `Secure`, cross-site cookie). So the console must have a real `https://…` address, which only happens when you set **`mesh_name` + `mesh_domain`** (Harbor then gets a Let's Encrypt cert via ACME — see the edge-TLS layer). **If you haven't set those, the bootstrap will refuse SAML and tell you so.** Plain HTTP on the raw overlay IP cannot work.
- **An Entra tenant** where you can create an **Enterprise Application** (you need the *Application Administrator* or *Cloud Application Administrator* role).
- **An Entra security group** for the people who should be console admins. Get its **Object ID** (Entra admin center → Groups → your group → *Object Id* — the GUID). Optionally separate groups for operators/viewers.
- **Your browser must reach the console.** The console is **mesh-only** (it lives on the overlay network). So browse from a machine that's enrolled in the mesh (e.g. the iMac) and that resolves the Harbor name to its overlay IP (a `hosts` entry or split-horizon DNS — see the genesis output). Microsoft does *not* need to reach the console; only your browser does.

---

## Your three URLs — write these down first

Everything hinges on three URLs, and you can compute all of them **right now** from your
`mesh_name` and `mesh_domain` (no need to run anything first). The console runs on the standard
HTTPS port (443), so its address ("base URL") is just `https://<mesh_name>-harbor.<mesh_domain>`.

Worked example with `mesh_name = poc` and `mesh_domain = mesh.failsafe.net`:

| What | Value (with the example) |
|---|---|
| **Base URL** (the console) | `https://poc-harbor.mesh.failsafe.net` |
| **Entity ID / Identifier** | `https://poc-harbor.mesh.failsafe.net/admin/v1/auth/saml/metadata` |
| **Reply URL / ACS** | `https://poc-harbor.mesh.failsafe.net/admin/v1/auth/saml/acs` |

> ℹ️ **No port in these URLs** — the console is on the standard HTTPS port **443**. (If you override
> `ADMIN_PORT` to something non-standard, add `:<port>` to all three.) The bootstrap re-prints these
> exact values when it wires SAML, so you can copy them verbatim into Entra.

---

## Part A — Tell Microsoft Entra about Harbor

In the Entra admin center (`entra.microsoft.com`):

1. **Create the app.** Identity → Applications → **Enterprise applications** → **New application** → **Create your own application** → name it (e.g. `Nebula Harbor Console`) → choose **"Integrate any other application you don't find in the gallery (Non-gallery)"** → **Create**.

2. **Start SAML.** Open the app → **Single sign-on** → choose **SAML**.

3. **Basic SAML Configuration** → **Edit**, and paste your two URLs from above:
   - **Identifier (Entity ID):** your Entity ID URL (e.g. `https://poc-harbor.mesh.failsafe.net/admin/v1/auth/saml/metadata`).
   - **Reply URL (Assertion Consumer Service URL):** your ACS URL (e.g. `…/admin/v1/auth/saml/acs`).
   - **Sign on URL:** optional; leave blank or set the base URL.
   - **Save.**

4. **Add the group claim.** Attributes & Claims → **Add a group claim** → choose **Security groups** (or *Groups assigned to the application* to keep the message small if your groups are big) → **Source attribute: Group ID** → Save.
   - This emits the claim under the name `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` — Harbor already expects exactly this, so you don't have to change anything.

5. **Copy the IdP metadata.** On the SAML page, find **App Federation Metadata Url** and copy it (it looks like `https://login.microsoftonline.com/<tenant-id>/federationmetadata/2007-06/federationmetadata.xml?appid=<app-id>`). You'll give this to Harbor as `SAML_METADATA_URL`.

6. **Assign who can log in.** App → **Users and groups** → **Add user/group** → add your **admin** security group (and any operator/viewer groups). Only assigned people can sign in.

**Before leaving Entra, make sure you have:**
- the **App Federation Metadata Url** (step 5), and
- the **Object ID (GUID)** of your admin group (and any operator/viewer groups).

---

## Part B — Tell Harbor about Microsoft (re-run the bootstrap)

You give Harbor four things: the IdP metadata URL, a signing keypair, the role map, and (already
defaulted) the group-claim name. The bootstrap delivers the keypair securely and starts the console
in production mode for you.

### 1. Make a signing keypair (one command)

Harbor signs its requests to Microsoft with its own keypair. **It must be an RSA key** (the SAML
library requires RSA — an EC/elliptic-curve key will be rejected at startup). Generate a stable one
(don't let Harbor auto-generate a throwaway one):

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout sp.key -out sp.crt -days 825 -subj "/CN=nebula-harbor-sp"
```

This writes `sp.key` (private — keep it safe) and `sp.crt` (the matching cert). Custody `sp.key`
like any production secret.

### 2. Build the role map

This maps **Entra group Object IDs (GUIDs)** to console roles. The format is
`GROUP=role` pairs **separated by semicolons** (`;`). (A single group can have multiple roles
with commas, e.g. `GROUP=admin,operator`.)

```bash
# one admin group:
SAML_ROLE_MAP="11111111-2222-3333-4444-555555555555=admin"
# admin + operators:
SAML_ROLE_MAP="11111111-...=admin;66666666-...=operator"
```

> ⚠️ Use **semicolons between groups**, not commas. **Pin at least one group to `admin`** or no
> one can administer the console. Anyone who authenticates but isn't in a mapped group gets
> `viewer` only (this fail-closed default is intentional).

### 3. Run the bootstrap with the SAML environment variables set

Set these, then run the genesis bootstrap the same way you normally do:

| Environment variable | What to put in it | Required? |
|---|---|---|
| `SAML_METADATA_URL` | the **App Federation Metadata Url** from Part A step 5 | yes (or `SAML_METADATA_FILE` with a downloaded XML path) |
| `SAML_SP_KEY_FILE` | path to `sp.key` from B.1 | yes |
| `SAML_SP_CERT_FILE` | path to `sp.crt` from B.1 | yes |
| `SAML_ROLE_MAP` | the map from B.2 | yes |
| `SAML_ENTITY_ID` | only if you used a *custom* Identifier in Entra (otherwise leave unset — it defaults to your metadata URL) | no |
| `SAML_GROUPS_ATTR` | only for a non-Entra IdP or a renamed claim (it already defaults to the Entra claim name) | no |

```bash
export SAML_METADATA_URL="https://login.microsoftonline.com/<tenant>/federationmetadata/2007-06/federationmetadata.xml?appid=<app-id>"
export SAML_SP_KEY_FILE=./sp.key
export SAML_SP_CERT_FILE=./sp.crt
export SAML_ROLE_MAP="11111111-2222-3333-4444-555555555555=admin"

SSH_KEY=~/.ssh/your-key  aws-vault exec nebula -- bash deploy/prod/bootstrap-genesis.sh
```

What the bootstrap does with these:
- **Refuses to continue if you don't have HTTPS** (i.e. `mesh_name`/`mesh_domain` unset) — because SAML can't work over plain HTTP.
- **Copies `sp.key` to the Harbor node as a `0600` file over SSH** (never on a command line).
- **Starts the console with real SAML in production mode** (`-environment production`) instead of the mock login.
- **Re-prints the exact Entity ID / ACS / metadata URLs** — confirm they match what you entered in Entra.

> Already have a running mock-login console and just want to flip it? See the Appendix for the
> equivalent `harbor admin-api` flags (restart just the console process — no need to re-do genesis).

---

## Test it (do this before you rely on it)

1. **Harbor advertises itself:** from a mesh member, `curl -sk https://<mesh_name>-harbor.<mesh_domain>/admin/v1/auth/saml/metadata` returns XML (the SP metadata). If this fails, your HTTPS/cert or networking is the problem, not SAML.
2. **Admin login works:** browse `https://<mesh_name>-harbor.<mesh_domain>/` → you're redirected to Microsoft → sign in as a member of the **admin** group → you land in the console **as an admin**. The login shows up in the audit log.
3. **Fail-closed check:** sign in as someone **not** in any mapped group → you land as **viewer** only (no admin buttons). This proves the role map is locked down.

## If it breaks — common causes (in order of likelihood)

- **Everyone lands as `viewer`, even admins.** The role map didn't match. Check: (a) the GUIDs in `SAML_ROLE_MAP` are the **Object IDs** of the assigned groups, (b) you used **`;`** between groups (not `,`), (c) the group claim is actually being emitted (Part A step 4).
- **Login loops / cookie errors.** You're not on HTTPS, or the URL the browser uses doesn't match the ACS you registered (host **and** port must match exactly — the console defaults to 443, so the URLs have no port).
- **`admin-api: SAML SP key must be RSA` at startup.** You generated an EC key. Re-make it with `-newkey rsa:2048` (B.1).
- **Microsoft says the Reply URL/Identifier doesn't match.** A character or the port differs between Entra and the values the bootstrap printed. Make them identical.
- **Browser can't reach the console at all.** You're not on the mesh, or the Harbor name doesn't resolve to its overlay IP from your machine.

## Break-glass

Keep a non-interactive **bearer admin token** (minted out-of-band) so you can still administer or
roll back if SSO breaks. **Do not** try to re-enable the mock login in production — `-environment
production` refuses it. Verify SSO end-to-end **before** you throw away the break-glass path.

---

## Appendix — the raw `harbor admin-api` flags (reference / flip an existing console)

The bootstrap builds this for you; shown here so you can see what it runs, or restart just the
console process to switch an already-running deployment to SAML without re-running genesis:

```bash
harbor admin-api \
  -dsn "$DSN" -ca-cert <genesis>/ca.crt -backend kms -kms-ca-key-id <arn> -kms-config-key-id <arn> \
  -addr <harbor-overlay>:443 \
  -base-url https://<mesh_name>-harbor.<mesh_domain> \
  -environment production \
  -saml-idp-metadata-url "<App Federation Metadata Url>" \
  -saml-sp-cert /home/<user>/ncp/saml/sp.crt -saml-sp-key /home/<user>/ncp/saml/sp.key \
  -saml-groups-attr "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups" \
  -role-map "11111111-...=admin;66666666-...=operator"
```

- Drop `-mock-idp`/`-mock-idp-addr` entirely (they conflict with real SAML, and production refuses them).
- **Port 443 is privileged** and admin-api runs **non-root**, so the unit needs `CAP_NET_BIND_SERVICE` (e.g. `systemd-run -p AmbientCapabilities=CAP_NET_BIND_SERVICE …`). The bootstrap adds this automatically; if you launch by hand on 443, grant it or the bind fails.
- `-base-url` has **no port** because 443 is the HTTPS default — keep it port-less so the SP's advertised Entity ID/ACS match what you registered in Entra. (Override `ADMIN_PORT`/`-addr` to a non-443 port only if you must, and then put `:<port>` back on `-base-url`.)
- `-saml-entity-id` is optional; omit it to default to `<base-url>/admin/v1/auth/saml/metadata`.
- The `;` in `-role-map` separates groups; a `,` would (wrongly) be read as multiple roles for one group.

## Notes

- **No Harbor code change** — configuration only. (The IdP code follow-ups in ADR 0007 — scheduling `SessionStore.GC` and OIDC-client-secret-from-file — don't affect SAML.)
- **Sessions live server-side in the database** (Aurora), so logins survive an admin-api instance loss and HA replicas need no sticky sessions.
- **Not yet live-validated (updated 2026-06-18):** the rest of the production deploy *is* live and exercised on real AWS (the poc is the prod stack — Aurora + KMS + ACME edge TLS + Fargate gateway/lighthouse + SSM-only access; the console is already served with `-tags ui` on :443). What remains is the **console Entra SAML round-trip specifically** — the live console still runs the dev mock-IdP, so an operator must create the Entra Enterprise App, generate the SP keypair, and re-run genesis with the `SAML_*` vars set. Expect to debug the first attempt with the checklist above.
