---
title: "Runbook — Entra ID (Azure AD) SAML SSO for the Harbor Console"
created: 2026-06-14
status: active
tags: [nebula, runbook, saml, entra-id, azure-ad, sso, idp, adminauth, production]
---

# Runbook — Entra ID (Azure AD) SAML SSO for the Harbor Console

Companion to **ADR 0007 (Production Deploy)**. Wires the Harbor admin console to **Microsoft
Entra ID (Azure AD)** as the SSO IdP over **SAML 2.0**, replacing the dev mock-IdP.

**No Harbor code is required.** `internal/adminauth` already implements a SAML 2.0 Service
Provider (signed assertions, RelayState/InResponseTo binding, ForceAuthn step-up, SP
metadata, group-claim → RBAC). This runbook is **configuration only**: register Harbor in
Entra (Part A), then point Harbor's existing `-saml-*` flags at it (Part B).

The two halves share three values — keep them consistent:

| Value | Where it's set | Convention |
|---|---|---|
| **Base URL** | Harbor `-base-url` | `https://<console-host>` (the prod ALB/console origin) |
| **ACS / Reply URL** | Entra "Reply URL" | `<base-url>/admin/v1/auth/saml/acs` |
| **Entity ID (Identifier)** | Entra "Identifier" **and** Harbor `-saml-entity-id` | `<base-url>/admin/v1/auth/saml/metadata` (or a URN like `urn:nebula:harbor`) |
| **SP metadata** (for reference/import) | Harbor serves it | `<base-url>/admin/v1/auth/saml/metadata` |
| **Groups claim name** | Entra claim name **and** Harbor `-saml-groups-attr` | `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` |

## Prerequisites

- The Harbor **admin-api** reachable at a stable **HTTPS** origin (the prod ALB/console
  host; SSO requires `https` + `-environment production` for Secure cookies).
- An Entra tenant with rights to create an **Enterprise Application** (Application
  Administrator / Cloud Application Administrator).
- An Entra **security group** for Harbor admins (and optionally operators/viewers). Note
  each group's **Object ID** (GUID).
- A **stable SP signing keypair** for Harbor (Part B) — don't rely on the ephemeral one.

---

## Part A — Entra ID (Azure AD) side

1. **Create the app.** Entra admin center → **Identity → Applications → Enterprise
   applications → New application → Create your own application** → name it (e.g.
   `Nebula Harbor Console`) → **"Integrate any other application you don't find in the
   gallery (Non-gallery)"** → Create.

2. **Start SAML SSO.** Open the app → **Single sign-on → SAML**.

3. **Basic SAML Configuration** (edit):
   - **Identifier (Entity ID):** the agreed Entity ID — e.g. `https://<console-host>/admin/v1/auth/saml/metadata` (must equal Harbor's `-saml-entity-id`).
   - **Reply URL (Assertion Consumer Service URL):** `https://<console-host>/admin/v1/auth/saml/acs`.
   - **Sign on URL** (optional; Harbor is SP-initiated): `https://<console-host>/` is fine.
   - Save.

4. **Attributes & Claims** (edit) — add the **group claim**:
   - **Add a group claim** → **Security groups** (or *Groups assigned to the application*
     to keep the assertion small) → **Source attribute: Group ID** (the object GUID —
     always present; group *names* require AD-synced groups).
   - Note the resulting claim name: `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`
     — this must match Harbor's `-saml-groups-attr`.
   - (Keep the default NameID / unique user identifier, e.g. `user.userprincipalname`.)

5. **SAML Certificates** — grab the IdP metadata for Harbor:
   - Preferred: copy the **App Federation Metadata Url** → Harbor `-saml-idp-metadata-url`
     (Harbor fetches + refreshes it).
   - Or **Download Federation Metadata XML** → Harbor `-saml-idp-metadata-file`.

6. **Assign users/groups.** App → **Users and groups → Add user/group** → assign the
   **admin** security group (+ any operator/viewer groups). Only assigned principals can log in.

> Record for Part B: the **Federation Metadata Url**, the **admin group Object ID(s)**, and
> confirm the **Entity ID** + **ACS URL** exactly match what Harbor will advertise.

---

## Part B — Harbor side

Harbor's SAML SP is built in; you supply the IdP metadata, a stable SP keypair, the
group-claim name, and a role map — then drop the mock-IdP.

1. **Mint a stable SP keypair** (used to sign AuthnRequests / SP metadata). If you omit
   `-saml-sp-cert`/`-saml-sp-key`, Harbor generates an **ephemeral** keypair and warns —
   not acceptable for prod (it changes every restart). Custody these in Secrets Manager /
   KMS (per ADR 0007).
   ```bash
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
     -keyout sp.key -out sp.crt -days 825 -subj "/CN=nebula-harbor-sp"
   ```

2. **Run admin-api with the SAML flags** (replacing `-mock-idp …`):
   ```bash
   harbor admin-api \
     -dsn "$AURORA_DSN" -driver postgres \
     -ca-... / -kms-... (per ADR 0007) -config-key ... \
     -addr <harbor-overlay>:8445 \
     -base-url https://<console-host> \
     -environment production \
     -saml-idp-metadata-url "<App Federation Metadata Url from Part A step 5>" \
     -saml-entity-id "https://<console-host>/admin/v1/auth/saml/metadata" \
     -saml-sp-cert /etc/harbor/sp.crt -saml-sp-key /etc/harbor/sp.key \
     -saml-groups-attr "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups" \
     -role-map "<admin-group-objectid>=admin,<ops-group-objectid>=operator"
   ```
   - **Drop** `-mock-idp` / `-mock-idp-addr`. `-environment production` enables Secure
     cookies and the fail-closed guards (a stray mock-IdP in production is refused).
   - `-saml-entity-id` **must equal** the Entra "Identifier".
   - `-saml-groups-attr` **must equal** the Entra group-claim name.

3. **The role map** (`-role-map`) — the **keys are whatever the groups claim emits.** With
   the default Entra "Group ID" source, the keys are **group Object IDs (GUIDs)**:
   ```
   -role-map "11111111-2222-3333-4444-555555555555=admin,66666666-...=operator"
   ```
   Mapping is **fail-closed**: unmapped groups grant nothing; everyone authenticated gets
   the universal `viewer` default only. (If you'd rather map by group *name*, configure
   Entra to emit `sAMAccountName` for synced groups and use names as the keys.)
   **Pin at least one group to `admin`** or no one can administer the console.

4. **Secrets handling (prod).** The SAML SP key is a file (`-saml-sp-key`) — inject it from
   Secrets Manager at boot (like the Fargate runtime secrets). *(OIDC/GitHub client secrets
   are argv today; SAML uses key files, so SAML avoids that exposure — see ADR 0007.)*

---

## Verify (before cutover) + break-glass

1. **SP metadata reachable:** `curl https://<console-host>/admin/v1/auth/saml/metadata`
   returns the SP metadata (entity ID + ACS + the SP cert).
2. **Admin login:** browse `https://<console-host>/` → redirected to Entra → sign in as an
   **admin-group** member → land in the console **with the admin role**. Confirm the login
   appears in the audit log.
3. **Fail-closed check:** a user **not** in any mapped group lands as **viewer** only (no
   admin surface) — confirms the role map is fail-closed.
4. **Step-up (optional):** privileged actions trigger `ForceAuthn` (the SP re-asserts) —
   confirm Entra re-prompts.

**Break-glass:** keep a non-interactive **bearer admin token** (minted out-of-band) so you
can administer / revert if SSO breaks. **Do not** re-enable `-mock-idp` in production (the
`-environment production` guard refuses it). Verify SSO end-to-end **before** removing the
break-glass path.

## Notes

- **No code change** — only configuration. (Net-new code in ADR 0007 for IdP is narrow:
  scheduling `SessionStore.GC` and OIDC client-secret-from-file; neither affects SAML.)
- **Sessions are server-side in the DB** — with Aurora (ADR 0007) they persist across HA
  admin-api replicas, so logins survive an instance loss and no sticky sessions are needed.
- **Group claim size:** if the admin group is large or users are in many groups, prefer
  *"Groups assigned to the application"* to keep the SAML assertion small.
