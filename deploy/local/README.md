# Local single-instance deploy (personal / dogfooding)

The whole Nebula control plane on **one box, maximally simplified** — for personal
use and real-world dogfooding:

- everything on **localhost**; **SQLite**; a **software CA** (no HSM)
- **co-located** enrollment: the gateway + the enroll worker share one local queue
  (the simple model — *not* the ADR-0005 off-mesh pull split, which is for the
  multi-host AWS deploy in `../terraform`)
- the admin **console logs in with your GitHub account** (OAuth)
- device **joins are GitHub-gated**: you mint a join key and **approve the device in
  the GitHub-authenticated console** (or use an auto-issue key for a one-step join)

You can enroll devices and drive the console **without a mesh** — the data-plane
tunnel (`nebula`) is an optional add-on (see *Add the mesh* below).

## Prereqs

`go`, `curl`, `openssl`. **`node`/`npm`** too if you want the React console (without
them you still get an API-only console — a "not built" page at `/` — and can approve
via the CLI). The mesh add-on needs `nebula` + `CAP_NET_ADMIN`/sudo.

## 1. A GitHub OAuth app (for the console login)

GitHub → **Settings → Developer settings → OAuth Apps → New OAuth App**:

| Field | Value |
|-------|-------|
| Application name | anything, e.g. `nebula-harbor-local` |
| Homepage URL | `http://localhost:8445` |
| Authorization callback URL | `http://localhost:8445/admin/v1/auth/callback` |

Copy the **Client ID** and generate a **Client secret**, then:

```bash
export NCP_GITHUB_CLIENT_ID=Iv1.xxxxxxxx
export NCP_GITHUB_CLIENT_SECRET=xxxxxxxxxxxxxxxx
```

*(Skip this and the deploy falls back to a built-in dev mock-IdP so you can try
everything without a GitHub app.)*

## 2. Bring it up

```bash
deploy/local/local-up.sh
```

It builds the binaries (with the console UI if `npm` is present), runs genesis (CA +
config-signing key), starts the gateway + enroll worker + admin console, mints two
join keys, and prints the console URL, the gateway URL, the config-signing **pin**,
and the exact enroll commands. State lives in `~/.ncp-local` (override with
`NCP_LOCAL_DIR`); a restart reuses the same genesis.

Open the console at **http://127.0.0.1:8445** and log in with GitHub. You are the
admin (see the security note).

## 3. Join a device — GitHub-gated approval

```bash
# device side (this box, or any machine that can reach the gateway):
pilot enroll -dir ~/.nebula -gateway http://<gateway-host>:8443 \
  -join-key <key from the local-up output> -config-pub <run-dir>/G/config-signing.pub -name my-laptop
# -> lands PENDING. In the console (logged in via GitHub) open the approvals queue,
#    approve it, then re-run the same enroll to fetch the issued cert + config.
```

GitHub is the **admission authority**: only someone logged in as you (in the console)
can approve a join. The auto-issue key the script prints skips approval for a
one-step join when you don't want the gate.

## Stop / reset

```bash
deploy/local/local-down.sh           # stop services, keep state (genesis/DB)
deploy/local/local-down.sh --purge   # stop AND delete the run dir
```

## Knobs (env vars)

| Var | Default | Meaning |
|-----|---------|---------|
| `NCP_GITHUB_CLIENT_ID` / `_SECRET` | — | GitHub OAuth app (else dev mock-IdP) |
| `NCP_BIND` | `127.0.0.1` | gateway bind — set to a LAN IP so other devices can enroll |
| `NCP_GW_PORT` / `NCP_ADMIN_PORT` / `NCP_MOCK_IDP_PORT` | 8443 / 8445 / 8446 | ports (change on a clash) |
| `NCP_LOCAL_DIR` | `~/.ncp-local` | state dir |

## Security note

The **console is bound to `127.0.0.1`** and grants admin to any GitHub login that
reaches it (`-default-roles admin`) — which is safe precisely *because* it's
local-only. The **gateway** can face your LAN (`NCP_BIND`) so other devices enroll,
but the **console stays local**. If you ever expose the console off-box, put it
behind TLS/a tunnel and restrict admins via `-role-map "<your-org>=admin"` (GitHub
org/team) instead of `-default-roles admin`; a bare personal account with no org
should keep the console local. This mirrors the production stance — the admin plane
is never a casually-exposed surface.

## Add the mesh (optional — real tunnels)

`local-up` runs the **control plane** (issue certs + config, approve joins); it does
not start `nebula`. To actually tunnel between joined devices, run `nebula` on each
(this box as a lighthouse + control-plane node, devices as members) using the issued
cert + rendered config — see `../../packaging/systemd/` (a hardened `pilot.service`
that supervises `nebula`) and `docs/Nebula Control Plane - Genesis Runbook.md`. For a
multi-host, off-mesh-gateway topology on AWS, use `../terraform` + `../scripts/bootstrap-genesis.sh`.
