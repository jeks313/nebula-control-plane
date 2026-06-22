---
title: "Runbook — Windows pilot demo (join a Windows host to the mesh)"
created: 2026-06-22
status: active
tags: [nebula, runbook, windows, pilot, demo, scm, wintun, enrollment, full-os-demo]
---

# Runbook — Windows pilot demo (join a Windows host to the mesh)

End-to-end steps to bring a **Windows** host onto a Nebula mesh — overlay tunnel up, heartbeating
in the console — alongside the Linux and macOS members, for a full-OS demo.

The Windows pilot is the SCM-service backend (ADR 0008 Phase 4). What makes this work with **zero
host provisioning** is the *embedded* pilot: `pilot.exe` carries nebula + the Wintun driver and
materializes them on first run (ADR 0003 Phase 2) into the exact subtree nebula loads Wintun from.
A fresh box only needs `pilot.exe` + the config-signing pin.

The steps are the same on any mesh; only the per-mesh **values** differ. This runbook's primary
path joins the **live `poc` mesh** with an **off-cloud Windows host** — the Windows analogue of the
off-cloud iMac (join key + manual approval, via the public gateway). The Appendix covers the
ready-made EC2 test box, which belongs to a **separate** lab stack.

> **Demo readiness:** every step is code-verified; the one thing never exercised on real hardware is
> this exact runtime hop (a Windows host bringing the tunnel up). Treat the first run as the live
> validation — the Troubleshooting section covers the known Windows gotchas.

---

## What you need

- **A build host** (Linux/macOS) with `go`, `make`, `curl`, `unzip` + network — to build the
  embedded `pilot.exe` (it fetches the pinned nebula `.zip` + Wintun and embeds them).
- **A Windows host** with internet access to the public gateway (a laptop or VM — anything that can
  reach `poc-gateway.mesh.failsafe.net:8443`). It needs **Administrator** (the SCM install requires
  an elevated token).
- **The poc's values** (stable; the gateway/console are public DNS, harbor/lighthouse are overlay):
  - mesh id: `poc`
  - gateway (public enroll): `https://poc-gateway.mesh.failsafe.net:8443`
  - Core API (over the mesh): `https://poc-harbor.mesh.failsafe.net:8444`
  - config-signing pin: from the operator, or the artifact bucket
    `https://ncp-artifacts-308040853462.s3.ca-central-1.amazonaws.com/config-signing.pub`
  - overlay IPs to ping once up: lighthouse `10.44.0.1`, harbor `10.44.0.2`

---

## 1. Build the embedded Windows pilot (on the build host)

```bash
make pilot-embedded NEBULA_OS=windows NEBULA_ARCH=amd64
file bin/pilot.exe    # -> PE32+ executable for MS Windows, x86-64
```

`bin/pilot.exe` now embeds nebula + Wintun (`-tags embed_nebula`). On first `supervise` it writes
`C:\Program Files\Nebula\nebula.exe` and `C:\Program Files\Nebula\dist\windows\wintun\bin\amd64\wintun.dll`
— the path nebula's `checkWinTunExists()` loads from.

---

## 2. Get `pilot.exe` + the pin onto the Windows host

Copy both to the host (any transport). Grab the pin from the bucket, or from the operator's
`deploy/prod/terraform/app/config-signing.pub`:

```powershell
# On the Windows host (PowerShell):
curl.exe -fsSL https://ncp-artifacts-308040853462.s3.ca-central-1.amazonaws.com/config-signing.pub -o $env:USERPROFILE\config-signing.pub
# ...and copy pilot.exe into the profile dir too (scp from the build host, a share, etc.).
```

---

## 3. Mint a join key (on harbor)

An off-cloud host has no IAM role, so it enrolls with a **join key + manual approval** (the iMac
path). On the harbor control-plane host, with this mesh's DB flags (see the publishing runbook):

```bash
harbor joinkey create -name win-demo -groups laptops <DB FLAGS>   # prints njk_...
```

---

## 4. Install + enroll (in an **elevated** PowerShell on the Windows host)

`pilot install` does it all: NTP clock-check → enroll → write the signed config + pin → create a
per-mesh auto-start SCM service (LocalSystem) → start it. On first start the service runs
`pilot supervise`, which materializes nebula.exe + wintun.dll and brings up the overlay.

```powershell
.\pilot.exe install -mesh poc `
  -gateway "https://poc-gateway.mesh.failsafe.net:8443" `
  -core    "https://poc-harbor.mesh.failsafe.net:8444" `
  -config-pub "$env:USERPROFILE\config-signing.pub" `
  -join-key "njk_..." `
  -name win-demo
```

Then **approve** the pending enrollment in the admin console (or `harbor enroll approve <id>` with
the DB flags). The supervisor polls and brings the tunnel up once the cert is issued.

> Tip: `.\pilot.exe install … -dry-run` previews the resolved paths + the exact service definition
> without enrolling or touching the SCM.

---

## 5. Verify (the demo "done when")

In the elevated PowerShell on the Windows host:

```powershell
.\pilot.exe status -mesh poc          # -> running

# Both binaries self-staged where nebula needs them:
Test-Path 'C:\Program Files\Nebula\nebula.exe'                                   # True
Test-Path 'C:\Program Files\Nebula\dist\windows\wintun\bin\amd64\wintun.dll'     # True

# Tail the service log (a service has no console; pilot redirects here):
Get-Content -Wait 'C:\ProgramData\NebulaControlPlane\pilot\poc\pilot.log'

# Overlay is up — reach the control plane over the mesh:
ping 10.44.0.1      # lighthouse
ping 10.44.0.2      # harbor
```

Then, in the **admin console** fleet view: the Windows host appears and is **heartbeating**,
alongside the Linux and macOS members. That's the full-OS demo.

---

## Troubleshooting (the known Windows gotchas)

- **`connect to the service manager (run from an elevated/Administrator prompt)`** → the shell isn't
  elevated. "Run as administrator" (an SSH-as-Administrator session is already elevated).
- **`clock skew … exceeds max`** → identity ops are clock-sensitive (fail-closed). Fix the clock, or
  `-skip-clock-check` on an airgapped host.
- **`can not load the wintun driver`** → wintun.dll isn't at
  `C:\Program Files\Nebula\dist\windows\wintun\bin\<arch>\wintun.dll`. The embedded pilot puts it
  there automatically; only happens if you passed your own `-nebula` without staging Wintun in that
  subtree.
- **`-core` unreachable / no heartbeat** → `poc-harbor.mesh.failsafe.net` must resolve to harbor's
  overlay IP (`10.44.0.2`) once the tunnel is up (the signed bundle / a hosts entry handles this).
  Fallback: `-core https://10.44.0.2:8444`.
- **AV / SmartScreen blocks nebula.exe or wintun.dll** → Authenticode signing is parked (M10), so the
  materialized binaries are unsigned. On a locked-down host, add an exclusion / unblock the files.
- **A pushed update doesn't reach the host** → pilot self-update **no-ops on Windows** by design;
  install at the pinned nebula/pilot version (rebuild + re-`install` to change versions).

---

## Teardown

```powershell
# On the host: stop + remove the service (add -purge to also wipe the per-mesh state dir):
.\pilot.exe uninstall -mesh poc
```

On harbor (optional): revoke the device, or let the reaper reclaim it (with the DB flags).

---

## Appendix — the ready-made EC2 test box (separate lab stack)

`deploy/terraform/windows.tf` provisions a Windows Server 2022 box purpose-built to exercise the
SCM/embed mechanics. **It belongs to the `deploy/terraform/` "Minimal AWS lab" stack — its own
self-contained mesh, NOT the `poc`** (`deploy/prod/`). Use it to dry-run the pilot mechanics on a
clean EC2 box; its enroll values come from the **lab** stack, not the poc.

```bash
# Bring up just the box + its VPC deps (lab stack):
terraform -chdir=deploy/terraform apply -var enable_windows_client=true -target=aws_instance.windows

# Public IP + the ready-made ssh line (this box has a PUBLIC IP + OpenSSH — DIRECT ssh as
# Administrator with your ed25519 key; NOT SSM like the prod Linux nodes):
terraform -chdir=deploy/terraform output windows_ssh        # -> ssh Administrator@<ip>
WIN_IP=$(terraform -chdir=deploy/terraform output -raw windows_client_ip)
scp -i ~/.ssh/absolute bin/pilot.exe Administrator@$WIN_IP:'C:/Users/Administrator/pilot.exe'
ssh -i ~/.ssh/absolute Administrator@$WIN_IP
```

It carries the lab node's IAM instance profile, so it enrolls **keyless via `-aws-sigv4`** (no join
key, no manual approval — cloud-trust auto-issues) against the lab's **in-VPC** gateway URL:

```powershell
.\pilot.exe install -mesh <lab-mesh-id> `
  -gateway "<the lab's enroll(in-VPC) URL>" `
  -core    "<the lab's Core URL>" `
  -config-pub "C:\Users\Administrator\config-signing.pub" `
  -aws-sigv4 -region ca-central-1 `
  -name win-lab
```

(Read the lab's gateway/Core URLs + pin from its `terraform -chdir=deploy/terraform output` / its
genesis summary.) Teardown: `terraform -chdir=deploy/terraform destroy -target=aws_instance.windows`.

> To put a Windows host **on the poc** itself (rather than the lab), either run the off-cloud path
> above on any internet-reachable Windows box, or add an equivalent `windows.tf` client to the prod
> app stack (`deploy/prod/terraform/app`) — it has no Windows client today. The pilot steps are
> identical; only the stack + values change.

---

## See also

- **ADR 0008 — Client Install & Bootstrap** — the `pilot install` design + the SCM service backend.
- **Genesis Runbook** — stands up the mesh + prints the gateway URLs / pin this runbook consumes.
- **Runbook — Publishing pilot and nebula releases** — building/publishing the embedded Windows
  pilot + the Wintun companion artifact.
