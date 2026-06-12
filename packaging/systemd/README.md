# Pilot systemd packaging (M1.9)

Runs `pilot` as a hardened systemd service that supervises `nebula`, under a
dedicated least-privilege account holding **only `CAP_NET_ADMIN`** — the single
capability nebula needs to create and configure its TUN device.

## Files

| File | Purpose |
|------|---------|
| `pilot.service` | The unit. Type=exec, `User=nebula-pilot`, ambient `CAP_NET_ADMIN`, full sandbox (ProtectSystem=strict, locked-down syscalls/devices). |
| `install.sh` | Root installer: creates the service user, installs binaries to `/usr/local/bin`, lays out `/etc/nebula-control-plane` (0700), runs `pilot init`, installs + enables the unit. |
| `uninstall.sh` | Removes the unit/binary; `--purge` also drops the config dir + user. |
| `values.example.yml` | Sample policy values for `pilot init` (copy to `/etc/nebula-control-plane/values.yml`). |

## Install

```bash
sudo packaging/systemd/install.sh
# place ca.crt + a signed host.crt in /etc/nebula-control-plane (see below)
sudo systemctl start pilot
journalctl -u pilot -f
```

`install.sh` generates the host key and renders `config.yml`, but a node can't
join until it has a CA bundle and a **signed** certificate. Until enrollment
(M3) exists, sign the generated `host.pub` by hand:

```bash
cd /etc/nebula-control-plane
sudo nebula-cert sign -ca-crt ca.crt -ca-key /path/to/ca.key \
  -in-pub host.pub -name "$(hostname)" -networks 100.64.0.5/16 -out-crt host.crt
sudo chown nebula-pilot:nebula-pilot ca.crt host.crt
```

## Capability model

- `AmbientCapabilities=CAP_NET_ADMIN` — granted to Pilot and **inherited by the
  nebula child** (ambient caps survive `execve`), so nebula can open
  `/dev/net/tun` and set routes without being root.
- `CapabilityBoundingSet=CAP_NET_ADMIN` — hard ceiling: nothing in the tree can
  hold any other capability, even if a binary is setuid/has file caps.
- `NoNewPrivileges=yes` — no privilege escalation past this point.
- `DevicePolicy=closed` + `DeviceAllow=/dev/net/tun rw` — only the TUN device is
  exposed; the rest of `/dev` is hidden (standard pseudo-devices aside).

## Reload

`systemctl reload pilot` sends SIGHUP, which Pilot turns into a nebula in-place
hot-reload of firewall / lighthouse / PKI (M1.8) — no tunnel drop.

## Acceptance (run on a VM)

The M1.9 *Done when* — "`systemctl start pilot` brings up the mesh node; no
extra capabilities granted" — must be checked on a real host/VM with root:

```bash
# starts and stays up (with ca.crt + host.crt in place)
systemctl start pilot && systemctl is-active pilot

# the nebula child holds exactly CAP_NET_ADMIN and nothing else:
pid=$(systemctl show -p MainPID --value pilot)
neb=$(pgrep -P "$pid" nebula)
grep Cap /proc/$neb/status         # CapEff should decode to cap_net_admin only
capsh --decode=$(awk '/CapEff/{print $2}' /proc/$neb/status)

# reload doesn't restart:
before=$(pgrep -P "$pid" nebula); systemctl reload pilot
sleep 1; [ "$before" = "$(pgrep -P "$pid" nebula)" ] && echo "reloaded, no restart"
```

## Notes / tuning

- `MemoryDenyWriteExecute=yes` is included for defense-in-depth. The Go runtime
  is normally compatible; if a future nebula/pilot build trips it, drop this one
  line and re-test.
- Verify the unit offline (no install) with `make systemd-verify`.
