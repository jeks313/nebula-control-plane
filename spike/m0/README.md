# M0 — Spike (local feasibility)

Throwaway harness that proves the foundations on this Linux box, **no cloud, no containers** —
just `nebula` processes in network namespaces, with **SoftHSM** standing in for the AWS KMS CA.

Maps to implementation-plan steps **M0.1, M0.2, M0.3, M0.5, M0.6** (and exercises the
`100.64.0.0/16` overlay so nothing collides with k3s `10.42/10.43`).

## What it proves

| Step | Question | How |
|------|----------|-----|
| M0.1 | Can we mint Nebula certs? | `30-gen-certs.sh` (local CA) |
| M0.2 | Does an overlay tunnel form? | `40-netns-up.sh` + `50-test.sh` (n1→n2 ping) |
| **M0.3** | **Can a CA key that never leaves a hardware module sign certs that work?** | `20-softhsm-ca.sh` + `10-build-...` + `31-gen-certs-hsm.sh` — **the make-or-break test** |
| M0.5 | Is the blocklist enforced peer-side? | `50-test.sh` blocks n2's fingerprint on n1 |
| M0.6 | Do cert groups gate the firewall? | n2 admits only group `a`; n1 is group `a` |

## Topology

```
            bridge nbr0 (underlay 192.168.77.0/24)
   ┌───────────────┬───────────────┬───────────────┐
 netns m0-lh     netns m0-n1     netns m0-n2
 192.168.77.1    .11             .12          (underlay)
 lighthouse      group a         group b      (nebula)
 100.64.0.1      100.64.0.11     100.64.0.12  (overlay)
```

## Run it

```bash
make m0-prereqs          # checks tooling; prints the pacman/paru install line
# install what it asks for, then the simple path:
make m0-up               # [sudo] bridge + 3 netns + nebula (local CA)
make m0-test             # [sudo] tunnel + blocklist + group checks
make m0-down             # [sudo] teardown

# the feasibility test (HSM-backed CA):
make m0-build            # build pkcs11-enabled nebula-cert from source
make m0-hsm              # SoftHSM P256 CA -> HSM-signed certs into run/
make m0-up && make m0-test   # [sudo] same lab, now on HSM-signed certs
```

## Notes / known rough edges (this is a spike)

- **PKCS#11 needs P256 / cert v2** — the HSM path uses `-curve P256`. The exact `-pkcs11`
  URI syntax (`31-gen-certs-hsm.sh`) is the thing M0.3 exists to pin down; check
  `tools/nebula-cert ca -h`.
- Scripts haven't been run end-to-end yet (toolchain not installed at authoring time) —
  expect to iterate on first run. Fingerprint parsing in `50-test.sh` assumes
  `nebula-cert print -json`; adjust if your version differs.
- `run/` and `tools/` are gitignored (generated certs, keys, SoftHSM token, built binaries).
- Everything is local and disposable: `make m0-down` then `rm -rf spike/m0/run spike/m0/tools`.
```
