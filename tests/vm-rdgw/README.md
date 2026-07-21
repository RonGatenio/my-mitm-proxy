# RD Gateway manual bring-up (Hyper-V)

A **manual, interactive** test (not an automated harness): drive `mstsc` from this
Windows host, through the `mymitm` proxy on a Debian/kernel-5.10 VM, to a real
Microsoft **Remote Desktop Gateway** on a Windows Server VM. Then inspect the
proxy's decrypted dump to confirm RDP works through the proxy and to read the
NTLM **challenge + computername** out of the server→client stream.

## Topology

```
 this Windows host                 B  (Debian 11, kernel 5.10)             GW (Windows Server 2025)
 ┌────────────────┐   rdgw-left    ┌───────────────────────────┐  rdgw-right ┌────────────────────────┐
 │ mstsc (client) │───10.20.1.0/24─│ mymitm transparent proxy  │─10.20.2.0/24│ RD Gateway role        │
 │ vEth 10.20.1.5 │                │ left0 .1.1   right0 .2.1  │             │ + RDP session host     │
 │ route .2.0/24  │                │ terminates TLS w/ GW cert │             │ .2.10  gw.rdgw.test    │
 │   via .1.1     │                │ dumps .c2s/.s2c           │             │ workgroup, Administrator│
 └────────────────┘                └───────────────────────────┘             └────────────────────────┘
```

| Node | Interface | IP | Notes |
|------|-----------|----|-------|
| Host | vEthernet (rdgw-left) | 10.20.1.5/24 | + route `10.20.2.0/24 → 10.20.1.1` |
| B    | left0  (rdgw-left)    | 10.20.1.1/24 | host's next hop; `mymitm` `local_addr` (eBPF) |
| B    | right0 (rdgw-right)   | 10.20.2.1/24 | egress toward GW; GW's default gateway |
| GW   | gw0 (rdgw-right)      | 10.20.2.10/24 | RD Gateway + RDP host; computer name `RDGW1` |

- Two **Internal** Hyper-V vSwitches: `rdgw-left` (host ↔ B), `rdgw-right` (B ↔ GW).
- Host `hosts`: `10.20.2.10  gw.rdgw.test`; `mstsc` gateway hostname = `gw.rdgw.test`
  so its TLS validates against the cert B presents (GW's real leaf).

## Why this shape

- `mymitm` is a transparent, src-IP-preserving L3/L4 interceptor — it must sit *in the
  path*, so B is a two-NIC router between the host and GW (mirrors `tests/vm`'s B).
- **Workgroup + local account + connect-by-IP/non-SPN name** forces gateway auth to fall
  back to **NTLM** (domain-join → Kerberos → no NTLMSSP challenge to capture).
- The proxy holds **GW's real leaf cert+key**, so it's transparent at the TLS layer; the
  tunneled RDP stays double-encrypted and opaque, but the gateway's outer-layer NTLM
  `CHALLENGE_MESSAGE` (with the computername `RDGW1`) is in the decrypted `.s2c`.

## Cert flow

Host generates a self-signed leaf for `gw.rdgw.test` (exportable) →
`.pfx` bound on GW as the RD Gateway SSL cert → same leaf split to `leaf.pem`+`leaf.key`
for `mymitm` on B → leaf trusted in the host's Root store so `mstsc` doesn't warn.

## Files

- `host-setup.ps1`  — **elevated, host**: switches, host vEth IP + route + hosts entry,
  self-signed cert (bound on GW, split to PEM for B, trusted here), creates B (VHDX +
  cloud-init seed) and GW (unattended from ISO). Idempotent.
- `autounattend.xml` — hands-off WS2025 install (Standard, Desktop Experience; computer
  name `RDGW1`; built-in **Administrator / 1311**).
- `gw-configure.ps1` — **host**: waits for GW, pushes the cert + `gw-provision.ps1`, runs
  it over PowerShell Direct (needs no network to GW yet).
- `gw-provision.ps1` — **inside GW**: static IP, RD Gateway role, bind cert, CAP/RAP
  (password/NTLM auth, any resource), enable RDP. Idempotent.
- `b-deploy.ps1`     — **host**: pushes the `mymitm` binary + cert to B over SSH, writes
  `mymitm.toml` from B's *actual* interface names, starts the proxy. Idempotent.
- `b-cloud-init/`    — B networking (left0/right0 by MAC), `admin`/`1311`, ip_forward, unit.
- `mymitm.toml`      — reference proxy config (b-deploy regenerates the effective one on B).

**Account note:** the gateway user is the built-in **Administrator / 1311**. An unattend-set
built-in password sidesteps Windows' complexity policy; creating a literal `admin` account
would need a policy-disable step first. (B's Linux login is `admin`/`1311`.)

## Run order

1. **[elevated host]** `.\host-setup.ps1` — switches, host route, cert, both VMs. GW then
   runs its ~15-20 min unattended install on its own.
2. **[elevated host]** `.\gw-configure.ps1` — waits for GW, then provisions the gateway.
3. **[host]** `.\b-deploy.ps1` — proxy live on B.
4. **[host]** `mstsc` → **Advanced ▸ Settings**: RD Gateway server name = `gw.rdgw.test`;
   **General**: computer = `10.20.2.10`; credentials = `Administrator` / `1311`.
5. **Inspect** on B:
   ```bash
   sudo ls -l /opt/mymitm/dumps
   sudo strings /opt/mymitm/dumps/*.s2c | grep -i -B2 -A2 -E 'ntlm|negotiate|www-authenticate'
   ```
   The NTLM CHALLENGE (raw `NTLMSSP\0` bytes, or base64 in a `WWW-Authenticate` header)
   carries the computername `RDGW1`. `mymitm/src/ntlm.rs::detect_challenge` parses this
   exact structure; wiring it into the live dump path is the follow-on.

## Teardown

```powershell
Stop-VM rdgw-B,rdgw-GW -TurnOff -Force -ErrorAction SilentlyContinue
Remove-VM rdgw-B,rdgw-GW -Force -ErrorAction SilentlyContinue
Remove-VMSwitch rdgw-left,rdgw-right -Force -ErrorAction SilentlyContinue
Get-NetRoute -DestinationPrefix 10.20.2.0/24 -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false
```
VM disks + ISOs live under `C:\Users\RonGatenio\rdgw-lab\` (outside the repo).

## Status

- [x] `mymitm` musl binary built
- [x] WS2025 eval ISO fetched + verified
- [x] Debian 11 → 16 GiB VHDX
- [x] scripts generated + statically validated (PS syntax, XML, YAML, TOML)
- [ ] elevated run (switches + VMs) — **needs your elevated session**
- [ ] GW provisioned
- [ ] proxy up on B, mstsc connects, dump inspected

## Caveats / likely iteration points

- **B interface rename**: Debian's cloud-init renderer may not honor `set-name` to
  left0/right0. `b-deploy.ps1` resolves the real names by MAC and writes the TOML to match,
  so this is handled — but if B has no IPs at all, cloud-init didn't apply the net config
  (check the VM console).
- **RDS provider**: `gw-provision.ps1` binds the cert + CAP/RAP via the `RDS:` PowerShell
  drive. If a cmdlet/param differs on WS2025, do it by hand in **RD Gateway Manager**.
- **eBPF vs iproute**: TOML defaults to `data_plane = "ebpf"` (fine on 5.10). If attach
  fails, re-run with the TOML set to `iproute`.
