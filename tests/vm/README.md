# VM test harness (kernel 4.15 / 5.10 / Debian 11, 3-machine source-IP validation)

Boots three QEMU/KVM VMs and proves `mymitmproxy` preserves the client's exact
source IP end-to-end on a **real old kernel** box — first as a plain router,
then with the proxy intercepting. Select what B (the router/proxy) runs
with via `--kernel {4.15,5.10,debian11}` (default `4.15`).

```
A (client, 10.10.1.10) ──br-left── B (router/proxy, kernel 4.15|5.10|debian11) ──br-right── C (HTTPS, 10.10.2.10)
                                    left0 .1.1     right0 .2.1
```

- **`--kernel 4.15`** — B is the *bionic* cloud image booted on its own distro
  kernel (4.15).
- **`--kernel 5.10`** — B is the *jammy* cloud image booted with an external
  vanilla **5.10** kernel from the [Cilium lvh](https://github.com/cilium/little-vm-helper)
  catalog (`5.10-main` → `5.10.260`). The lvh kernel has virtio/ext4 built in, so
  it boots the jammy rootfs with no initrd; its modules (the modular `clsact` /
  `sch_ingress` and iptables `mangle`/`mark` targets) are exported to the guest
  over a 9p share and installed at `up` time. A, C always run jammy.
- **`--kernel debian11`** — B is a stock **Debian 11 "bullseye"** genericcloud
  image on its **own native 5.10 kernel** (`5.10.0-*-cloud-amd64`, Debian's own
  build — no external kernel, no 9p). Distro-exact proof; because it's a full
  distro kernel (not the lean lvh test kernel) the `iproute` plane's netfilter tcp
  match is present, so **both** data planes run. Debian's image is fetched via
  `SHA512SUMS`, and B's data-leg names are resolved by MAC (Debian's cloud-init
  renderer may not honor netplan `set-name:`). A, C run jammy.

- **A** sends `curl https://C`; **C** logs the peer IP it sees.
- **Phase 1 (`router`)**: B just forwards — C must see `10.10.1.10`.
- **Phase 2 (`proxy`)**: B terminates TLS (decrypted bytes land in a dump) and
  re-originates to C preserving the src — C still sees `10.10.1.10`.

## Prerequisites

- WSL2 (or Linux) with **KVM**: `/dev/kvm` present and writable (`kvm-ok`). Without
  it QEMU falls back to slow TCG emulation but still runs.
- Packages: `qemu-system-x86`, `qemu-utils`, `cloud-image-utils` (for
  `cloud-localds`), `iproute2`, `openssl`, `curl`, `gettext-base` (for `envsubst`).

```bash
sudo apt-get update && sudo apt-get install -y \
  qemu-system-x86 qemu-utils cloud-image-utils iproute2 openssl curl gettext-base
```

- For `--kernel 5.10` only: the [`lvh`](https://github.com/cilium/little-vm-helper)
  binary on `PATH`. The harness runs `lvh kernels pull 5.10-main` once (cached
  under `.work/lvh/`) to fetch the vanilla 5.10 kernel + modules.
- **SSH key location:** the harness keeps its throwaway SSH key under
  `${MYMITM_VM_KEYDIR:-/tmp/mymitm-vm}`, *not* under `.work/`. An SSH private key
  must be mode `0600`; on a Windows drvfs mount (repo under `/mnt/c/...` in WSL)
  every file is `0777` and `chmod` is ignored, so OpenSSH would reject a key kept
  in the repo tree. Override the dir with `MYMITM_VM_KEYDIR` if `/tmp` is not a
  native filesystem for you.

## Run

All commands run as root (they create taps/bridges and use `/dev/kvm`):

```bash
# kernel 4.15 (default)
sudo bash tests/vm/run.sh all                                    # up -> router -> proxy -> down (eBPF)
sudo bash tests/vm/run.sh all --data-plane iproute               # same, iproute data plane

# kernel 5.10
sudo bash tests/vm/run.sh all --kernel 5.10                      # eBPF, kernel 5.10
sudo bash tests/vm/run.sh all --kernel 5.10 --data-plane iproute # iproute, kernel 5.10

# Debian 11 (native 5.10 distro kernel) — both planes run
sudo bash tests/vm/run.sh all --kernel debian11                      # eBPF, Debian 11
sudo bash tests/vm/run.sh all --kernel debian11 --data-plane iproute # iproute, Debian 11

# negative control: run the proxy with source-IP preservation OFF
# (preserve_src_ip = false / --preserve-src-ip=false). Phase 2 then asserts C sees
# the BOX IP (10.10.2.1), not the client (10.10.1.10) — proving the feature is
# what changes the source IP.
sudo bash tests/vm/run.sh all --kernel 5.10 --no-preserve
```

Step by step (leaves the VMs running between commands — pass the same
`--kernel` to each):

```bash
sudo bash tests/vm/run.sh up     --kernel 5.10   # images (first run), boot A/B/C, install 5.10 modules, server on C
sudo bash tests/vm/run.sh router --kernel 5.10   # phase 1 assertions
sudo bash tests/vm/run.sh proxy  --kernel 5.10   # phase 2 assertions (add --data-plane iproute to switch)
sudo bash tests/vm/run.sh down   --kernel 5.10   # tear everything down
```

Use `--keep` with `all` to skip the final teardown for debugging.

## Current status

All passing runs end with `ALL PHASES PASS` — source IP preserved at C in both
phases, and (phase 2) decrypted bytes visible in B's dump.

| kernel | `ebpf` (default) | `iproute` |
|--------|------------------|-----------|
| 4.15 (bionic distro kernel)          | **PASS** | **PASS** |
| 5.10 (lvh `5.10.260`, lean test krnl)| **PASS** | **SKIP** — test-kernel limit (see below) |
| Debian 11 (native `5.10.0-*-amd64`)  | **PASS** | **PASS** |

The **eBPF** plane — what the product ships by default — is validated end-to-end
on all three targets (4.15, lvh 5.10, and Debian 11's native 5.10). On 5.10 it
takes the `clsact+tc` path (TCX needs ≥ 6.6); the four `TCX attach unavailable`
lines are logged at DEBUG and are expected, not a fault.

The **iproute** plane passes on 4.15 and Debian 11, and is **skipped only on the
lvh 5.10 kernel**: that lean BPF-testing kernel is built without
`NETFILTER_XT_MATCH` (no `xt_tcpudp`), so the iptables `-p tcp --dport` match can't
load. The harness detects this and skips with a message — a limitation of the
*test kernel*, not the proxy. **Confirmed on `debian11`:** Debian's native
`5.10.0-45-cloud-amd64` ships `xt_tcpudp`, so the iproute plane runs and preserves
the client IP there — proving the SKIP is the lvh kernel, not kernel 5.10 itself.
(Debian genericcloud ships without the `iptables` binary — it defaults to
nftables — so the harness installs it on demand before the iproute phase.)

> **History — defects this harness surfaced:**
> 1. **4.15 BPF verifier** rejected the eBPF object (`math between pkt pointer and
>    register with unbounded min value`) because `meta()` derived the L3 offset at
>    runtime. Fixed by monomorphizing the parse on a compile-time L3 (`meta_at::<L3>`).
> 2. **`RLIMIT_MEMLOCK` on kernels < 5.11** — BPF memory is charged against memlock
>    there; under the default (~64 KiB inherited by a systemd unit) map creation fails
>    with `Operation not permitted`. The proxy now raises `RLIMIT_MEMLOCK` to infinity
>    at startup (`bpf.rs::raise_memlock_rlimit`), so no manual `ulimit` is needed.
> 3. **iptables-nft `--dport`** — Ubuntu jammy's iptables v1.8.7 (nft backend) rejects
>    `-p tcp -d X --dport Y` with `unknown option --dport`. The iproute ruleset now
>    loads the match explicitly with `-m tcp`, portable across the legacy and nft backends.

## Reading the result

Each assertion prints `PASS:`/`FAIL:`. A green `ALL PHASES PASS` banner means both
phases preserved the client IP at C and (phase 2) the proxy saw decrypted bytes.
On failure the harness dumps the relevant `journalctl -u mymitm` / server log.

The first `up` downloads the cloud image(s) into `tests/vm/.work/images/` (jammy
always; bionic for `--kernel 4.15`; the Debian 11 genericcloud qcow2 for
`--kernel debian11`) and, for `--kernel 5.10`, the lvh kernel into
`tests/vm/.work/lvh/`; all are cached and reused. Everything the harness writes
lives under `tests/vm/.work/` (git-ignored).

## Troubleshooting

- **`no /dev/kvm: TCG fallback`** — nested virtualization isn't available; the run
  still works but boots slowly. On Windows, ensure nested virt is enabled for the
  WSL2 utility VM.
- **A VM never becomes SSH-reachable** — inspect its serial console at
  `tests/vm/.work/<A|B|C>.serial.log`.
- **Image download/checksum failure** — delete `tests/vm/.work/images/` and re-run
  `up`; the URLs track the maintained `current` cloud images.
- **Traffic dropped between VMs on a Docker/WSL2 host** — the harness inserts
  per-bridge `iptables FORWARD ACCEPT` rules in `up` and removes them in `down`;
  if a previous run was killed mid-way, `down` is idempotent and cleans them.
