# VM test harness (kernel 4.15, 3-machine source-IP validation)

Boots three QEMU/KVM VMs and proves `mymitmproxy` preserves the client's exact
source IP end-to-end on a **real kernel 4.15** box — first as a plain router,
then with the proxy intercepting.

```
A (client, 10.10.1.10) ──br-left── B (router/proxy, kernel 4.15) ──br-right── C (HTTPS, 10.10.2.10)
                                    left0 .1.1     right0 .2.1
```

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

## Run

All commands run as root (they create taps/bridges and use `/dev/kvm`):

```bash
sudo bash tests/vm/run.sh all                      # up -> router -> proxy -> down (eBPF)
sudo bash tests/vm/run.sh all --data-plane iproute # same, iproute data plane
```

Step by step (leaves the VMs running between commands):

```bash
sudo bash tests/vm/run.sh up        # download images (first run), boot A/B/C, start server on C
sudo bash tests/vm/run.sh router    # phase 1 assertions
sudo bash tests/vm/run.sh proxy     # phase 2 assertions (add --data-plane iproute to switch)
sudo bash tests/vm/run.sh down      # tear everything down
```

Use `--keep` with `all` to skip the final teardown for debugging.

## Current status on kernel 4.15

Both data planes pass all phase-1 and phase-2 assertions on kernel 4.15
(source IP preserved at C, decrypted bytes visible on B):

- **`ebpf` data plane (default) — passes.** `sudo bash tests/vm/run.sh all` ends with
  `ALL PHASES PASS (data_plane=ebpf)`.
- **`iproute` data plane — passes.** `sudo bash tests/vm/run.sh all --data-plane iproute`.

> **History:** the eBPF plane originally failed to load on the 4.15 BPF verifier
> (`math between pkt pointer and register with unbounded min value is not allowed`),
> because `mymitm-ebpf/src/main.rs::meta()` derived the L3 offset at runtime and used
> it in packet-pointer arithmetic. The fix monomorphizes the header parse on a
> compile-time-constant L3 offset (`meta_at::<L3>`), so the verifier can bound it. This
> harness is what surfaced that defect — the 4.19 verifier accepted the original form.

## Reading the result

Each assertion prints `PASS:`/`FAIL:`. A green `ALL PHASES PASS` banner means both
phases preserved the client IP at C and (phase 2) the proxy saw decrypted bytes.
On failure the harness dumps the relevant `journalctl -u mymitm` / server log.

The first `up` downloads two Ubuntu cloud images (~1 GB total) into
`tests/vm/.work/images/` and caches them; subsequent runs reuse them. Everything
the harness writes lives under `tests/vm/.work/` (git-ignored).

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
