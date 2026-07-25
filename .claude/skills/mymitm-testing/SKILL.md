---
name: mymitm-testing
description: Use when running, setting up, or debugging mymitmproxy's tests — the unit suites, the netns end-to-end harness (eBPF and iproute data planes), the 3-VM kernel-4.15 source-IP harness, or the protocol-coverage matrix — or when reproducing a test failure and reading the decrypted dumps or the PASS/FAIL report.
---

# Running mymitmproxy's tests

## Overview

Four test layers. Every network test needs **Linux + root** (network namespaces, eBPF, KVM); on the Windows dev box run them inside **WSL2**. The e2e and VM harnesses run the **real static musl binary**, so **rebuild after any code change**.

Golden rules:
- **Run from the repo root, inside Linux/WSL2.** All harness paths are relative (`tests/...`). On the Windows box, enter WSL first (see the `wsl-shell` skill); the repo is at `/mnt/c/projects/mymitmproxy/...` and netns/eBPF/KVM exist only in the Linux environment.
- **Rebuild first:** `cargo build -p mymitm --release` → `target/x86_64-unknown-linux-musl/release/mymitm`. `.cargo/config.toml` pins the default target to musl, so no `--target` flag is needed. The harnesses do *not* rebuild for you.
- **Network harnesses need `sudo`.** Unit tests do not.
- **GitLab CI is red by design** (k8s-runner dlopen limitation, not the code); **GitHub Actions is the authoritative CI** — don't chase the GitLab red.

## Quick reference

| Suite | Command | Root? | Proves | Where results land |
|---|---|---|---|---|
| Unit | `cargo test -p mymitm-common && cargo test -p mymitm` | no | classify / config / dump / proxy DER-pin | cargo test output |
| netns e2e (eBPF) | `sudo bash tests/integration/run_e2e.sh` | yes | handshake+pin, byte round-trip, dump has plaintext, **src-IP preserved** (multi-client) | colored `PASS`/`FAIL`; dumps under the printed `workdir` |
| netns e2e (iproute) | `sudo MODE=iproute bash tests/integration/run_e2e.sh` | yes | same + **post-run state cleanliness** (no leftover iptables/ip-rule) | same |
| 3-VM (kernel 4.15) | `sudo bash tests/vm/run.sh all [--data-plane iproute] [--keep]` | yes + KVM | routing + src-IP on a **real 4.15** box, both planes | `PASS:`/`FAIL:` lines + `ALL PHASES PASS`; artifacts in `tests/vm/.work/` |
| Protocol matrix (P0) | `sudo bash tests/integration/protocols/run_matrix.sh [--mode ebpf\|iproute] [--only NAME]` | yes | per-protocol *forward* + *dump-parse* (P0: HTTP/1.x, keep-alive, streaming, pump, SSE, SigV4, pinning, lifecycle) | `tests/reports/matrix-<mode>-<stamp>/` (report.txt + report.json + dumps/ + logs/) |

## Setup

One-time toolchain (Linux/WSL2), from the repo root:

```bash
rustup target add x86_64-unknown-linux-musl        # nightly + rust-src come from rust-toolchain.toml
cargo install bpf-linker --locked                  # builds the eBPF object
sudo apt-get update && sudo apt-get install -y clang llvm libelf-dev musl-tools pkg-config
```

- **Protocol-matrix deps:** `python3 -m pip install -r tests/integration/protocols/requirements.txt` (h11 + botocore + pytest). Missing deps make affected rows report `SKIP`, never a false pass.
- **VM harness extras:** `sudo apt-get install -y qemu-system-x86 qemu-utils cloud-image-utils iproute2 openssl curl gettext-base` and a writable `/dev/kvm` (without it QEMU falls back to slow TCG but still runs). The first `up` downloads ~1 GB of Ubuntu cloud images into `tests/vm/.work/images/` and caches them.

Full build notes are in the README "Build" section.

## Running & reading each suite

**Unit** — fast, no root: `cargo test -p mymitm-common && cargo test -p mymitm`.

**netns e2e** (`tests/integration/run_e2e.sh`) — **build the release binary first.** It builds the `mmcli`/`mmsrv` netns + veth topology, runs the real binary plus a fake TLS server, and sends `PING-FROM-CLIENT`/`PONG-FROM-SERVER`. Success prints a green **`ALL ASSERTIONS PASS`** banner; on any failure it auto-prints `proxy.log` + `server.log`. It prints `workdir: /tmp/mymitm-e2e.XXXXXX`; the decrypted dumps and those logs live under `$workdir/`. Confirm the request was captured with `grep -rl PING-FROM-CLIENT "$workdir/dumps/"` (a request lands in `<conn_id>.c2s`, the response in `.s2c`). `MODE=iproute` switches the data plane and adds post-run cleanliness checks. Teardown is automatic and idempotent. To bring the topology up by hand (no client) for probing: `sudo bash tests/integration/debug_setup.sh`.

**Protocol matrix** (`tests/integration/protocols/run_matrix.sh`) — **build the release binary first**, then `python3 -m pip install -r tests/integration/protocols/requirements.txt`. It reuses the netns topology (`lib.sh`), brings it up once, and runs each `manifest.tsv` row sequentially (one server → one proxy → one client → dump-parse). Each row reports **Fwd** vs **Dump** against the row's *expected* verdict; a documented gap (e.g. `preexisting`) that correctly `✗`s forward is a **PASS**. `--only NAME` runs one row; `--mode iproute` switches the data plane. All output is organized in the report folder (below). Pure-Python parsers/logic have fast unit tests: `cd tests/integration/protocols && python3 -m pytest -q` (no root).

**3-VM** (`tests/vm/run.sh`) — boots A (client) / B (router+proxy, **kernel 4.15**) / C (HTTPS server). `all` runs up→router→proxy→down; or step through `up`, `router`, `proxy`, `down` (add `--keep` to leave the VMs running for debugging). On failure it prints `journalctl -u mymitm` from B and C's server log; serial consoles are at `tests/vm/.work/<A|B|C>.serial.log`. See `tests/vm/README.md` for troubleshooting.

**Dump format** (what the proxy decrypted): per connection, `<dump_path>/<conn_id>.c2s` (client→server) and `.s2c` (server→client) hold the **raw decrypted bytes**; `index.jsonl` has one JSON record per connection (`conn_id`, `client`, `server`, timestamps). To confirm a specific request was captured: `grep -rl "<marker>" <dump_path>` then read the matching `.c2s`/`.s2c`. Note the dump records no HTTP/TLS version — parse the bytes with an external parser (see `tests/PROTOCOL_COVERAGE.md`).

## Test report folder

Every harness run drops its artifacts into `tests/reports/<suite>-<mode>-<UTC>/` (gitignored; override with `REPORT_DIR=`). On the Windows box that path is `C:\projects\mymitmproxy\...\tests\reports\` — open it directly, nothing to fetch. Each run holds `report.txt`/`report.json` (the matrix), `dumps/<case>/` (decrypted `.c2s`/`.s2c` + `index.jsonl`), `logs/`, and `meta.txt`; `tests/reports/LATEST` names the newest run. The 3-VM harness `scp`s VM B's `/opt/mymitm/dumps` back here automatically at the end of phase 2, so kernel-4.15 dumps land locally too.

## Common mistakes

- **Ran on Windows or without root** → netns/eBPF/KVM fail. Use WSL2 and `sudo`.
- **Forgot to rebuild** → the harness silently runs a stale binary. `cargo build -p mymitm --release` first.
- **"proxy listening" never appears / early exit** → read the printed `proxy.log` (e2e) or `sudo journalctl -u mymitm` on B (VM).
- **Leftover netns/veths/taps** from a killed run → all harnesses clean up on exit and are idempotent; just re-run (or `tests/vm/run.sh down`).
- **Panicking at red GitLab CI** → expected; trust GitHub Actions.

## See also

- `README.md` — build and run the proxy itself.
- `tests/PROTOCOL_COVERAGE.md` — protocol test plan + coverage matrix (the planned matrix suite and report shape).
- `tests/vm/README.md` — VM harness details and troubleshooting.
