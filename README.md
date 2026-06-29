# mymitmproxy

Transparent TLS man-in-the-middle proxy with **source-IP preservation**, written in Rust as a
single fully-static `x86_64-unknown-linux-musl` binary.

It terminates the TLS between a target client and a remote HTTPS server (presenting the
server's genuine leaf certificate, so certificate pinning passes unmodified), dumps the
decrypted bytes to disk, and re-originates the upstream connection so that the server sees the
**client's exact source IP** — not the proxy box's IP.

## Quickstart (for the impatient)

Five commands, from a clean checkout to a running proxy:

```bash
# 1. one-time toolchain setup
rustup target add x86_64-unknown-linux-musl && cargo install bpf-linker --locked

# 2. build the static binary
cargo build -p mymitm --release

# 3. make a throwaway cert/key (use the REAL server's cert+key in production)
openssl req -x509 -newkey ed25519 -keyout leaf.key -out leaf.pem -days 1 -nodes -subj /CN=test

# 4. write a minimal config
cat > mymitm.toml <<'EOF'
target_server_ip = "192.168.1.50"   # the real HTTPS server you proxy to
box_ip           = "192.168.1.10"   # this box's IP on the egress NIC
cert_path        = "leaf.pem"
key_path         = "leaf.key"
egress_iface     = "eth0"           # NIC toward the server
tun_iface        = "tun0"           # interface the client traffic arrives on
EOF

# 5. run it (root needed to load eBPF) — Ctrl-C to stop, state is cleaned up on exit
sudo ./target/x86_64-unknown-linux-musl/release/mymitm --config mymitm.toml
```

That intercepts any client reaching `192.168.1.50:443`, decrypts to `dump_path`
(default `/var/tmp/mitm-dumps`), and re-sends to the server with the client's own
source IP. No client IP needed up front — it's learned per connection. For the full
field list and CLI flags, read on.

## Why

We hold the real leaf cert + key for a remote `SERVER`, and we run as `root` on a Linux box
that the target client's traffic transits (e.g. an OpenVPN server whose clients reach `SERVER`
on the inner network). We need TLS visibility while:

- **Transparent** — the client sees no difference; we present `SERVER`'s genuine leaf cert, so
  CA / leaf / SPKI pinning all pass with no client change.
- **Source-IP preserving** — the proxy→`SERVER` leg egresses with the client's exact source IP,
  for network optics and because inner firewalls enforce per-client source IPs. Off-the-shelf
  proxies (mitmproxy et al.) always open the upstream socket from the host's own IP and cannot
  do this.
- **Config-clean** (eBPF data plane) — leaves zero footprint in `ip route` / `iptables` / `nft`
  / `ip rule` and adds no visible interface. Only BPF-aware tooling (`bpftool`, `tc filter
  show`) can see it.

## How it works

Decrypted client→`SERVER` traffic arrives on the client-side interface (e.g. `tun0`) carrying
the client's real source IP. The proxy diverts that flow to a local TLS-terminating listener,
decrypts and dumps it, then opens an upstream TLS connection to `SERVER` whose egress packets
carry `src = client IP`. The server's replies (addressed to the client) are rewritten back to
the box **before the routing decision** so the kernel delivers them to our socket instead of
forwarding them on.

```
 client ──TLS──▶ tun0 ─divert─▶ [ TLS server (real cert) ─▶ dumper ─▶ TLS client ] ──▶ eth0 ──▶ SERVER
                                                                          (egress src = client IP)
        ◀──────────────────────  replies un-rewritten back to the box  ◀──────────────────────
```

The client IP is learned **dynamically per connection** from the accepted socket's peer
address — you do not need to know it in advance. Setting `target_client_ip` restricts
interception to a single client; omitting it intercepts any client to the configured
`target_server_ip:port`.

### Two data planes

Selectable via `data_plane` (config) or `--data-plane` (CLI):

- **`ebpf`** (default) — tc-eBPF programs (loaded/attached via [aya](https://aya-rs.dev)) do
  the divert + source-IP rewrite in-kernel. Config-clean. Attach mode is auto-detected:
  TCX on kernel ≥ 6.6, falling back to `clsact` + classic tc-bpf on older kernels. Validated
  down to **kernel 4.15** (no TCX, no BTF). Override with `--attach-mode {auto,tcx,tc}`.
- **`iproute`** — `IP_TRANSPARENT` bind + policy routing (`ip rule` fwmark → dedicated table)
  + an `iptables` mangle `MARK` rule. Not config-clean, but uses only standard kernel features;
  useful where eBPF is unavailable. State is torn down on exit.

## Repository layout

| Path | Purpose |
|------|---------|
| `mymitm/` | The userspace binary: TLS terminate/originate, dumper, data-plane drivers (`bpf.rs`, `iproute.rs`, `dataplane.rs`), config (`config.rs`), `proxy.rs`, `main.rs`. |
| `mymitm-common/` | Types and constants shared between userspace and the eBPF object (`Config`, map values, classify helpers). |
| `mymitm-ebpf/` | The eBPF programs. Built out-of-tree by `mymitm/build.rs` (separate target), not a workspace member. |
| `examples/mymitm.toml` | Annotated sample config. |
| `tests/integration/` | netns end-to-end harness (`run_e2e.sh`, `client.py`, `fake_server.py`). |
| `docs/superpowers/specs/` | Design docs (v1 + v2 data-plane). |

## Build

Requires the nightly toolchain pinned in `rust-toolchain.toml` (with `rust-src`), the musl
target, and `bpf-linker` for the eBPF object.

```bash
# one-time
rustup target add x86_64-unknown-linux-musl
cargo install bpf-linker --locked
# host build deps: clang, llvm, libelf-dev, musl-tools, pkg-config (see .gitlab-ci.yml)

# release (fully static) binary
cargo build -p mymitm --release
# -> target/x86_64-unknown-linux-musl/release/mymitm
```

## Configure

Copy `examples/mymitm.toml` and fill in real values. Required: `target_server_ip` and
`box_ip`. The cert/key default to `/etc/mymitm/leaf.{pem,key}`. See the sample for every field
and its default. Quick throwaway cert for testing:

```bash
openssl req -x509 -newkey ed25519 -keyout leaf.key -out leaf.pem -days 1 -nodes -subj /CN=test
```

## Run

Needs `root` (loads eBPF / configures routing). Config path defaults to `./mymitm.toml`.

```bash
sudo ./mymitm --config /etc/mymitm/mymitm.toml
```

Common overrides (also available as `MYMITM_*` env vars):

```bash
sudo ./mymitm \
  --server 192.168.1.50 --server-name real.example.com \
  --cert leaf.pem --key leaf.key \
  --tun tun0 --egress eth0 \
  --data-plane ebpf --attach-mode auto \
  --dump-path /var/tmp/mitm-dumps
```

- `--client <IP>` restricts interception to one client (omit for dynamic per-connection).
- `--cleanup` reverses any leftover state (stale `clsact` qdisc / iproute rules) from a
  previous unclean exit, then continues startup.
- Decrypted payloads are written under `dump_path` as a JSONL index plus per-connection
  `.c2s` / `.s2c` blobs.

## Test

Unit tests:

```bash
cargo test -p mymitm-common
cargo test -p mymitm
```

End-to-end (network namespaces, runs the real release binary; needs `root`):

```bash
cargo build -p mymitm --release
sudo bash tests/integration/run_e2e.sh                 # eBPF, multi-client
sudo MODE=iproute bash tests/integration/run_e2e.sh    # iproute data plane
```

The e2e harness asserts the TLS handshake/pinning passes, application bytes round-trip both
directions, the dump files hold the decrypted plaintext, and the server records the **client's**
peer IP (not the box IP).

CI (`.gitlab-ci.yml`) runs both unit suites and the release build on `rust:bookworm`.

## License

Proprietary.
