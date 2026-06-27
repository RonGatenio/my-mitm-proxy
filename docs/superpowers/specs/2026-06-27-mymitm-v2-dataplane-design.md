# mymitmproxy v2 data plane — design

Date: 2026-06-27
Status: approved (brainstorming) — pending spec review
Supersedes parts of: `2026-06-20-mymitmproxy-design.md` (the static-single-client data plane)

## Goal

Evolve the v1 transparent TLS MITM (single hardcoded client IP, TCX-only, eBPF-only)
into a v2 data plane that:

1. **Learns the client IP dynamically per connection** — any client reaching the
   target server is intercepted and its exact source IP is preserved on the
   upstream leg, with no client IP configured ahead of time. (Multi-client,
   single target server.)
2. **Runs on kernel 4.15 → 6.6+** — auto-detect the attach mechanism (TCX where
   available, classic `clsact`+tc-bpf on older kernels).
3. **Offers a non-eBPF fallback** — a visible iproute2/iptables data plane,
   selectable by config, for portability/debugging (explicitly not stealthy).
4. Tidies config: inline clap/serde defaults; `target_client_ip` becomes optional.

The proxy core (TLS terminate presenting the real leaf, upstream dial, byte pump,
decrypted dump) is unchanged in behavior; only the kernel plumbing changes.

Out of scope for this spec (next steps, per chosen sequencing): finalizing the
GitLab CI pipeline (the `.gitlab-ci.yml` already drafted on this branch) and the
full 3-VM A/B/C router test harness.

## Non-goals / retained constraints

- Still a single configured **target server IP:port**. Multiple servers and
  per-server cert selection remain out of scope.
- Fully static `x86_64-unknown-linux-musl` binary, no runtime deps.
- eBPF mode keeps the v1 threat model (zero `ip route`/`iptables`/`ip rule`
  footprint; tc-eBPF footprint acceptable). **ip-route mode deliberately breaks
  that** — it is the opt-in non-stealthy fallback.

## Architecture

### Mode selection

Two config switches choose the kernel plumbing; everything above is shared.

- `data_plane = "ebpf" | "iproute"` (default `"ebpf"`).
- `attach_mode = "auto" | "tcx" | "tc"` (default `"auto"`, eBPF mode only).
  - `auto`: try TCX (kernel ≥6.6); on failure fall back to `clsact`+tc-bpf.
  - `tcx`/`tc`: force one path (debugging / known target).

A common abstraction hides the difference:

```rust
trait DataPlane {
    /// Open the upstream socket for one intercepted connection, carrying the
    /// client's source IP by the mode's mechanism. `client_ip` is learned from
    /// the accepted listener socket's peer address.
    fn upstream_socket(&self, client_ip: Ipv4Addr, server: SocketAddrV4)
        -> anyhow::Result<std::net::TcpStream>;
}
// Drop on the concrete type tears down all kernel state it installed.
```

The proxy calls `plane.upstream_socket(client_ip, server)` and never learns which
mode is active. The per-connection difference lives entirely in that method.

### Config changes (`mymitm/src/config.rs`)

- `target_client_ip: Option<Ipv4Addr>`:
  - omitted → dynamic multi-client (any client to the target server),
  - set → restrict to that one client (v1 behavior).
- In the BPF `Config`, `client_ip == 0` (0.0.0.0) is the "any client" sentinel.
- New `data_plane` and `attach_mode` fields with defaults above.
- Inline defaults: replace the `d_*()` free functions with inline
  `#[arg(default_value = "...")]` (CLI) and `#[serde(default = "...")]` (TOML)
  annotations; unify the CLI-override / TOML-default story.

## eBPF mode: dynamic client IP

### The correlation problem

The proxy terminates TLS and opens a **fresh** upstream TCP connection, so the
client's 5-tuple on `tun0` shares no fields with the box's 5-tuple on `eth0`.
The bridge is userspace: DNAT rewrites only the destination, so the local
listener's accepted socket has **peer address = the real client `IP:port`**.
Userspace therefore knows the client without any in-kernel guessing.

### Maps (`mymitm-common`)

- `CONFIG: Array<Config>` — unchanged shape; `client_ip == 0` means wildcard.
- `UPSTREAM: LruHashMap<UpstreamKey, UpstreamVal>` — unchanged. Keys on actual
  packet fields (server, client_ip, server_port, client_port), so multi-client
  works without modification.
- **New** `EGRESS: LruHashMap<u16 /*box ephemeral port*/, u32 /*client_ip*/>` —
  populated by userspace per connection, read by `cls_eth_egress`.

### Per-connection userspace (eBPF `upstream_socket`)

1. Create `socket2` TCP socket; set `SO_MARK = fwmark`.
2. **Bind to `box_ip:0`** and read back the assigned ephemeral port via
   `getsockname` → `box_port`.
3. **Insert `EGRESS[box_port] = client_ip`** (network byte order) into the map.
4. `connect()` to the server. (Bind-before-connect closes the race where the SYN
   would egress before the map entry exists.)
5. On connection close, delete `EGRESS[box_port]` (LRU also self-heals if missed).

### Classifier changes (logic stays in unit-tested `classify_*`)

1. `cls_tun_ingress` — match `dst == server_ip:server_port` and
   (`cfg.client_ip == 0` **or** `src == cfg.client_ip`) → DNAT dest to the local
   listener.
2. `cls_tun_egress` — match `src == local_ip:local_port` (any dst) → un-DNAT src
   back to `server_ip:server_port`. (Drops the old `dst == client_ip` condition;
   any reply from our listener is ours.)
3. `cls_eth_egress` — match `mark == fwmark && dst == server_ip:server_port`;
   look up `client_ip = EGRESS[src_port]`; if found, SNAT `src_ip → client_ip`
   (port unchanged) and record the reverse mapping in `UPSTREAM`.
4. `cls_eth_ingress` — reply `src == server, dst == <client_ip>:box_port`; key
   `UPSTREAM` on the packet fields (client IP read from the packet) → un-SNAT
   dest back to `box_ip:box_port`.

### Attach (eBPF)

- `auto`/`tcx`: TCX links (kernel ≥6.6), held by the process; auto-detach on death.
- `auto` fallback / `tc`: add a `clsact` qdisc and attach the four programs as
  tc-bpf filters (ingress/egress on `tun_iface` and `egress_iface`). aya's
  `SchedClassifier` + clsact helpers; no shelling out to `tc`.

## ip-route mode (non-eBPF)

Same proxy core; visible iproute2/iptables/sysctl plumbing. **Abandons the
zero-footprint goal by design** — the portable/debuggable fallback, and what the
VM test uses "for simplicity".

### One-time `setup()` (each action recorded so Drop reverses it exactly)

- sysctl (save originals first): `net.ipv4.ip_forward=1`,
  `net.ipv4.conf.<tun>.rp_filter=0`, and `route_localnet=1` where the reply table
  requires it.
- **Intercept:**
  `iptables -t nat -A PREROUTING -i <tun> -p tcp -d <server_ip> --dport <server_port> -j DNAT --to-destination <local_ip>:<local_port>`.
  The target server is known from config, so plain DNAT — no TPROXY /
  SO_ORIGINAL_DST recovery needed.
- **Reply capture for the spoofed-source upstream:**
  `ip rule add fwmark <fwmark> lookup <table>` and
  `ip route add local 0.0.0.0/0 dev lo table <table>`, so replies addressed to a
  (spoofed) client IP and marked by our socket are delivered locally instead of
  being forwarded back out.

### Per-connection upstream (ip-route `upstream_socket`)

Set `IP_TRANSPARENT` + `SO_MARK = fwmark`, **bind to `client_ip:0`** (the dynamic
client IP from the accept peer), then `connect()`. The kernel emits packets with
`src = client_ip` — no SNAT rule and no per-flow iptables churn. The `fwmark`
rule routes replies back to us; the kernel's socket/conntrack lookup reassociates
them with our connection.

### Drop teardown

Delete the PREROUTING rule, the `ip rule`, the `ip route ... table <table>`, and
restore every saved sysctl — leaving the box as found.

## Error handling / fail behavior

- **eBPF/TCX:** unchanged auto fail-open on process death (links close with the fd).
- **eBPF/tc:** Drop-guard deletes the clsact qdisc. On SIGKILL the qdisc lingers
  (the program keeps DNATing with no listener → connections break until cleaned).
  Documented; a `--cleanup` flag force-removes a stale qdisc on next start.
- **ip-route:** every rule/route/sysctl reversed in Drop. On SIGKILL they linger;
  the same `--cleanup` path reverses a known-tagged ruleset.
- **Map writes** (`EGRESS` insert) that fail are logged and the connection
  proceeds un-SNATted — a visible failure, never silent corruption.

## Kernel 4.15 validation

The programs read packets by **raw offset** and access `__sk_buff->mark` as a
context field — no kernel-struct CO-RE relocations — so we expect **no BTF
dependency** (4.15 ships none). The residual risk is the older verifier being
stricter on bounds. Validate with the **`lvh` skill** (from sweetd in WSL): boot a
4.15 VM, load the object, confirm the verifier accepts all four programs and the
`clsact`+tc attach path works. Any bounds failure is fixed inside `meta()`'s
guards. Required kernel features all predate 4.15: `clsact` qdisc (4.5),
`BPF_MAP_TYPE_LRU_HASH` (4.10), `bpf_skb_store_bytes` / `bpf_l3_csum_replace` /
`bpf_l4_csum_replace` (3.x–4.x), `IP_TRANSPARENT`/TPROXY (2.6.x).

## Testing

- `mymitm-common` unit tests extended for wildcard-client (`client_ip == 0`) and
  the dynamic matching in `classify_tun` / `classify_eth`.
- `config.rs` tests for `data_plane` / `attach_mode` parsing, inline defaults, and
  optional `target_client_ip`.
- netns e2e harness (`tests/integration/run_e2e.sh`):
  - **multi-client** assertion — two client IPs, each observed at the server with
    its own source IP preserved;
  - a **second run in `data_plane = "iproute"`** asserting the same four
    invariants (handshake on real cert, byte round-trip, dump plaintext,
    server-observed source IP == the client's).
- 4.15 verifier check via `lvh`.

## Risks / open questions

- aya 0.13.1 tc/clsact attach API parity with the TCX path — confirm the exact
  `SchedClassifier`/qdisc calls during implementation.
- ip-route mode reply routing (`ip rule`/`local` route) interacting with an
  existing OpenVPN routing setup on a real box — the netns/VM tests must exercise
  a realistic routing table, not just loopback.
- `--cleanup` semantics: how stale state is tagged so it can be reversed safely
  without touching unrelated rules (e.g. a dedicated chain / a reserved fwmark +
  rule priority).
