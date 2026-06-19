# mymitmproxy — Transparent TLS MITM with source-IP preservation

**Status:** Design approved 2026-06-20
**Author:** Ron Gatenio (rong@sweet.security) with Claude

## 1. Background & goal

We have `root` on a Linux box running an **OpenVPN server**. VPN clients tunnel in and
reach a remote **HTTPS server** ("SERVER") on the inner network. We hold SERVER's **real
leaf certificate and its private key**.

We need a tool that transparently man-in-the-middles the TLS between a **target client**
and SERVER, for traffic visibility:

- **Transparent** — the client must see no difference. We present SERVER's genuine leaf
  cert, so any certificate pinning (CA / leaf / SPKI) passes with no client modification.
- **Source-IP preserving** — the onward (proxy → SERVER) connection must egress with the
  **exact source IP of the client** (its in-tunnel IP), both for network optics and because
  inner firewall rules enforce per-client source IPs.
- **Config-clean (threat model A)** — leave **zero footprint** in the host's network
  configuration surfaces: nothing in `ip route`, `iptables`/`nft`, or `ip rule`, and no new
  visible network interface. A footprint discoverable only via BPF-aware tooling
  (`bpftool`, `tc filter show`) is acceptable. Evading BPF-aware inspection (rootkit-level
  hiding) is explicitly **out of scope**.
- **Single static binary** — `x86_64-unknown-linux-musl`, fully static (`ldd` →
  "not a dynamic executable"), no dynamic/runtime dependencies. Written in **Rust**.

### v1 scope

- A **single target client IP** and a **single target server IP:port**, passed as
  configuration.
- Full MITM for that one flow; **all other traffic forwarded untouched** by the kernel.
- Decrypted bytes written to a **dump** on disk.
- Multi-target (multiple clients/servers) is a later iteration.

## 2. Why not mitmproxy / off-the-shelf

mitmproxy (and equivalents) **always open the upstream socket from the host's own IP** —
there is no IP-transparency option. That alone fails the source-IP requirement, independent
of mitmproxy's other drawbacks (Python/PyInstaller size; the `REDIRECT`-based NAT loop that
forces a dedicated UID). Since we must build the IP-transparent egress ourselves, we build
the whole interceptor.

## 3. Key networking facts that shape the design

1. **Decrypted VPN traffic on `tun0` carries the client's real (in-tunnel) source IP.** We
   operate purely on this plaintext side; OpenVPN is never touched or reconfigured.
2. **Linux forwarding is destination-based.** A client→SERVER packet injected by OpenVPN on
   `tun0` is forwarded out `eth0` purely because the route for SERVER's destination resolves
   to `eth0` and `ip_forward=1`. The ingress interface plays no role.
3. **Active MITM requires being inline.** Passive sniffing cannot intercept (a copy doesn't
   stop forwarding) and cannot decrypt (TLS 1.2/1.3 ECDHE forward secrecy means the server
   private key does not enable passive decryption). We must terminate the TLS ourselves.
4. **To divert without `ip route`/`iptables`/`ip rule`, we use tc-eBPF** attached to the
   data path. eBPF is the only mechanism that diverts packets in-kernel while leaving the
   config surfaces clean.
5. **Preserving the exact client source IP requires capturing the upstream return leg.**
   When the upstream packet carries `src = client IP`, SERVER replies to the client IP; the
   kernel would otherwise forward that reply to the real client. We rewrite the reply's
   destination back to the box **before the routing decision** (tc-ingress on `eth0`) so the
   kernel delivers it to our socket — the eBPF equivalent of `IP_TRANSPARENT` + `ip rule`,
   but invisible.

## 4. Architecture

```
                        ┌─────────────────────── our static binary ───────────────────────┐
 client 10.8.0.5        │  userspace (tokio + rustls[ring])                                 │
   │ TLS to SERVER      │   ┌──────────────┐   decrypt    ┌──────────┐  re-encrypt         │
   ▼                    │   │ TLS server   │─────────────▶│  dumper  │                      │
 tun0 (OpenVPN) ─ingress┼──▶│ (real cert)  │              └──────────┘                      │
   ▲           tc-eBPF  │   └──────────────┘                    │                            │
   │  (DNAT to local)   │          ▲                            ▼                            │
   │                    │          │                    ┌──────────────┐                     │
 eth0 ──────────ingress─┼──────────┘                    │ TLS client   │── kernel socket ──▶ eth0
   ▲           tc-eBPF  │   (un-SNAT replies)            │ (to SERVER)  │   (SO_MARK)         │
   └── egress  tc-eBPF ─┼───────────────────────────────┴──────────────┘  (SNAT src→client) │
       (SNAT src→client)│         aya loads/attaches both progs + maps (CO-RE)               │
                        └──────────────────────────────────────────────────────────────────┘
```

### Components

- **eBPF data plane** (aya, Rust, CO-RE) — two tc/`SCHED_CLS` programs plus maps:
  - `cls_tun` on `tun0` (client side): DNAT/un-DNAT for the target flow.
  - `cls_eth` on `eth0` (server side): mark-based SNAT on egress, map-based un-SNAT on
    ingress.
- **Userspace control + data plane** (tokio):
  - `bpf` — load programs, create the `clsact` qdisc, attach filters, populate/maintain maps,
    detach on shutdown.
  - `proxy` — accept the locally-delivered client connection, terminate TLS (real cert+key),
    dial SERVER (TLS client, `SO_MARK`), pump bytes both directions.
  - `dump` — write decrypted streams + index.
  - `config` — TOML + CLI.
  - `cleanup` — signal handlers + `Drop` guards; idempotent stale-filter removal on startup.

Both proxy legs use **ordinary kernel TCP sockets** — no `smoltcp`, no `AF_PACKET`. The
eBPF NAT makes the kernel deliver the diverted/return traffic to those sockets.

## 5. Data flow

### Target flow (client → SERVER:443)

1. OpenVPN writes the plaintext packet to `tun0`. `cls_tun` ingress matches
   `src=CLIENT, dst=SERVER:PORT`, rewrites `dst → 127.0.0.1:LPORT`, fixes L3/L4 checksums,
   returns `TC_ACT_OK`.
2. Kernel delivers locally to our listener on `127.0.0.1:LPORT`. We terminate TLS presenting
   the real leaf cert+key.
3. Our replies leave via `cls_tun` egress, which rewrites `src 127.0.0.1:LPORT → SERVER:PORT`
   so the client sees SERVER as the peer.
4. We dial SERVER with a kernel TCP socket tagged `SO_MARK = fwmark`. `cls_eth` egress sees
   the mark, rewrites `src boxIP:P → CLIENT:P`, and records
   `(SERVER:PORT, CLIENT:P) → boxIP:P` in `upstream_map`.
5. SERVER replies to `CLIENT:P` arriving on `eth0`. `cls_eth` ingress looks up `upstream_map`,
   rewrites `dst CLIENT:P → boxIP:P` **before routing**, so the kernel delivers it to our
   socket. No reply reaches the real client; no RST storm.
6. Decrypted bytes both directions → dumper.

### Pass-through (everything else)

Any other client, server, or port produces no eBPF match → the kernel forwards normally. The
proxy never sees it. Source-IP preservation is automatic for pass-through because those are
the client's own connections.

## 6. eBPF programs & maps

- **`cls_tun`** (`SCHED_CLS`, attached to `tun0` ingress + egress via `clsact`):
  - ingress: if `src==client && dst==server:port` → DNAT to `127.0.0.1:lport`.
  - egress: if `src==127.0.0.1:lport && dst==client` → rewrite src to `server:port`.
- **`cls_eth`** (`SCHED_CLS`, attached to `eth0` ingress + egress via `clsact`):
  - egress: if `skb->mark==fwmark && dst==server:port` → SNAT src to `client:P`; upsert
    `upstream_map`.
  - ingress: if `src==server:port && dst==client:P` present in `upstream_map` → un-SNAT
    `dst → boxIP:P`.
- **Maps:**
  - `config_map` (array, 1 entry): target client IP, server IP, server port, lport, fwmark,
    boxIP. Populated by userspace at startup, so one compiled object is fully parameterized at
    runtime.
  - `upstream_map` (hash): `(serverIP, serverPort, clientIP, clientPort) → (boxIP, boxPort)`
    for reverse rewrite; entries reaped on connection close (userspace deletes; TTL sweep as
    backstop).
- **CO-RE** throughout (BTF at `/sys/kernel/btf/vmlinux`) so the single binary runs across
  kernel versions.

Because v1 is single-client/single-server, the original destination is known from config;
we do not need to smuggle it to userspace dynamically.

All program/map names are derived from a configurable `bpf_obj_name` prefix.

## 7. Configuration

TOML file with CLI-flag overrides for every field. Mandatory: `cert_path`, `key_path`,
`target_client_ip`, `target_server_ip`. Everything else defaulted.

```toml
target_client_ip   = "10.8.0.5"
target_server_ip   = "192.168.1.50"
target_server_port = 443
tun_iface          = "tun0"        # client-side attach point (configurable)
egress_iface       = "eth0"        # server-side attach point (configurable)
local_addr         = "127.0.0.1"
local_port         = 8443
fwmark             = 0x1337        # SO_MARK value; configurable to avoid collisions
cert_path          = "/path/leaf.pem"
key_path           = "/path/leaf.key"
dump_path          = "/var/tmp/mitm-dumps/"
bpf_obj_name       = "mymitm"      # prefix for program/map names (configurable)
log_level          = "info"
```

## 8. Dump format (v1)

Protocol-agnostic. Per connection:

- one line appended to `index.jsonl`:
  `{ "conn_id": "...", "client": "10.8.0.5:43012", "server": "192.168.1.50:443",
     "start_ts": "...", "end_ts": "..." }`
- raw decrypted streams: `<conn_id>.c2s` (client→server) and `<conn_id>.s2c`
  (server→client).

HTTP (or other protocol) parsing is a later layer, not v1. Dump I/O must never block or
crash the proxy path; on I/O error it degrades to dropping dump data with a warning.

## 9. Error handling & lifecycle

- **Graceful shutdown** (SIGTERM/SIGINT) and **`Drop` guards** detach tc filters, remove the
  `clsact` qdisc we added (only if we added it), and clear maps.
- **Ungraceful death:** tc filters can linger and would drop target connections (fail-closed
  for the target flow only — pass-through is unaffected). Mitigations: (a) **idempotent
  startup** that detects and removes our own stale filters/qdisc before re-attaching;
  (b) documented manual recovery: `tc filter del dev <iface> ...` / `tc qdisc del dev <iface>
  clsact`.
- **Upstream connect failure / cert problems:** log and reset the client connection; the
  client retries.
- **Map exhaustion / unexpected packet:** eBPF defaults to `TC_ACT_OK` (pass) so a logic gap
  degrades toward normal forwarding rather than a black hole.

## 10. Build & packaging

- Cargo workspace:
  - `mymitm` — userspace binary.
  - `mymitm-ebpf` — eBPF programs (Rust → BPF), embedded into the binary by aya at build time.
  - `mymitm-common` — shared `#[repr(C)]` map structs used by both sides.
- Target `x86_64-unknown-linux-musl`, `-C target-feature=+crt-static`. Result: one fully
  static file.
- rustls with the **`ring`** crypto provider (static-musl friendly; avoids the `aws-lc-rs` C
  build).
- No hostname resolution anywhere (IP-only), sidestepping musl static-NSS limits.

## 11. Testing

- **Gating spike (do first):** attach a no-op tc-eBPF program to a `tun` device in WSL2 and
  confirm it loads with CO-RE. WSL2 here is kernel 6.6 with `BPF_SYSCALL`, BTF present, and
  `NET_CLS_BPF`/`NET_ACT_BPF` modules — promising, but tc-on-`tun` must be proven. **If it
  fails, provision a Hyper-V or EC2 VM** and develop the data plane there; keep WSL2 for
  userspace/TLS unit tests.
- **Integration harness (netns-based):** a fake client, a fake SERVER (TLS server using a
  self-signed cert that we also feed the proxy as the "real" cert), and a `tun` standing in
  for `tun0`. Assertions:
  - client sees the genuine cert (handshake succeeds against a pinned client);
  - bytes round-trip correctly both directions;
  - dump files match the transferred bytes;
  - **the upstream SYN to SERVER carries the client's source IP** (verified by capture on the
    SERVER side).
- **Unit tests:** config parsing, dump writer, map encode/decode, and checksum-fixup logic
  (known test vectors).

## 12. Open items / future work

- Multi-target (multiple clients and servers; dynamic original-dst via map instead of config).
- Optional HTTP/protocol parsing layer over the raw dump.
- Optional pcap-style dump output.
- Decision detail to verify in the spike: redirecting diverted packets to `127.0.0.1` (`lo`)
  vs the box IP for the client-side DNAT target.
