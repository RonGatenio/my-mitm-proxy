# Task 11 report — netns end-to-end (MITM + source-IP preservation proof)

## Status: PASS — 4/4 e2e assertions pass against the REAL release binary, incl. source-IP = 10.8.0.5

The full system was proven end-to-end against the actual static-musl release
binary (`target/x86_64-unknown-linux-musl/release/mymitm`) using a real-TCP
netns + veth topology. The eBPF data plane (not any `ip route`/iptables rule)
performs the DNAT diversion and the source-IP SNAT.

## Topology (real TCP via netns + veth)

```
 netns mmcli                  root ns (runs the mymitm binary)               netns mmsrv
 vcli 10.8.0.5/24 <-veth-> mmvroot 10.8.0.1/24   mmveth0 192.168.1.10/24 <-veth-> vsrv 192.168.1.50/24
 default via 10.8.0.1      tun_iface = mmvroot    egress_iface = mmveth0          fake TLS server :443
                          box_ip = 192.168.1.10   local 127.0.0.1:8443
```

Packet path (all rewrites done by eBPF):
1. Client (10.8.0.5) -> 192.168.1.50:443 routes via default -> arrives (RX) on
   `mmvroot`. `cls_tun_ingress` DNATs dst -> 127.0.0.1:8443; kernel delivers it
   locally to the proxy listener.
2. Proxy terminates client TLS (presents the genuine leaf), then dials
   192.168.1.50:443 over a `SO_MARK=0x1337` socket from box 192.168.1.10 on
   `mmveth0`. `cls_eth_egress` matches the mark and SNATs src 192.168.1.10 ->
   10.8.0.5 (source port unchanged), recording the reverse mapping in `UPSTREAM`.
3. The fake server in netns mmsrv sees the connection arriving from **10.8.0.5**.
4. Server replies to 10.8.0.5; a route `10.8.0.0/24 via 192.168.1.10` in mmsrv
   sends it back on `mmveth0`, where `cls_eth_ingress` un-SNATs dst -> the box.
5. Proxy's reply to the client egresses `mmvroot`; `cls_tun_egress` un-DNATs
   src 127.0.0.1:8443 -> 192.168.1.50:443 so the client sees the real server.

## The FOUR assertions (final run output)

```
[harness] starting mymitm (real release binary) in root ns
mymitm data plane attached + proxy listening
[harness] running TLS client in netns mmcli (src 10.8.0.5 -> 192.168.1.50:443)
----- client output -----
HANDSHAKE_OK peer_cert_subject=((('commonName', 'server.test'),),)
RESPONSE=b'PONG-FROM-SERVER'
CLIENT_OK
-------------------------
[harness] evaluating FOUR assertions
ASSERTION 1 PASS: client completed TLS handshake trusting the genuine leaf cert
ASSERTION 2 PASS: application bytes round-tripped (PING/PONG) through the MITM
ASSERTION 3 PASS: dump index + c2s/s2c contain decrypted plaintext (conn_id=conn-00000000)
[harness] fake server recorded peer IP = 10.8.0.5
ASSERTION 4 PASS: fake server recorded peer IP = 10.8.0.5 (source IP preserved via eBPF SNAT)

================================================================
 ALL FOUR ASSERTIONS PASS (incl. source-IP = 10.8.0.5)
================================================================
```

- **(1) genuine cert**: the python client trusts ONLY the genuine leaf cert
  (`load_verify_locations(cafile=leaf.pem)`, `CERT_REQUIRED`, `check_hostname`
  against SNI `server.test`). HANDSHAKE_OK proves a real cryptographic trust,
  not verification-disabled.
- **(2) round-trip**: client sent `PING-FROM-CLIENT`, received `PONG-FROM-SERVER`
  through the MITM both directions.
- **(3) dump**: `index.jsonl` carries a record with client 10.8.0.5 + server
  192.168.1.50, and `<id>.c2s`/`.s2c` contain the decrypted `PING`/`PONG`.
- **(4) source-IP preservation (CORE)**: the fake server recorded peer IP =
  **10.8.0.5** (the client), NOT 192.168.1.10 (the box). Authoritative proof the
  eBPF SNAT carries the client's exact source IP upstream.

Verified repeatable (3 consecutive clean runs, 4/4 each). Teardown leaves no
netns/veth (`NO_NETNS`, `NO_VROOT`, `NO_VETH0`) and restores the
`net.ipv4.conf.all.route_localnet` sysctl to its original value.

## Bug found and fixed during this task (eBPF L2 auto-detection)

The harness initially failed at assertion 1: the client SYN timed out, never
reaching the proxy listener (`ss` showed no SYN-RECV on 127.0.0.1:8443).

Debugging method: temporarily added `aya-log-ebpf` `info!` traces (bridged to
the tracing subscriber via `tracing-subscriber`'s `tracing-log` feature) and a
`HIT cls_tun_ingress` entry log. Result: `HIT` fired on every arriving packet
(so the TCX program WAS attached and running), but the `meta()` guard always
bailed before classification.

Root cause: `meta()` auto-detected L2-vs-L3 from the high nibble of the first
packet byte (`(first >> 4) == 4` => treat as raw IPv4 at offset 0). On this
topology the veth's MAC was `4e:83:21:..` — its first byte `0x4e` has high
nibble `4`, so an **Ethernet** frame was misdetected as **raw L3**. The code
then read the IHL/proto from inside the MAC header, found proto != TCP, and
returned `None` — so no DNAT ever happened. (Tasks 6/7 passed only because
those interfaces' MACs did not happen to start with `0x4_`.)

Fix (`mymitm-ebpf/src/main.rs`, `meta()`): detect L2 by probing the EtherType
field that exists only in an L2 frame — if bytes [12..14] == 0x0800 (IPv4
EtherType, NBO) the frame is Ethernet (l3 = 14); otherwise fall back to the
IPv4 version-nibble check at offset 0 for a raw tun (l3 = 0). This is a
1-knob change to the kernel glue; `classify_tun`/`classify_eth` are untouched.

Residual note: a raw-L3 IPv4 datagram whose source-IP first two bytes are
`8.0` would alias the 0x0800 EtherType and be misread as Ethernet. This is a
rare corner (source 8.0.0.0/16) and does not affect the veth case or typical
OpenVPN tun deployments; a fully robust version would consult the skb
`protocol` field. Documented here for completeness.

A second route-level fix was needed (environmental, in the harness, not the
binary): a packet DNAT'd to 127.0.0.1 that ARRIVES on a real interface is
dropped as a martian unless `route_localnet` is enabled for that interface —
the same mechanism transparent proxies / Docker rely on. The harness sets
`net.ipv4.conf.<tun>.route_localnet=1` (+ `all`) and restores `all` on teardown.
No `ip route`/iptables diversion is used — the eBPF does all NAT.

## Deliverables (committed under tests/integration/)

- `tests/integration/run_e2e.sh` — self-contained driver: builds topology +
  cert + TOML, starts the fake server and the real binary, runs the client,
  asserts all four, tears down (idempotent, non-zero exit on any failure).
  Run: `sudo bash tests/integration/run_e2e.sh`.
- `tests/integration/fake_server.py` — TLS server in netns srv; records the
  raw-socket peer IP (assertion 4) and echoes a fixed body.
- `tests/integration/client.py` — TLS client in netns cli; pins/trusts the
  genuine leaf cert as CA (assertion 1), sends PING, checks PONG.
- `tests/integration/debug_setup.sh` — companion that brings up the topology
  only (used during debugging; handy for manual probing).

## Regression check

`cargo test` (host): 8/8 in mymitm + 6/6 in mymitm-common pass (incl.
`proxy::tests::loopback_roundtrip_with_dump` and all `classify_*` tests). The
eBPF object still loads + verifies cleanly with the production (log-free)
build.

## Concerns / caveats
- The L2 auto-detect aliasing corner (source IP 8.0.x.x) noted above.
- Test depends on `route_localnet` (standard for transparent proxies) and a
  return route in the server netns; both are environment setup, not binary
  changes. A real OpenVPN box would already route the VPN client subnet.
- `tcpdump` is unavailable in this env; the server-recorded peer IP is the
  authoritative source-IP proof (as the brief specifies).

## Final-review fixes

Pre-merge whole-branch review cleanups applied to `feat/mymitm-implementation`:

1. **Unbounded UPSTREAM map (blocker).** `mymitm-ebpf/src/main.rs`: changed
   `UPSTREAM` from `aya_ebpf::maps::HashMap` to `LruHashMap`
   (`BPF_MAP_TYPE_LRU_HASH`), keeping `max_entries=1024` and the same
   `insert(&key,&val,0)` / `get(&key)` usage. Now self-evicting so it can never
   fill permanently.
2. `mymitm-common/src/lib.rs`: documented the v1 single-client invariant for the
   ingress un-SNAT match above `classify_eth` (comment only).
3. `mymitm/src/proxy.rs`: `run()` accept loop is now log-and-continue on a
   transient `accept()` error (warn + continue) instead of propagating.
4. `mymitm/src/bpf.rs`: removed the now-unused `BpfPlane::upstream_map()`
   accessor (dead after the LRU change) and cleaned the unused
   `HashMap`/`UpstreamKey`/`UpstreamVal` imports; annotated the `ebpf` field as
   an RAII-only guard.
5. `mymitm/src/proxy.rs`: corrected the misleading "non-blocking" dump-write
   comment to state the writes are synchronous best-effort `std::fs` writes
   (async conversion is a tracked follow-up).

### Re-validation output

```
$ cargo build -p mymitm --release --target x86_64-unknown-linux-musl
    Finished `release` profile [optimized] target(s) in 3.38s
   (eBPF crate compiles to BPF; only pre-existing bpf_obj_name dead-code warning)

$ cargo test -p mymitm --target x86_64-unknown-linux-gnu
running 9 tests
test bpf::tests::loads_attaches_and_cleans_up ... ignored
test config::tests::missing_required_field_errors ... ok
test config::tests::server_name_optional_defaults_none_and_parses ... ok
test config::tests::to_bpf_config_is_network_order ... ok
test config::tests::toml_parses_with_defaults ... ok
test dump::tests::writes_streams_and_index ... ok
test proxy::tests::loads_cert_and_key ... ok
test proxy::tests::pin_verifier_rejects_wrong_cert ... ok
test proxy::tests::loopback_roundtrip_with_dump ... ok
test result: ok. 8 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out

$ cargo test -p mymitm-common --target x86_64-unknown-linux-gnu
running 6 tests
test tests::eth_egress_marked_is_snatted ... ok
test tests::eth_egress_unmarked_untouched ... ok
test tests::eth_ingress_reply_to_client_is_unsnatted ... ok
test tests::tun_egress_reply_is_undnatted ... ok
test tests::tun_ingress_other_client_untouched ... ok
test tests::tun_ingress_target_is_dnatted ... ok
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### End-to-end harness (proves LRU change did not break the data path)

```
$ sudo bash tests/integration/run_e2e.sh
[harness] binary: .../target/x86_64-unknown-linux-musl/release/mymitm
[harness] running TLS client in netns mmcli (src 10.8.0.5 -> 192.168.1.50:443)
----- client output -----
HANDSHAKE_OK peer_cert_subject=((('commonName', 'server.test'),),)
RESPONSE=b'PONG-FROM-SERVER'
CLIENT_OK
-------------------------
ASSERTION 1 PASS: client completed TLS handshake trusting the genuine leaf cert
ASSERTION 2 PASS: application bytes round-tripped (PING/PONG) through the MITM
ASSERTION 3 PASS: dump index + c2s/s2c contain decrypted plaintext (conn_id=conn-00000000)
[harness] fake server recorded peer IP = 10.8.0.5
ASSERTION 4 PASS: fake server recorded peer IP = 10.8.0.5 (source IP preserved via eBPF SNAT)
================================================================
 ALL FOUR ASSERTIONS PASS (incl. source-IP = 10.8.0.5)
================================================================
```

The `UPSTREAM` LRU map is written on `cls_eth_egress` and read on
`cls_eth_ingress` to un-SNAT replies; assertion 4 (peer IP == 10.8.0.5)
directly exercises that lookup, confirming the LRU conversion is data-path-clean.
