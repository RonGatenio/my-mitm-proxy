# mymitmproxy — Network Protocol Test Coverage & Plan

_Status: P0 IMPLEMENTED (2026-07-21). The P0 harness (§13) ships under
`tests/integration/protocols/` — matrix driver, dump-parser library, and the green-today
rows (HTTP/1.x, keep-alive, streaming, pump, SSE, SigV4, pinning, lifecycle). All runs
collect dumps + report into `tests/reports/`. P1/P2 remain planned. This doc explains the
existing suite and specifies the full application-protocol coverage; it incorporates two
research passes — a survey of mitmproxy's coverage/tests, and a web-protocol + TLS-feature
survey._

---

## 1. Purpose & scope

mymitmproxy is a transparent, source-IP-preserving TLS MITM. Today its tests prove the
**plumbing** (TLS terminate/pin, byte round-trip, source-IP preservation, data-plane
cleanliness) but exercise **no real application protocol** — the e2e harness sends a fixed
`PING-FROM-CLIENT` / `PONG-FROM-SERVER` payload.

This plan adds **application-protocol coverage**. For every protocol a real client might push
through the proxy, answer two questions and hold one invariant:

1. **Does it forward?** — the client gets the correct end-to-end result through the proxy.
2. **Do we dump it correctly?** — the decrypted `.c2s`/`.s2c` blobs, fed to a real parser,
   reconstruct the protocol's messages (**readable and parsable**, per the request).
3. **Invariant — we always forward, even when we cannot dump.** A protocol we cannot parse
   (or deliberately do not intercept) must still reach its destination. A case that fails to
   *forward* is a real defect (flagged RED); a case that forwards but does not dump is a
   documented capability boundary, not a bug.

---

## 2. What mymitmproxy is, for test design

The single most important fact: **the proxy is a pure byte pipe.** `handle_conn`
(`mymitm/src/proxy.rs:249`) terminates the client's TLS, dials upstream, and `select!`-pumps
raw decrypted bytes in ≤16 KiB chunks into per-connection `.c2s`/`.s2c` files plus an
`index.jsonl` (`mymitm/src/dump.rs`). **It never parses any application protocol.**
Consequences that shape the whole plan:

| Property | Where | Test implication |
|---|---|---|
| Byte-level relay; no HTTP/WS/gRPC awareness | `proxy.rs:249-270` | "Dump correct" = an **external** parser re-parses the raw dump. The pipe can't mangle framing, but it also adds no framing metadata. |
| Dumps raw decrypted streams + JSONL index | `dump.rs:26-59` | Dump has **no record of negotiated HTTP/TLS version or ALPN** — offline parsers must infer it. (See §12 recommendation.) |
| Independent half-close propagation in the pump | `proxy.rs:253,265` (`shutdown()` the peer's write on EOF) | Full-duplex / half-close *look* correct — must be proven (this is the classic byte-pipe bug). |
| **No ALPN advertised** on the client-facing leg | `proxy.rs:52-65` (`with_single_cert`, no `alpn_protocols`) | An `h2`/`h3`-preferring client is **not offered** h2/h3 → downgrades to HTTP/1.1, or (strict clients like gRPC) **fails**. |
| **No ALPN** offered on the upstream leg | `proxy.rs:151-160` | Upstream negotiates its default (usually HTTP/1.1). Both legs independently default to h1 → *consistent by accident.* |
| **No client-cert auth** on the client-facing leg | `proxy.rs:62` (`with_no_client_auth`) | **mTLS breaks**: the proxy never sends a CertificateRequest, so the client never presents its cert. |
| Serves a **single fixed leaf** regardless of SNI | `proxy.rs:52-65` (`with_single_cert`) | SNI-based cert selection isn't used → SNI/ECH edge cases behave differently than a forging proxy. |
| Upstream trust = **exact leaf-DER pin** | `proxy.rs:106` | Because we hold + present the **genuine** leaf, **cert pinning / HSTS pass** (a *feature*, not a break — unlike a CA-forging MITM). |
| **TCP + IPv4 only** in the data plane | eBPF `main.rs:126,148,151` (rejects non-`0x0800`, non-v4 nibble, non-TCP) | **QUIC (UDP) and IPv6 are never diverted** → routed past the box untouched (`TC_ACT_OK`). Forward-only, never dumped. |
| Divert matches `dst==server:443`, **ignores TCP flags** | `mymitm-common/src/lib.rs:65` | A **pre-existing** connection's mid-stream packet is DNAT'd to a socket that never saw its SYN → kernel RST → **existing connection terminated**. |
| IPv6 client hard-bail even if one arrived | `proxy.rs:225` | v6 is doubly unsupported (data plane won't divert it; proxy would reject it). |

**Architectural corollary (the big one).** Because the proxy terminates TLS on **both** legs
and relays plaintext verbatim, correctness requires **both legs to speak the same wire
protocol**. Today that holds only because neither leg negotiates ALPN, so both fall to
HTTP/1.1. The moment ALPN is added on one leg only — or the two legs negotiate different HTTP
versions — the pipe would forward HTTP/2 frames into an HTTP/1.1 server and corrupt every
connection. mitmproxy solves this by **negotiating upstream ALPN first and mirroring the
result onto the client leg** (`mitmproxy/addons/tlsconfig.py`); any future h2/h3 support here
must do the same (see §12).

---

## 3. Current test inventory (what already exists)

| Layer | Location | What it proves | Protocol realism |
|---|---|---|---|
| Unit — classify | `mymitm-common/src/lib.rs` tests | DNAT/SNAT/un-NAT decisions, wildcard vs restricted client, NBO | n/a |
| Unit — config | `mymitm/src/config.rs` tests | TOML/CLI parsing, defaults, fwmark!=0, NBO conversion | n/a |
| Unit — dump | `mymitm/src/dump.rs` tests | c2s/s2c blobs + index.jsonl written | raw bytes |
| Unit — proxy | `mymitm/src/proxy.rs` tests | loopback terminate→dial→pump→dump; **DER pin accept/reject** | `PING`/`PONG` |
| E2E — netns | `tests/integration/run_e2e.sh` (+ `client.py`, `fake_server.py`) | Real release binary; TLS handshake+pin, byte round-trip, dump has plaintext, **source-IP preserved** (multi-client eBPF; iproute cleanliness) | `PING`/`PONG` |
| E2E — 3-VM | `tests/vm/` (`run.sh`, `lib.sh`, cloud-init) | Full routing on **kernel 4.15**, src-IP preservation, eBPF+iproute | plain routing + TLS |

**Reusable building blocks (the new suite is a thin layer over these, not a rewrite):**

- **netns topology + idempotent teardown** — `run_e2e.sh` / `debug_setup.sh` build the
  `mmcli`/`mmsrv` netns + `mmvroot`/`mmveth0` veths, set `route_localnet`, load the
  wildcard-client eBPF config, and clean up. The protocol matrix reuses this verbatim.
- **Cert fixtures** — `tests/vm/certs/gen-certs.sh` (CA + leaf) and the `openssl` one-liner in
  `run_e2e.sh`; one leaf is server identity **and** the proxy's served cert **and** the
  upstream pin (`proxy.rs:106`).
- **Real HTTPS server pattern** — `tests/vm/server/tls_server.py` (stdlib, logs peer IP +
  path, returns a known body) is the template for the per-protocol servers; the source-IP +
  body assertions carry over unchanged.
- **Dump inspection** — the VM harness already greps a request marker out of
  `/opt/mymitm/dumps/*` + `index.jsonl` (`run.sh` phase 2). The dump-parser generalises that
  from "marker present" to "the stream fully parses."
- **Output/assert style** — `lib.sh` `pass`/`fail`/`info`/`red`/`green` + colored per-assertion
  lines; the matrix report matches this.
- **Two data planes + real binary** — every harness runs the real musl release binary under
  both `ebpf` and `iproute` (`MODE=` / `--data-plane`); the matrix inherits that switch.

**Gap this plan fills:** none of the above sends real HTTP/WS/SSE/gRPC/etc., so we have **zero
application-protocol coverage** and no dump-parseability assertions beyond "the bytes exist."

---

## 4. Testing model

### Verdict legend

| Symbol | Forward | Dump / parse |
|---|---|---|
| `✓` | client got correct result through the proxy | external parser fully reconstructed the messages |
| `~` | works but degraded (e.g. protocol downgraded) | partial (e.g. handshake yes, frames no; opaque only) |
| `✗` | does **not** reach destination | not captured / not parseable |
| `n/a` | — | dump not applicable (never intercepted) |
| `?` | to be determined by the test | to be determined by the test |
| `*` | conditional — see the row's note | — |

### Failure-class lens

Since the proxy is a byte pipe, *forwarding* is trivially correct for most HTTP-layer
protocols; the real risks cluster into five classes. Each matrix row is tagged with its
dominant class(es) so we can prioritise (the first four threaten **correctness/interception**;
the last threatens only **dump quality**):

- **BYPASS** — escapes the proxy entirely (UDP/QUIC, or the client switches transport). A
  TCP-only proxy is blind to it.
- **HANDSHAKE** — TLS won't complete under interception (mTLS, ECH, unknown groups) — or the
  app protocol needs an ALPN we don't negotiate.
- **SPLIT** — breaks because one client connection becomes a *different* upstream connection
  (state bound to a single TCP/TLS connection).
- **PIPE** — exposes a naive byte-pipe bug (message-alignment assumptions, half-close,
  full-duplex, idle timeout, buffering-before-forward).
- **READABILITY** — forwards fine as bytes, but the *dump* is opaque and needs decoding.

### How each axis is asserted

- **Forward** — the real client asserts a protocol-correct result (HTTP status + body hash,
  WebSocket echo, SSE event count, gRPC response, signature-validated response…). Plus
  (unchanged) the fake server records the **client's** source IP, never the box IP. For BYPASS
  rows, `tshark`/`pyshark` confirms whether a UDP:443 flow survived.
- **Dump parseable** — a Python **dump-parser** reads `<conn>.c2s` / `<conn>.s2c`, runs the
  matching parser (§13), and asserts the reconstructed messages match what was sent/received.
- **Invariant** — every row asserts Forward independently of Dump. Forward-`✗` is RED.

---

## 5. Master coverage matrix

Verdicts are **hypotheses to be confirmed by the tests** (rationale grounded in §2). All rows
are **over TLS on the intercepted `:443`, IPv4**, unless the row says otherwise.

### Group A — HTTP core (HTTP/1.x)

| Case | Class | Fwd | Dump | Notes |
|---|---|---|---|---|
| HTTP/1.1 (GET/POST/HEAD, small+large body) | PIPE | `✓` | `✓` | Baseline; `h11`/`httptools`. |
| HTTP/1.0 (EOF-delimited body) | PIPE | `✓` | `✓` | No Content-Length; body ends at close. |
| Keep-alive / pipelining (≥3 req per conn) | PIPE | `✓` | `✓` | Parser must walk **all** messages in the stream. |
| Chunked + long-lived streaming (unidirectional) | PIPE | `✓` | `✓` | Dechunk; assert no head-of-line stall. |
| **Full-duplex + independent half-close + idle** | PIPE | `✓` | `✓` | The flagship pipe-correctness test; both dirs concurrent, one FIN must not kill the other, no idle timeout (`proxy.rs:253,265`). |
| SSE (`text/event-stream`) | PIPE/READ | `✓` | `✓` | Incremental delivery; **advantage vs mitmproxy** (which buffers+warns). |
| Large binary upload (S3 PUT-style, ~GiB) | PIPE | `✓` | `✓` | Backpressure; ties to SigV4-streaming. |
| Content-Encoding: gzip/deflate/**br**/**zstd** (+ stacking) | READ | `✓` | `✓` | Forward unaffected; dump must decode all four + stacked codings. |
| Range / 206 Partial Content / multipart-byteranges | READ | `✓` | `✓` | Dump must stitch ranges + parse multipart boundary. |
| Trailers / `Expect: 100-continue` / 103 Early Hints / 1xx | PIPE/READ | `✓` | `✓` | Interim responses **before** the final one; relay interim, don't swallow body. |
| CONNECT tunnel + TLS-in-TLS (nested) | BYPASS/PIPE | `✓` | `~` | Inner is a second TLS session → opaque dump unless recursed. |

### Group B — HTTP/2 & HTTP/3 / QUIC

| Case | Class | Fwd | Dump | Notes |
|---|---|---|---|---|
| HTTP/2 via ALPN `h2` | HANDSHAKE/PIPE | `~` | `~→✗` | No ALPN ⇒ client **downgrades to h1**; dumps parse as h1, not h2. |
| HTTP/2 prior-knowledge (no ALPN) | PIPE | `?` | `?` | Works only if upstream **also** accepts prior-knowledge h2; else frame/version mismatch. |
| HTTP/3 / QUIC (UDP :443) | BYPASS | `✓*` | `n/a` | **Never diverted** (UDP). *Forwards only if the box IP-forwards UDP; never dumped. |
| h3 escape via `Alt-Svc` + SVCB/HTTPS DNS RR | BYPASS | `✓*` | `n/a` | Client discovers h3 and jumps to UDP:443. Test = **strip Alt-Svc + block UDP:443** to force TCP. |
| h3 → h2 → h1 **fallback** intercepted | BYPASS→PIPE | `✓` | `✓`/`~` | With QUIC blocked, client must retry over TCP → intercepted; verify via `tshark` no UDP:443 survives. |
| WebTransport over HTTP/3 | BYPASS | `✓*` | `n/a` | Extended CONNECT over QUIC; invisible (UDP). |
| MASQUE CONNECT-UDP / CONNECT-IP (h2 fallback) | BYPASS/PIPE | `✓` | `~` | h3 variant bypasses; **h2 fallback rides TCP:443** as an opaque tunnel carrying UDP/IP. |

### Group C — RPC & realtime

| Case | Class | Fwd | Dump | Notes |
|---|---|---|---|---|
| gRPC native (unary + server/client/bidi stream) | HANDSHAKE | `✗` | `n/a` | Requires ALPN `h2` → handshake fails today. **Biggest gap.** |
| gRPC-Web over HTTP/1.1 | READ/PIPE | `✓` | `✓` | Rides h1.1 → works + dumps. Base64 (`grpc-web-text`) is **not frame-aligned** (accumulate then decode); trailers are a final in-body frame. |
| Connect RPC (unary) | READ | `✓` | `✓` | Plain POST `application/json`/`proto`, **no length-prefix, no trailers** → easiest RPC to dump. |
| WebSocket over HTTP/1.1 | PIPE | `✓` | `✓` | Upgrade (`h11`) then `wsproto`: masking, fragmentation, ping/pong, close codes, permessage-deflate. |
| WebSocket over HTTP/2 (8441) / HTTP/3 (9220) | HANDSHAKE/BYPASS | `✗` | `n/a` | Extended CONNECT needs h2 (blocked) / h3 (bypass). |
| Socket.IO / Engine.IO / long-poll (poll→WS upgrade) | PIPE | `✓` | `✓` | Long-idle, transport upgrade mid-session; same pump stress as full-duplex. |
| MQTT over WebSocket (:443, subprotocol `mqtt`) | PIPE/READ | `✓` | `~` | Long-idle bidirectional binary frames on 443; good pump stress. |
| DoH — DNS-over-HTTPS | READ | `~` | `~` | h1 GET `?dns=` works; h2 POST downgrades. Body = binary DNS message (`dnspython`). |

### Group D — TLS layer

| Case | Class | Fwd | Dump | Notes |
|---|---|---|---|---|
| TLS 1.2 both legs | HANDSHAKE | `✓` | `✓` | Intercept + dump under 1.2. |
| TLS 1.3 both legs | HANDSHAKE | `✓` | `✓` | Default path. |
| **PQ-hybrid ClientHello** (X25519MLKEM768, multi-segment) | HANDSHAKE/PIPE | `?` | `?` | ~1.3–1.6 KB CH spanning 2 TCP segments; rustls must know the group + not assume single-read CH. Current default in Chrome/Cloudflare. |
| Session resumption (ticket / TLS 1.3 PSK) | HANDSHAKE/SPLIT | `?` | `?` | Per-leg; resumed handshake carries **no cert** — verify pin path still holds. |
| 0-RTT / early data | PIPE/SPLIT | `?` | `?` | App bytes before handshake completes + before ALPN known; can't safely relay as 0-RTT (replay). Expect `425`/buffer. |
| Renegotiation (1.2) / KeyUpdate (1.3) mid-stream | PIPE | `?` | `?` | Post-handshake handshake records must not break the pump. |
| **mTLS / client certificate** | HANDSHAKE/SPLIT | `✗` | `n/a` | `with_no_client_auth` ⇒ client identity lost. **Real gap.** |
| **Cert pinning / HSTS / gRPC channel creds** | (positive) | `✓` | `n/a` | Genuine leaf presented ⇒ CA/leaf/SPKI pin + HSTS **pass**. **Differentiator vs forging MITMs.** |
| ECH — Encrypted ClientHello (RFC 9849) | HANDSHAKE | `?` | `?` | Encrypts inner SNI **and** ALPN; single-fixed-cert may sidestep selection, but rustls-server ECH behaviour is TBD. |
| SNI variations (none / IP-literal / SNI≠Host) | HANDSHAKE | `✓` | `✓` | Pin verifier makes IP-SNI fine (`proxy.rs:165`). |

### Group E — connection lifecycle & network

| Case | Class | Fwd | Dump | Notes |
|---|---|---|---|---|
| **Pre-existing** conn (attach mid-flow / missed SYN) | PIPE | `✗` | `n/a` | Flag-agnostic divert (`lib.rs:65`) RSTs it → **terminated**. Accepted/documented. |
| New connection after attach | PIPE | `✓` | `✓` | Fresh SYN → normal interception (companion to the row above). |
| Proxy restart mid-connection | PIPE | `✗`→`✓` | — | In-flight intercepted conns drop; new ones fine; no wedged state. |
| **IPv6** client (any protocol) | BYPASS | `✓*` | `n/a` | Not diverted (v4-only data plane + `proxy.rs:225`). *Routed un-intercepted; never dumped. |
| Plain HTTP → intercepted `:443` | HANDSHAKE | `✗` | `n/a` | TLS acceptor rejects cleartext ClientHello. |
| Plain HTTP → non-intercepted port | — | `✓` | `n/a` | Not matched by divert → routed normally, never seen. |
| Non-HTTP TLS app-proto on the configured port (opaque) | READ | `✓` | `~` | Protocol-agnostic pipe ⇒ forward + **opaque** dump (raw hexdump); proves generality. |
| **SSH** (non-TLS) on the path | HANDSHAKE | `✓`/`✗` | `n/a` | Not TLS — proxy must passthrough/reject gracefully, **not choke**. |

### Group F — request integrity / auth

| Case | Class | Fwd | Dump | Notes |
|---|---|---|---|---|
| SigV4 header auth (GET + PUT) | integrity | `✓` | `✓` | Signature validates end-to-end ⇒ byte-exact request. |
| SigV4 presigned query | integrity | `✓` | `✓` | Query-string auth survives. |
| SigV4 **streaming** (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`) | PIPE | `✓` | `✓` | Per-chunk signatures validate (ties to streaming). |
| Legacy SigV3 | integrity | `✓` | `✓` | Older scheme survives. |
| Azure SharedKey / GCP HMAC / RFC 9421 msg-sig | integrity | `✓` | `✓` | Header-integrity holds. |
| **NTLM / Negotiate / SPNEGO / Kerberos** (connection-bound) | SPLIT | `?` | `~` | Auth binds to one TCP connection; 1-upstream-per-client *should* survive — must verify no 401-loop / auth-bleed. |

---

## 6. Per-case test specifications

Each spec lists **server / client / traffic / forward assertion / dump assertion / expected
verdict + why**. Tooling in §13. (Referenced by name; the matrix in §5 is the at-a-glance view.)

### 6.1 HTTP/1.1 and HTTP/1.0 (baseline)
Server nginx/aiohttp (TLS, harness leaf); client `curl --http1.1`/`--http1.0` + a scripted
Python client. Traffic: GET (small+large), POST, HEAD, keep-alive ≥3 requests, chunked
response, `Connection: close` (h1.0 EOF body). Forward: status + body SHA-256; src IP ==
client. Dump: `h11`/`httptools` reconstructs every message; for keep-alive assert the parser
walks all of them. Verdict `✓`/`✓` — the reference everything else is compared to.

### 6.2 Pump correctness — full-duplex, half-close, idle
The most important *correctness* test for a byte pipe. A slow bidirectional echo: client
uploads while the server streams down; then the client half-closes (FIN c2s) while the server
keeps sending; then an idle-but-open period. Forward: both directions flow concurrently, the
half-close reaches the server without tearing down s2c, and an idle stream is **not** timed
out. Grounded in `proxy.rs:253,265` (on `Ok(0)` it shuts down only the *peer's* write). Dump:
both `.c2s` and `.s2c` reassemble fully. Verdict `✓`/`✓` (prove it; this is where naive pipes
fail).

### 6.3 HTTP/2
Server nginx `http2` (ALPN `h2`); client `curl --http2` and `--http2-prior-knowledge`.
Expected: with ALPN the proxy offers no `h2` → curl **downgrades to h1.1** (forward `~`, dump
parses as h1). Prior-knowledge succeeds only if upstream also accepts it on the same bytes —
capture the actual outcome. Dump: attempt `h2`+`hpack`+`hyperframe`; expect **fail-as-h2,
parse-as-h1**, which is the finding. Flips to `✓`/`✓` (HEADERS/DATA/SETTINGS/flow-control/
multiplexed streams) once consistent-ALPN byte-relay lands (§12).

### 6.4 HTTP/3 / QUIC (and forced fallback)
Server: an h3 server (nginx-quic/Caddy/aioquic) on UDP:443 **and** a TCP h2/h1 server on the
same name. Client: `curl --http3` (fallback-capable) + a QUIC-only client (aioquic).
Expected: QUIC is UDP → eBPF `TC_ACT_OK` → **not diverted**. Assert (a) with UDP forwarding on,
the QUIC-only client completes **un-intercepted** (`✓`/`n/a`); (b) **strip `Alt-Svc` / SVCB
discovery and block UDP:443**, and the fallback client retries over TCP → intercepted+dumped;
`tshark` confirms **no UDP:443 flow survived**. h3 is invisible **by design**.

### 6.5 WebSocket
Over h1.1: server `websockets`/aiohttp, client `websockets`; exercise text+binary, client→
server **masking**, **fragmentation**, **ping/pong**, **close** codes, **permessage-deflate**.
Forward: echo round-trip. Dump: `h11` for the `101` handshake, then `wsproto` per direction
(c2s masked, s2c unmasked); assert opcodes+payloads. `✓`/`✓`. Over h2/h3 (RFC 8441/9220):
blocked by the h2/h3 gaps — include so they flip green later.

### 6.6 Server-Sent Events
Server aiohttp/`sse-starlette` emitting an unbounded `text/event-stream` (`data:`/`id:`/
`event:`/`: comment`/retry). Client `curl -N`/`httpx` reads N events then closes. Forward:
events arrive **incrementally** (assert time-spread, not one blob). Dump: `h11` headers +
event-stream line parser over `.s2c`. `✓`/`✓` — passing is a **differentiator** (mitmproxy
buffers+warns).

### 6.7 gRPC family
**Native gRPC:** server Python `grpc` (unary + 3 streaming modes), client `grpcurl`/Python.
Expected **`✗`** — requires ALPN `h2`; assert the concrete failure (`UNAVAILABLE`/handshake).
Flips to `✓`/`✓` with h2 (dump = h2 frames → gRPC length-prefixed → protobuf, honouring
`grpc-encoding`). **gRPC-Web:** Envoy `grpc_web` / `grpcwebproxy`; rides h1.1 → works+dumps;
parse base64 (`grpc-web-text`, **not frame-aligned**) or binary frames + in-body trailer frame.
**Connect RPC** (bonus): unary plain POST, no framing/trailers → dumps like ordinary HTTP.

### 6.8 Connection lifecycle (your "missed SYN")
**Pre-existing / missed SYN:** establish a real TLS connection **before** the proxy attaches,
then start it; assert the existing connection is **reset** (broken pipe/RST) — grounded in the
flag-agnostic divert (`lib.rs:65`) DNAT'ing a mid-stream packet to a socket that never saw the
SYN; then assert a **new** connection is intercepted normally. **Proxy restart:** kill+restart
mid-connection; in-flight drops, new succeeds (complements iproute cleanliness checks).
**Reuse:** many requests over one connection; parser walks all.

### 6.9 IPv6
Bring up dual-stack in the netns harness; client → server over IPv6:443. Expected: eBPF never
matches (v4-only `meta`) → `TC_ACT_OK` → **routed un-intercepted** (forward `✓` if the box
forwards v6, dump `n/a`). Document that v6 interception is **unimplemented** and that this is
correct "forward even if we don't dump" behaviour.

### 6.10 TLS layer
Force TLS 1.2 and 1.3 (both legs); a PQ-hybrid client (`openssl s_client -groups
X25519MLKEM768`, OpenSSL 3.5+) to prove multi-segment ClientHello is handled; resumption
(`-sess_out`/`-sess_in`); 0-RTT (`-early_data`); mTLS (`-cert`/`-key` vs `ssl_verify_client on`
→ expect fail); a **pinned** client (assert it passes — differentiator); ECH (capture outcome);
SNI variants. Verdicts per §5 Group D.

### 6.11 Plain HTTP & non-HTTP
Plain → `:443`: TLS acceptor rejects (documented `✗`). Plain → other port: routed, unseen.
Non-HTTP TLS app-proto on the configured port: opaque forward + raw-hexdump dump. SSH on the
path: proxy must passthrough/reject gracefully, not choke.

---

## 7. Payload readability depth ladder

"Dump correctly" has depth. L1 is framing; deeper levels make the body human-readable,
mirroring mitmproxy's ~21 content views. Report the **highest level achieved** per row.

| Level | What | Tooling | Applies to |
|---|---|---|---|
| L1 Framing | HTTP/WS/gRPC message boundaries reconstruct | h11, wsproto, h2, grpc framing | all intercepted rows |
| L2 De-transfer | dechunk, de-`Content-Length`, EOF bodies | h11/httptools | HTTP |
| L3 De-compress | gzip, deflate, **br**, **zstd** (+ stacked) | zlib, brotli, zstandard | Content-Encoding |
| L4 Body decode | JSON, urlencoded/multipart forms, protobuf, images, XML/HTML, MsgPack | stdlib, protobuf, requests-toolbelt | JSON APIs, forms, gRPC(-Web) |
| L5 Domain decode | gRPC→protobuf (w/ `.proto`), DoH→DNS message, MQTT packets | grpc, dnspython, mqtt codec | RPC / DoH / MQTT |

---

## 8. Extended web protocols — ranked for THIS proxy

Ranked by importance (byte-pipe, TLS-terminating, connection-splitting, TCP/IPv4/443, no
ALPN). All appear in the §5 matrix; this is the priority ordering + the "web vs adjacent" call.

1. **ALPN negotiation/mirroring** — upstream of almost everything; the mechanism h2/h3/gRPC
   ride on. *(Gap #1 in §12.)*
2. **HTTP/3 / QUIC transport escape** via Alt-Svc + SVCB/HTTPS RR — can't intercept; test the
   forced-fallback story.
3. **mTLS / client certificates** — explicit breakage (`with_no_client_auth`).
4. **Cert pinning / HSTS** — *positive* here (genuine leaf) — a headline differentiator.
5. **CONNECT + TLS-in-TLS (nested)** — inner TLS is opaque; detect + recurse/forward.
6. **Half-close / full-duplex / idle pumping** — the most common byte-pipe bug (§6.2).
7. **TLS resumption / 0-RTT / renegotiation / KeyUpdate** — split-state + pipe ordering.
8. **ECH (RFC 9849)** — encrypts SNI+ALPN; emerging; capture graceful behaviour.
9. **PQ-hybrid ClientHello fragmentation** — multi-segment CH; current default traffic.
10. **WebSocket-over-h2/h3, WebTransport, MASQUE** — h2 (gap) / h3 (bypass); MASQUE h2-fallback
    is an opaque tunnel worth one test.
11. **gRPC-Web / Connect RPC** — the dumpable RPCs (h1.1).
12. **Content-Encoding br/zstd, Range/206, trailers/1xx/103** — readability/reassembly only.
13. **NTLM / Negotiate / SPNEGO** — flagship connection-bound (SPLIT) auth.
14. **Socket.IO/Engine.IO/long-poll, MQTT-over-WS, DoH** — realtime + web-transport DNS.

**Web vs adjacent (as asked).** *Genuine web:* gRPC-Web, Connect RPC, WS-over-h2/h3,
WebTransport, long-poll/Socket.IO/Engine.IO, MQTT-over-WebSocket, DoH, and HTTP-core features
(Content-Encoding, Range, trailers, 100-continue, 103/1xx, CONNECT, NTLM/Negotiate). ALPN /
Alt-Svc / SVCB / ECH / SNI / resumption / 0-RTT / PQ are web **transport plumbing** (TLS layer)
— not app protocols, but *where this proxy actually breaks*. *Adjacent (non-web or non-443):*
DoT, DoQ, MQTT-over-TLS(8883), SMTP/IMAP/POP/Postgres/MySQL/Redis/AMQP/STOMP-over-TLS, SSH,
MASQUE — test only as "opaque TLS byte-preserving forward" smoke tests (and SSH as "not TLS —
don't choke").

---

## 9. Request-integrity / auth suite ("don't break SigV3/SigV4 etc.")

A signed request is the strongest transparency probe: AWS SigV4 hashes a canonical request
(method, path, **sorted headers with exact names/casing**, signed-headers list, payload hash).
If it still validates after the proxy, the proxy provably did not reorder headers, change
casing, alter the body, or re-chunk. Any silent transcoding (e.g. a future h2↔h1 bridge) breaks
these — which is exactly why they're valuable regression guards.

| Test | How | Asserts |
|---|---|---|
| SigV4 header auth (GET+PUT) | boto3 / `aws s3` vs MinIO or `moto` through the proxy | server accepts signature → byte-exact request |
| SigV4 presigned URL | presigned GET/PUT via curl | query-auth survives |
| SigV4 streaming payload | S3 multipart / `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` | per-chunk signatures validate |
| SigV3 (legacy) | SigV3 signer vs validating endpoint | older scheme survives |
| Azure SharedKey / GCP HMAC / RFC 9421 | signer + validator pair | header-integrity holds |
| NTLM / Negotiate (connection-bound) | `curl --ntlm`/`--negotiate` vs Apache `mod_auth_gssapi` | connection-scoped auth survives the split (no 401-loop / auth-bleed) |

Most AWS S3 SDK traffic is HTTP/1.1 → **expected `✓`** today. A signer that defaults to h2 will
surface the ALPN gap instead — itself a useful signal.

---

## 10. Borrowed HTTP edge cases (from mitmproxy's suite)

mitmproxy explicitly tests these; we add them (h1 now, h2 later) because a byte pipe must not
corrupt them and the dump parser must handle them: **CONNECT** + nested TLS; **`Upgrade`**
(WS/h2c) + upgrade-denied; **`Expect: 100-continue`** and **1xx** (incl. **103 Early Hints**);
**trailers**; **HEAD** (no body / no terminating chunk); **Content-Length vs Transfer-Encoding
conflict** (smuggling shapes — the dump parser should flag ambiguity, not silently mis-parse);
**pipelining / keep-alive / reuse-after-close**; **`Alt-Svc`** advertising h3.

---

## 11. Known gaps & findings (the payoff)

Ranked by impact. **Gaps** = defects/limitations; **wins** = properties the matrix proves in
our favour.

**Gaps**
1. **No ALPN on either TLS leg** → h2/h3 downgrade-or-die; **gRPC + WS-over-h2 blocked**; h2
   never dumped as h2. _Fix:_ negotiate upstream ALPN first, then **mirror it onto the client
   leg** (mitmproxy's strategy) — a **consistent-ALPN byte-relay** that keeps the pipe design
   and unblocks h2/gRPC without teaching the proxy to parse.
2. **Version-mismatch hazard** — ALPN on one leg only would relay h2 frames into an h1 peer.
   The mirror in (1) is the guard; add a test that fails loudly on any per-connection
   leg-version mismatch.
3. **mTLS unsupported** (`with_no_client_auth`) → client-cert services can't traverse. _Fix:_
   optional client-cert request + upstream re-presentation, or detect + passthrough/fail loud.
4. **IPv6 unimplemented** (v4-only data plane + `proxy.rs:225`) → v6 forward-only.
5. **QUIC/UDP never intercepted** (by design) → optionally block UDP:443 + strip Alt-Svc/SVCB
   to force h3→TCP fallback into the intercepted path when full visibility is wanted.
6. **Pre-existing connections are reset** on attach (flag-agnostic divert) — documented; a
   graceful-adoption change is a design decision, not a bug.
7. **Dump carries no protocol/version metadata** → offline parsers must guess. _Fix:_ record
   negotiated ALPN / HTTP version / TLS version per connection in `index.jsonl` (`dump.rs:47`)
   so the dump is self-describing and parsing is deterministic.
8. **Emerging TLS handshakes** (ECH RFC 9849, PQ-hybrid multi-segment CH) — verify rustls
   accepts current-generation ClientHellos and the proxy degrades gracefully where it can't.

**Wins to prove**
- **Cert pinning / HSTS pass** (genuine leaf) — the core value prop; unique vs forging MITMs.
- **Source-IP preserved** end-to-end (already tested; keep asserting it per protocol).
- **Streaming/SSE/full-duplex** handled natively by the byte pipe — better than mitmproxy's
  buffering.

---

## 12. Harness design (approved: extend the netns harness, Python)

Reuse and generalise `tests/integration/`; keep the bash-driver + Python-client/server style;
add real per-protocol clients/servers and a Python **dump-parser** library.

### Layout
```
tests/integration/
  run_e2e.sh                 # existing plumbing test (unchanged)
  protocols/
    run_matrix.sh            # driver: sets up netns once, iterates cases, prints the §5 matrix
    cases/                   # one module per protocol: server cmd, client cmd, assertions
      http1.py http2.py http3.py websocket.py sse.py streaming.py pump.py
      grpc.py grpcweb.py connectrpc.py sigv4.py tls.py lifecycle.py ipv6.py ntlm.py ...
    dumpparse/               # reusable dump parsers (the "dump correct?" axis)
      http1.py (h11)  http2.py (h2/hpack)  ws.py (wsproto)
      grpc.py (framing+protobuf)  eventstream.py  encodings.py (gzip/br/zstd)  dns.py
    report.py                # emits the coverage matrix + highest readability level per row (+ JSON)
```

### Per-protocol tooling
| Protocol / feature | Server | Client | Dump parser / verifier |
|---|---|---|---|
| HTTP/1.x | nginx / aiohttp | curl, python | `h11` / `httptools` |
| HTTP/2 | nginx `http2` / hypercorn | `curl --http2` | `h2`+`hpack`+`hyperframe` |
| HTTP/3 + fallback | nginx-quic / Caddy / aioquic | `curl --http3`, aioquic | fwd-only; `tshark`/`pyshark` for UDP:443 |
| WebSocket (h1) | `websockets` / aiohttp | `websockets` | `h11` + `wsproto` |
| SSE | `sse-starlette` / aiohttp | `curl -N` / `httpx` | `h11` + event-stream lines |
| gRPC | python `grpc` | `grpcurl` | `h2` + grpc framing + protobuf |
| gRPC-Web / Connect | Envoy / `grpcwebproxy` / connecpy | grpc-web, curl | `h11` + base64/binary frames / plain JSON |
| SigV4/3 · NTLM | MinIO / `moto` · Apache `mod_auth_gssapi` | boto3 / `aws` · `curl --ntlm` | server-side signature/auth validation |
| DoH | DoH server (bind/knot/py) | `curl --doh-url` / `kdig +https` | `h11`/`h2` + `dnspython` |
| MQTT (WS + 8883) | mosquitto (TLS) | paho-mqtt | mqtt codec |
| TLS matrix | `openssl s_server -Verify` / nginx `ssl_verify_client` | `openssl s_client` (`-tls1_2/3`, `-sess_in/out`, `-early_data`, `-alpn`, `-groups X25519MLKEM768`, `-cert/-key`, `-ech`); tlsfuzzer | handshake capture via `tshark`/scapy TLS |
| Content-Encoding · Range | nginx / Caddy | `curl --compressed` / `curl -r` | zlib/brotli/zstandard · `requests-toolbelt` MultipartDecoder |
| Non-HTTP TLS · SSH | postgres/redis (TLS) · sshd | native client · ssh | opaque hexdump · "not-TLS, don't choke" assert |

Reuses `run_e2e.sh`'s netns topology (`mmcli`/`mmsrv` + `mmvroot`/`mmveth0` veths +
`route_localnet`), the wildcard-client eBPF config, `tests/vm/certs/gen-certs.sh` for the
CA+leaf, the `tls_server.py` server pattern, and the source-IP assertion — so the matrix is a
thin protocol layer over proven plumbing, not a new harness. The 3-node VM harness
(`tests/vm/run.sh`) stays as-is for kernel-version/routing validation; the protocol matrix can
optionally be driven inside its phase-2 `proxy` step for a **real-kernel-4.15** pass. Installs
tooling at start (matching the "local root, rich tooling" decision), **skips-with-reason** any
tool it can't install, and never lets a missing tool masquerade as a pass. **mitmproxy** can be
run alongside as a reference oracle for expected interception behaviour.

### Output
A printed matrix identical in shape to §5 (Class / Fwd / Dump / readability-level per row) plus
a machine-readable JSON so results can be diffed over time and eventually CI-gated.

---

## 13. Phasing (for the later implementation session)

- **P0 — foundation + safety net (all expected green today):** matrix driver + dump-parser lib;
  HTTP/1.1, HTTP/1.0, keep-alive, chunked/streaming, **pump correctness (full-duplex/half-close/
  idle)**, SSE; connection lifecycle (pre-existing SYN, restart); SigV4 header+presigned;
  cert-pinning/HSTS win.
- **P1 — gaps made visible:** HTTP/2 (downgrade proof), gRPC (fail proof), gRPC-Web + Connect
  (works), WebSocket/h1, IPv6 (forward-only), QUIC (not-intercepted + forced fallback), mTLS
  (fail proof), TLS 1.2/1.3 + PQ-hybrid + resumption/0-RTT, content-encodings, SigV4-streaming +
  SigV3, NTLM.
- **P2 — breadth + readability + emerging:** DoH, MQTT-over-WS, non-HTTP-TLS opaque + SSH,
  Range/206, Socket.IO/long-poll, MASQUE opaque tunnel, ECH behaviour, readability L3–L5,
  borrowed edge cases; then **re-run** P1's h2/gRPC/WS-h2 rows after consistent-ALPN byte-relay
  lands (they should flip green).

Correctness-threatening classes (BYPASS/HANDSHAKE/SPLIT/PIPE) come before READABILITY-only work.

---

## 14. Appendix — mitmproxy parity

Source: their `mitmproxy/proxy/layers/` + `test/mitmproxy/proxy/layers/`.

- **Fully parses:** HTTP/1, HTTP/2, HTTP/3, WebSocket, DNS, DTLS; **content views** for JSON,
  XML/HTML, protobuf, gRPC, MsgPack, GraphQL, WBXML, JS, CSS, forms, images, zip, MQTT,
  Socket.IO. **No SSE view, no CSV.**
- **ALPN:** negotiates upstream first, mirrors to client; strips `h2` if disabled; **forces
  http/1.1 for CONNECT** (h2 CONNECT unsupported).
- **QUIC/h3:** auto-**passthrough** when the interception cert is untrusted; tests fragmented
  QUIC ClientHello parsing.
- **Where we differ by design:** we are a **byte pipe**, not a parser — our "coverage" is
  (forward + external-parse); we intercept **only TLS-over-TCP:443 on IPv4**; we **preserve the
  client source IP** (mitmproxy cannot); and because we present the **genuine leaf**, **pinning
  and HSTS pass** (mitmproxy's forged cert breaks them). SSE/full-duplex streaming is a place we
  can be *better* than mitmproxy.
- **Edge cases we borrow:** CONNECT, Upgrade, 100-continue/1xx/103, trailers, HEAD, CL/TE
  conflicts, keep-alive/pipelining, h1↔h2 interop, WS masking/fragmentation/ping/close/deflate,
  Alt-Svc.
