# NTLM dump mode — design

## Goal

For a Microsoft RD Gateway (and any NTLM-authenticated HTTPS target), let the proxy
capture the **full NTLM exchange for one connection — the server CHALLENGE, the
gateway's machine name, and the client's RESPONSE — grouped into a single record** that
yields a crackable net-NTLMv2 hash (hashcat `-m 5600`), without writing the huge
per-connection raw dumps a real RDP session produces (hundreds of KB of opaque,
doubly-encrypted tunnel).

## Background

The NTLM handshake rides the *outer* client↔gateway HTTP auth, which this proxy
decrypts, and it is **split across both directions**:

- **Type-2 CHALLENGE** — server→client (`.s2c`), `WWW-Authenticate: NTLM|Negotiate …`.
  Carries the 8-byte ServerChallenge nonce + the gateway's NetBIOS/DNS computer & domain
  names. Recovered by `detect_challenge` (`mymitm/src/ntlm.rs`).
- **Type-3 AUTHENTICATE** — client→server (`.c2s`), `Authorization: NTLM|Negotiate …`.
  Carries the account `username`/`domain`/`workstation` and the NTLMv2 response
  (`NtChallengeResponse` = NTProofStr ‖ blob). Recovered by `detect_authenticate`.

Both land in the plaintext **before** any WebSocket framing. Pairing the ServerChallenge
(Type-2) with the NTProofStr + blob (Type-3) from the same connection produces a
hashcat-ready **net-NTLMv2** hash (`user::domain:challenge:ntproof:blob`, mode 5600).
Verified live against `RDGW1`.

## Config — two composable booleans (the `--flag=true|false` idiom from the config refactor)

| field       | default | meaning                                                             |
|-------------|---------|---------------------------------------------------------------------|
| `raw_dump`  | `true`  | write the per-connection `.c2s` / `.s2c` / `.ws.jsonl` streams       |
| `ntlm_dump` | `true`  | scan the decrypted streams for the NTLM exchange → one `ntlm.jsonl` line |

CLI overrides mirror `--ws-decode`: `--raw-dump=true|false`, `--ntlm-dump=true|false`
(`Option<bool>` + `ArgAction::Set`; explicit value required; overrides the config file
only when given).

- **NTLM-only** (the RD Gateway testing case) = `raw_dump = false` (leave `ntlm_dump` on).
- `index.jsonl` (the tiny per-connection metadata line) is written regardless, so you
  still see what connected even when there is no NTLM.

## Output — `ntlm.jsonl` (one grouped line per connection)

A connection's Type-2 (from `.s2c`) and Type-3 (from `.c2s`) are held and emitted as a
**single** record — never two lines. It is flushed **as soon as authentication completes**
(the gateway's `101`/`2xx` answering the client's Type-3), so a live, long-lived RDP
session is captured immediately and the record survives a mid-session proxy kill. A
connection that closes without a completed auth (challenge-only, or a denied attempt) is
flushed at connection close instead:

```json
{"conn_id":"conn-00000006","ts":"…Z","client":"10.20.1.5:51616","server":"10.20.2.10:443",
 "server_name":"gw.rdgw.test",
 "endpoint":"RDG_OUT_DATA /remoteDesktopGateway/","rdg_user_id":"Administrator@RDGW1",
 "username":"Administrator","domain":"RDGW1","workstation":"RON-SWEET-PC",
 "server_challenge":"<16 hex>","nt_proof_str":"<32 hex>","blob":"<hex>",
 "net_ntlmv2":"Administrator::RDGW1:<challenge>:<ntproof>:<blob>",
 "target_name":"RDGW1","nb_computer_name":"RDGW1","nb_domain_name":"RDGW1",
 "dns_computer_name":"RDGW1","dns_domain_name":null,
 "www_authenticate":"Negotiate <base64 Type-2 as sent>",
 "authorization":"Negotiate <base64 Type-3 as sent>",
 "auth_result":"success"}
```

Field groups:

| group | fields | source |
|-------|--------|--------|
| connection | `conn_id` `ts` `client` `server` `server_name` | proxy |
| request context | `endpoint` (method + path), `rdg_user_id` (decoded `RDG-User-Id` UPN) | `.c2s` headers |
| net-NTLMv2 | `username` `domain` `workstation` (Type-3) · `server_challenge` (Type-2) · `nt_proof_str` `blob` (Type-3) · `net_ntlmv2` (assembled `-m 5600` line) | both |
| gateway machine name | `target_name` `nb_computer_name` `nb_domain_name` `dns_computer_name` `dns_domain_name` | Type-2 |
| raw carriers | `www_authenticate` (Type-2), `authorization` (Type-3) — scheme + verbatim base64 as sent | both |
| outcome | `auth_result` — `"success"` (challenge → `101`/`2xx`) or `"denied"`; set only when a Type-3 was captured | `.s2c` status |

`net_ntlmv2` is present only when **both** halves were seen. A challenge-only connection
(e.g. a client that never submits credentials) records the Type-2 fields with the Type-3
fields `null`. The raw carriers preserve the full wire messages (negotiate flags,
timestamp, AV_PAIRs, MIC) for downstream NTLM tooling; `null` when found as raw bytes
rather than in a header.

## Implementation

- **config.rs** — `raw_dump` / `ntlm_dump` TOML fields (+ `d_*` defaults), `Cli`
  `Option<bool>` flags, `Settings` fields, `load()` overrides, `test_default()`.
  (Unchanged by the grouping work.)
- **ntlm.rs** — alongside `detect_challenge` (Type-2), add `detect_authenticate`
  (Type-3) → `NtlmResponse { domain, username, workstation, nt_proof_str, blob, scheme,
  token }`. `parse_authenticate` reads the AUTHENTICATE_MESSAGE fields (DomainName@0x1c,
  UserName@0x24, Workstation@0x2c via `read_field_str`; NtChallengeResponse@0x14 via a
  new `read_field_bytes`, split NTProofStr[0..16] ‖ blob). Reuses `auth_tokens` /
  `base64_decode` for the `NTLM`/`Negotiate` carriers.
- **dump.rs** — `open_conn` creates `.c2s`/`.s2c` only when `raw_dump`. Both directions
  accumulate a bounded (64 KiB) per-connection prefix (`ntlm_c2s_buf` / `ntlm_s2c_buf`)
  whenever `ntlm_dump` is on. The grouped record is emitted **once** (guarded by
  `ntlm_emitted`) either **eagerly** — when a `.s2c` chunk carries a `101`/`2xx` and both
  Type-2 + Type-3 are in hand — or as a **fallback at `finish()`** for a
  challenge-only/denied connection. Emitting parses both prefixes (`detect_challenge` on
  s2c, `detect_authenticate` on c2s), derives `endpoint` / `rdg_user_id` / `auth_result`,
  assembles `net_ntlmv2`, and appends **one** line to `ntlm.jsonl`. `index.jsonl` still
  written.
- **proxy.rs** — gate the `WsTap` on `raw_dump && ws_decode`. `write_c2s`/`write_s2c`
  call sites unchanged (both already pumped every connection; the c2s NTLM accumulation
  rides along).
- **main.rs** — construct `Dumper` with the settings-derived `DumpOptions`.

## Scope / non-goals

- Not decoding the WS-framed RDP tunnel for RD Gateway — it is opaque + high-volume, and
  decoding it would reintroduce the exact data explosion this feature avoids. (Correctly
  *classifying* the RD Gateway upgrade — non-GET `RDG_OUT_DATA` + `401→101` NTLM
  round-trip — is a separate deferred `handshake.rs` v2; see the `ws:none` finding.)
- One grouped record per connection (the gateway runs one Type-2/Type-3 handshake per
  connection), emitted as soon as auth succeeds — or at connection close for a
  challenge-only/denied connection.
- `net_ntlmv2` cracking is offline; the proxy only captures — it does not attempt or
  verify the hash.

## Test plan

- **ntlm**: `detect_authenticate` recovers username/domain/workstation + NTProofStr/blob
  from a Type-3 in raw bytes, `NTLM <b64>`, and SPNEGO `Negotiate <b64>`; ignores Type-1
  / Type-2.
- **dump**: a challenge (s2c) + response (c2s) on one connection produce exactly **one**
  `ntlm.jsonl` line carrying the assembled `net_ntlmv2`; challenge-only still records the
  Type-2 fields with Type-3 fields null; `.c2s`/`.s2c` suppressed and `index.jsonl` still
  written when `raw_dump=false`; both-off writes no stream/ntlm files; on a successful
  auth the record is flushed on the `101` (before close) and not duplicated at close.
- **live**: deploy to B with `raw_dump=false`, drive mstsc, confirm one grouped record
  with `net_ntlmv2` + `RDGW1` and no big per-connection files.
