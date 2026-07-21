# NTLM dump mode — design

## Goal

For a Microsoft RD Gateway (and any NTLM-authenticated HTTPS target), let the proxy
capture just the **NTLM CHALLENGE + the gateway's machine name** without writing the
huge per-connection raw dumps a real RDP session produces (hundreds of KB of opaque,
doubly-encrypted tunnel).

## Background

The NTLMSSP CHALLENGE_MESSAGE (Type 2) rides the *outer* client↔gateway HTTP auth
(`WWW-Authenticate: NTLM|Negotiate …`), which this proxy decrypts. It lands in the
server→client (`.s2c`) plaintext **before** any WebSocket framing, so `detect_challenge`
(`mymitm/src/ntlm.rs`) recovers the 8-byte ServerChallenge nonce + NetBIOS/DNS computer
& domain names independently of the WS decoder. Verified live against `RDGW1`.

## Config — two composable booleans (the `--flag=true|false` idiom from the config refactor)

| field       | default | meaning                                                             |
|-------------|---------|---------------------------------------------------------------------|
| `raw_dump`  | `true`  | write the per-connection `.c2s` / `.s2c` / `.ws.jsonl` streams       |
| `ntlm_dump` | `true`  | scan `.s2c` for the NTLM challenge → append one line to `ntlm.jsonl` |

CLI overrides mirror `--ws-decode`: `--raw-dump=true|false`, `--ntlm-dump=true|false`
(`Option<bool>` + `ArgAction::Set`; explicit value required; overrides the config file
only when given).

- **NTLM-only** (the RD Gateway testing case) = `raw_dump = false` (leave `ntlm_dump` on).
- `index.jsonl` (the tiny per-connection metadata line) is written regardless, so you
  still see what connected even when there is no challenge.

## Output — `ntlm.jsonl` (one line per connection, first challenge only)

```json
{"conn_id":"conn-00000001","ts":"…Z","client":"10.20.1.5:51616","server":"10.20.2.10:443",
 "server_name":"gw.rdgw.test","server_challenge":"<16 hex chars>","target_name":"RDGW1",
 "nb_computer_name":"RDGW1","nb_domain_name":"RDGW1","dns_computer_name":"RDGW1","dns_domain_name":null}
```

## Implementation

- **config.rs** — `raw_dump` / `ntlm_dump` TOML fields (+ `d_*` defaults), `Cli`
  `Option<bool>` flags, `Settings` fields, `load()` overrides, `test_default()`. Tests in
  the refactor's shape (defaults / TOML disable / CLI parse / bare-flag rejected).
- **dump.rs** — `Dumper::new(dir, DumpOptions { raw_dump, ntlm_dump, server_name })`.
  `open_conn` creates `.c2s` / `.s2c` only when `raw_dump`. `write_s2c` feeds a capped
  (64 KiB) per-connection buffer to `detect_challenge`; on the first hit, append the
  record to `ntlm.jsonl` and stop scanning. `finish` still writes `index.jsonl`.
- **proxy.rs** — gate the `WsTap` on `raw_dump && ws_decode` (no `.ws.jsonl` in
  NTLM-only mode). `write_c2s` / `write_s2c` call sites unchanged.
- **main.rs** — construct `Dumper` with the settings-derived `DumpOptions` (incl.
  `server_name` for the record).

## Scope / non-goals

- Not decoding the WS-framed RDP tunnel for RD Gateway — it is opaque + high-volume, and
  decoding it would reintroduce the exact data explosion this feature avoids. (Correctly
  *classifying* the RD Gateway upgrade — non-GET `RDG_OUT_DATA` + `401→101` NTLM
  round-trip — is a separate deferred `handshake.rs` v2; see the `ws:none` finding.)
- One challenge per connection (the gateway sends one Type 2 per auth handshake).

## Test plan

- **config**: defaults `true`; TOML can disable each; CLI `--raw-dump=false` /
  `--ntlm-dump=false` and space-form `true` parse; bare flag rejected.
- **dump**: `ntlm_dump` writes the record *and* suppresses `.c2s`/`.s2c` when
  `raw_dump=false`; `index.jsonl` still written; first-challenge-only; both-off writes no
  stream/ntlm files.
- **live**: deploy to B with `raw_dump=false`, drive curl + mstsc, confirm `ntlm.jsonl`
  holds the challenge + `RDGW1` and no big per-connection files appear.
