# Protocol Coverage Matrix — P0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the protocol-coverage test harness (bash driver + Python case modules + a reusable Python dump-parser library + matrix report) and land every P0 row from `tests/PROTOCOL_COVERAGE.md` §13 — the rows expected to pass today (HTTP/1.1, HTTP/1.0, keep-alive, chunked/streaming, pump full-duplex/half-close/idle, SSE, SigV4 header+presigned, cert-pinning/HSTS, connection lifecycle).

**Architecture:** A thin protocol layer over the *existing* proven netns plumbing. Task 1 extracts `run_e2e.sh`'s topology into a sourceable `lib.sh`; a new `run_matrix.sh` brings that topology up once and iterates cases sequentially (single-target proxy → one server at a time). Each case is one Python module exposing a uniform `server` / `client` / `parse` CLI; the "dump correct?" axis is a reusable pure-Python `dumpparse/` library (real parsers over the raw `.c2s`/`.s2c` bytes). A `manifest.tsv` holds each row's expected `(Fwd, Dump)` verdict; `report.py` compares actual-vs-expected and emits the §5-shaped matrix + JSON.

**Tech Stack:** bash (driver, reusing the netns/veth/eBPF plumbing), Python 3 stdlib (servers/clients — matches existing `fake_server.py`/`client.py`), `h11` (HTTP/1 dump parsing), `botocore` (SigV4 sign+validate), `pytest` (unit tests for the pure-Python parsers/report/sigv4 logic). The real static musl `mymitm` release binary under both data planes.

## Global Constraints

- **Test-harness only — no `mymitm` Rust code changes in this plan.** Red rows are documented gaps, not defects. (User decision.)
- **Linux + root + WSL2.** Every matrix run needs network namespaces + eBPF/iproute → `sudo`, from the repo root, inside WSL2 on the Windows box. Cross-ref the `mymitm-testing` and `wsl-shell` skills.
- **Rebuild the release binary first:** `cargo build -p mymitm --release` → `target/x86_64-unknown-linux-musl/release/mymitm`. `.cargo/config.toml` pins the musl target (no `--target` flag). Harnesses do not rebuild.
- **Two data planes.** Everything works under `MODE=ebpf` (default) and `MODE=iproute`, exactly like `run_e2e.sh`. `local_addr` = `10.8.0.1` (ebpf) / `127.0.0.1` (iproute).
- **Single-target proxy.** The proxy has one `target_server_ip = 192.168.1.50`, `target_server_port = 443`. Cases run **sequentially**: each brings up its own server at `192.168.1.50:443`, its own proxy instance (fresh dump dir), its own client.
- **Always-forward invariant.** Every case asserts **Forward** independently of **Dump**. A row's expected verdict lives in `manifest.tsv`; a forward-`fail` is a test PASS **only** for rows whose `exp_fwd=fail` (documented gaps). Any deviation from the expected verdict is a matrix FAIL.
- **Dump carries no version metadata** (`dump.rs` records only `conn_id`/`client`/`server`/timestamps). Offline parsers infer framing from the bytes.
- **One leaf cert** is server identity **and** the proxy's served cert **and** the upstream DER pin (`proxy.rs:106`). Generated once per run (`gen_cert`), reused everywhere.
- **Skip-with-reason, never skip-as-pass.** A missing tool/dep marks the row `SKIP <reason>` in the report; it is never silently counted green.
- **Source-IP preservation** is re-asserted per simple case (server records peer IP; client IP must appear, box IP `192.168.1.10` must not).

## Verdict tokens (used in `manifest.tsv`, `results.tsv`, and `report.py`)

| token | Fwd meaning | Dump meaning | display |
|---|---|---|---|
| `ok` | client got correct end-to-end result | parser fully reconstructed messages | `✓` |
| `degrade` | works but downgraded | partial (handshake only / opaque) | `~` |
| `fail` | did **not** reach destination | not captured / not parseable | `✗` |
| `na` | — | dump not applicable | `n/a` |

---

## Test report folder

All harness output is collected into a persistent, organized **report folder** so you never hunt in `/tmp` or SSH into a VM to fetch dumps.

- **Location:** `tests/reports/` by default (override with `REPORT_DIR=/path`). Because the repo is mounted at `/mnt/c/projects/mymitmproxy` in WSL2, this is directly visible from Windows at `C:\projects\mymitmproxy\...\tests\reports\` — no fetching for the netns matrix.
- **Created if missing** (`mkdir -p`); the folder is **gitignored** (runtime output).
- **One folder per run**, `<suite>-<mode>-<UTC-timestamp>/`:
  ```
  tests/reports/
    LATEST                                  # basename of the newest run
    matrix-ebpf-20260721T130500Z/
      report.txt   report.json              # coverage matrix (human + machine)
      manifest.tsv results.tsv  meta.txt    # expected-vs-actual + run metadata
      dumps/<case>/index.jsonl + *.c2s + *.s2c
      logs/<case>.{server,proxy,client,parse}.log
    vm-ebpf-20260721T131500Z/
      dumps/…                               # scp'd back from VM B automatically
  ```
- **Automatic** in both harnesses: the protocol matrix writes here directly (local netns); the 3-VM harness `scp`s B's `/opt/mymitm/dumps` back here at the end of phase 2. The `mymitm-testing` skill documents where to look, so it is both automatic *and* discoverable.

---

## File Structure

```
tests/integration/
  lib.sh                     # NEW  — shared netns/veth/cert/toml/proxy plumbing (extracted from run_e2e.sh)
  run_e2e.sh                 # MODIFY — source lib.sh; keep its 4 assertions + iproute cleanliness
  client.py fake_server.py   # unchanged
  protocols/
    run_matrix.sh            # NEW — bash driver: topo up once, iterate cases, write results.tsv, call report.py
    requirements.txt         # NEW — h11, botocore, pytest
    conftest.py              # NEW — makes protocols/ the pytest rootdir (so `import dumpparse`, `import _util`, `import cases.*` resolve)
    _util.py                 # NEW — shared case helpers: server_ctx/client_ctx/spki_pin/read_conn/records
    manifest.tsv             # NEW — one row per case: name,kind,group,class,exp_fwd,exp_dump,exp_level,note
    report.py                # NEW — read manifest.tsv + results.tsv → print matrix, write report.json, exit nonzero on mismatch
    dumpparse/
      __init__.py            # NEW
      http1.py               # NEW — parse_exchange(c2s,s2c) via h11 (multi-message, chunked, EOF bodies)
      eventstream.py         # NEW — parse_events(body) for text/event-stream
      test_http1.py          # NEW — pytest (pure, no root)
      test_eventstream.py    # NEW — pytest (pure, no root)
    cases/
      __init__.py            # NEW
      http1.py               # NEW — GET/POST/HEAD baseline (walking skeleton, kind=simple)
      http1_0.py keepalive.py streaming.py pump.py sse.py   # NEW
      sigv4.py pinning.py    # NEW
      lifecycle_client.py    # NEW — controllable client used by the bash-orchestrated lifecycle rows
    test_report.py           # NEW — pytest for report.py
    test_sigv4.py            # NEW — pytest for sigv4 sign+validate logic (in-process, no root)
```

Runtime output lands in the **report folder** `tests/reports/` (gitignored) — see *Test report folder* above.

**Run the unit tests** (no root) from `tests/integration/protocols/`: `python3 -m pytest -q`.
**Run the matrix** (root/WSL2) from the repo root: `sudo bash tests/integration/protocols/run_matrix.sh [--mode ebpf|iproute] [--only <name>]`.

---

## Task 1: Extract shared netns plumbing into `lib.sh`; refactor `run_e2e.sh`

**Files:**
- Create: `tests/integration/lib.sh`
- Modify: `tests/integration/run_e2e.sh` (replace inline topology/cert/toml/proxy blocks with `source lib.sh` + helper calls; keep all 4 assertions + iproute cleanliness verbatim)

**Interfaces:**
- Produces (sourced by `run_e2e.sh` and `run_matrix.sh`):
  - Constants: `NS_CLI=mmcli NS_SRV=mmsrv VROOT=mmvroot VCLI=mmvcli VETH0=mmveth0 VSRV=mmvsrv`; `CLIENT_IP=10.8.0.5 CLIENT2_IP=10.8.0.9 SERVER_IP=192.168.1.50 BOX_IP=192.168.1.10`; `LOCAL_PORT=8443 FWMARK=0x1337 SERVER_NAME=server.test`.
  - `red/green/info/pass/fail/warn <msg>` — colored output (matches existing style; `fail` exits 1).
  - `topo_reset` — idempotently delete leftover netns/veths.
  - `topo_up <mode>` — build netns+veths+addrs+routes, set `route_localnet` on `$VROOT`, set `net.ipv4.ip_forward=1`; if `mode=ebpf`, add secondary `$CLIENT2_IP` to `$VCLI`.
  - `topo_down` — teardown + leftover warnings.
  - `gen_cert <cert> <key>` — CN=server.test leaf (the openssl one-liner).
  - `write_toml <toml> <mode> <cert> <key> <dump_dir>` — mode-correct `local_addr`, `data_plane`.
  - `wait_file <path> [tries]` — poll for a file (default 50 × 0.1s).
  - `start_proxy <toml> <log>` — launch `$BIN`, set global `PROXY_PID`; `wait_proxy <log>` — grep `proxy listening` (fail if it exits early); `stop_proxy` — kill/kill-9, clear `PROXY_PID`.
  - `BIN` — the release-binary path.
  - `REPORT_DIR` (default `tests/reports`, env-overridable) + `report_run_dir <suite> <mode>` — creates and echoes a per-run `<suite>-<mode>-<UTCstamp>/{dumps,logs}` folder and updates a `LATEST` pointer.

- [ ] **Step 1: Create `tests/integration/lib.sh`**

```bash
#!/usr/bin/env bash
# Shared plumbing for the netns e2e + protocol-matrix harnesses. Source, don't execute.
# Extracted verbatim from run_e2e.sh so both harnesses share one proven topology.

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$LIB_DIR/../.." && pwd)"
BIN="$REPO_ROOT/target/x86_64-unknown-linux-musl/release/mymitm"

# Persistent, organized output for all harnesses (override with REPORT_DIR=...).
# Repo-relative default => visible from Windows at C:\...\tests\reports\ under WSL2.
REPORT_DIR="${REPORT_DIR:-$REPO_ROOT/tests/reports}"

# --- topology constants ----------------------------------------------------
NS_CLI=mmcli
NS_SRV=mmsrv
VROOT=mmvroot   # root-side client veth == tun_iface
VCLI=mmvcli     # in netns mmcli
VETH0=mmveth0   # root-side server veth == egress_iface
VSRV=mmvsrv     # in netns mmsrv

CLIENT_IP=10.8.0.5
CLIENT2_IP=10.8.0.9
SERVER_IP=192.168.1.50
BOX_IP=192.168.1.10
LOCAL_PORT=8443
FWMARK=0x1337
SERVER_NAME=server.test

# --- output helpers --------------------------------------------------------
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m[harness]\033[0m %s\n' "$*"; }
warn()  { printf '\033[33m%s\033[0m\n' "$*"; }
pass()  { green "PASS: $*"; }
fail()  { red "ASSERTION FAILED: $*"; exit 1; }

# --- topology --------------------------------------------------------------
topo_reset() {
  ip netns del "$NS_CLI" 2>/dev/null || true
  ip netns del "$NS_SRV" 2>/dev/null || true
  ip link del "$VROOT"   2>/dev/null || true
  ip link del "$VETH0"   2>/dev/null || true
}

topo_up() {  # topo_up <ebpf|iproute>
  local mode="$1"
  info "building netns + veth topology (mode=$mode)"
  ip netns add "$NS_CLI"
  ip netns add "$NS_SRV"

  # client veth: root-side VROOT (tun_iface) <-> VCLI in netns cli
  ip link add "$VROOT" type veth peer name "$VCLI"
  ip link set "$VCLI" netns "$NS_CLI"
  ip addr add 10.8.0.1/24 dev "$VROOT"
  ip link set "$VROOT" up
  # eBPF DNATs the client flow to a local (non-local-to-iface) listener address;
  # route_localnet lets such martian-destined packets be accepted on VROOT.
  sysctl -wq net.ipv4.conf."$VROOT".route_localnet=1
  # Plain L3 forwarding is needed for the lifecycle "pre-attach" connection to
  # reach the server before the proxy diverts it. Harmless for diverted flows
  # (TC/PREROUTING DNAT precedes the forwarding decision).
  sysctl -wq net.ipv4.ip_forward=1
  ip netns exec "$NS_CLI" ip addr add "$CLIENT_IP/24" dev "$VCLI"
  ip netns exec "$NS_CLI" ip link set "$VCLI" up
  ip netns exec "$NS_CLI" ip link set lo up
  ip netns exec "$NS_CLI" ip route add default via 10.8.0.1

  if [ "$mode" = "ebpf" ]; then
    info "adding secondary client IP $CLIENT2_IP to $VCLI"
    ip netns exec "$NS_CLI" ip addr add "$CLIENT2_IP/24" dev "$VCLI"
  fi

  # server veth: root-side VETH0 (egress_iface) <-> VSRV in netns srv
  ip link add "$VETH0" type veth peer name "$VSRV"
  ip link set "$VSRV" netns "$NS_SRV"
  ip addr add "$BOX_IP/24" dev "$VETH0"
  ip link set "$VETH0" up
  ip netns exec "$NS_SRV" ip addr add "$SERVER_IP/24" dev "$VSRV"
  ip netns exec "$NS_SRV" ip link set "$VSRV" up
  ip netns exec "$NS_SRV" ip link set lo up
  # SNATted upstream packets arrive with src 10.8.0.x (outside server's /24);
  # route that back via the box so replies return on VETH0 for un-SNAT.
  ip netns exec "$NS_SRV" ip route add 10.8.0.0/24 via "$BOX_IP"
}

topo_down() {
  info "tearing down topology"
  ip netns del "$NS_CLI" 2>/dev/null || true
  ip netns del "$NS_SRV" 2>/dev/null || true
  ip link del "$VROOT"   2>/dev/null || true
  ip link del "$VETH0"   2>/dev/null || true
  if ip netns list 2>/dev/null | grep -qE "^($NS_CLI|$NS_SRV)\b"; then
    warn "WARNING: leftover netns remain"; ip netns list
  fi
  if ip link show "$VROOT" >/dev/null 2>&1 || ip link show "$VETH0" >/dev/null 2>&1; then
    warn "WARNING: leftover veth remain"
  fi
}

# --- cert ------------------------------------------------------------------
gen_cert() {  # gen_cert <cert> <key>
  local cert="$1" key="$2"
  info "generating leaf cert (CN=$SERVER_NAME)"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$key" -out "$cert" -days 2 \
    -subj "/CN=$SERVER_NAME" \
    -addext "subjectAltName=DNS:$SERVER_NAME" >/dev/null 2>&1 \
    || fail "openssl cert generation failed"
}

# --- config ----------------------------------------------------------------
write_toml() {  # write_toml <toml> <mode> <cert> <key> <dump_dir>
  local toml="$1" mode="$2" cert="$3" key="$4" dump="$5"
  local local_addr; [ "$mode" = ebpf ] && local_addr="10.8.0.1" || local_addr="127.0.0.1"
  cat > "$toml" <<EOF
target_server_ip = "$SERVER_IP"
target_server_port = 443
box_ip = "$BOX_IP"
cert_path = "$cert"
key_path = "$key"
tun_iface = "$VROOT"
egress_iface = "$VETH0"
local_addr = "$local_addr"
local_port = $LOCAL_PORT
fwmark = $FWMARK
dump_path = "$dump"
log_level = "info"
server_name = "$SERVER_NAME"
data_plane = "$mode"
EOF
}

# --- process helpers -------------------------------------------------------
wait_file() {  # wait_file <path> [tries]
  local path="$1" tries="${2:-50}" i
  for i in $(seq 1 "$tries"); do [ -f "$path" ] && return 0; sleep 0.1; done
  return 1
}

PROXY_PID=""
start_proxy() {  # start_proxy <toml> <log>
  local toml="$1" log="$2"
  RUST_LOG=info "$BIN" --config "$toml" >"$log" 2>&1 &
  PROXY_PID=$!
}
wait_proxy() {  # wait_proxy <log>
  local log="$1" i
  for i in $(seq 1 100); do
    grep -q "proxy listening" "$log" && return 0
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then red "mymitm exited early:"; cat "$log"; return 1; fi
    sleep 0.1
  done
  red "mymitm never logged 'proxy listening':"; cat "$log"; return 1
}
stop_proxy() {
  [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null
  sleep 0.4
  [ -n "$PROXY_PID" ] && kill -9 "$PROXY_PID" 2>/dev/null
  PROXY_PID=""
}

# --- report folder ---------------------------------------------------------
# Create + return a per-run report folder: <suite>-<mode>-<UTC-timestamp>/{dumps,logs}
report_run_dir() {  # report_run_dir <suite> <mode> ; echoes the created dir
  local ts; ts="$(date -u +%Y%m%dT%H%M%SZ)"
  local dir="$REPORT_DIR/$1-$2-$ts"
  mkdir -p "$dir/dumps" "$dir/logs"
  echo "$1-$2-$ts" > "$REPORT_DIR/LATEST"
  echo "$dir"
}
```

Also append `tests/reports/` and `/tmp/mymitm-*` to `.gitignore` (runtime outputs; the report folder is not tracked).

- [ ] **Step 2: Refactor `run_e2e.sh` to source `lib.sh` — replace the cert block**

In `tests/integration/run_e2e.sh`, replace the `# --- cert ---` block (the `openssl req ...` invocation, currently lines ~114-120) with a call to the helper. First add the source line near the top (right after `MODE="${MODE:-ebpf}"`):

```bash
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
```

Then replace the inline cert generation with:

```bash
gen_cert "$CERT" "$KEY"
```

(The local `CERT`/`KEY`/`WORK` variable definitions in `run_e2e.sh` stay; they feed the helpers. `red/green/info` are now provided by `lib.sh` — delete `run_e2e.sh`'s local copies to avoid redefinition.)

- [ ] **Step 3: Refactor `run_e2e.sh` — replace the topology block**

Replace the `# --- topology ---` block (the `ip netns add ... ip route add 10.8.0.0/24 via "$BOX_IP"` sequence, currently lines ~122-163) with:

```bash
info "building netns + veth topology"
topo_up "$MODE"
```

Delete `run_e2e.sh`'s local topology constants (`NS_CLI`, `VROOT`, `CLIENT_IP`, `SERVER_IP`, `BOX_IP`, …) — they come from `lib.sh`. Keep `CLIENT2_IP` usage; it is also in `lib.sh`.

- [ ] **Step 4: Refactor `run_e2e.sh` — replace the TOML block and proxy start**

Replace the two mode-branched `cat > "$TOML" <<EOF ... EOF` blocks (currently lines ~168-212) with:

```bash
mkdir -p "$DUMP_DIR"
write_toml "$TOML" "$MODE" "$CERT" "$KEY" "$DUMP_DIR"
info "wrote config: $TOML"
```

Replace the proxy launch + readiness loop (currently lines ~227-238) with:

```bash
info "starting mymitm (real release binary) in root ns"
start_proxy "$TOML" "$PROXY_LOG"
wait_proxy "$PROXY_LOG" || fail "mymitm did not come up"
green "mymitm data plane attached + proxy listening"
```

Update `teardown()` to call `topo_down` for the netns/veth removal (keep the proxy/server `kill` lines; replace the four `ip netns del`/`ip link del` lines with `topo_down`).

- [ ] **Step 5: Run the eBPF mode to verify no regression**

Run: `cargo build -p mymitm --release && sudo bash tests/integration/run_e2e.sh`
Expected: green `ALL ASSERTIONS PASS (eBPF multi-client mode)`; both client IPs preserved.

- [ ] **Step 6: Run the iproute mode to verify no regression**

Run: `sudo MODE=iproute bash tests/integration/run_e2e.sh`
Expected: green `ALL ASSERTIONS PASS (iproute mode)` + the four post-run cleanliness checks pass.

- [ ] **Step 7: Commit**

```bash
git add tests/integration/lib.sh tests/integration/run_e2e.sh
git commit -m "refactor(tests): extract shared netns plumbing into lib.sh"
```

---

## Task 2: `dumpparse/http1.py` — HTTP/1.x message reconstruction (pure, TDD)

**Files:**
- Create: `tests/integration/protocols/requirements.txt`, `tests/integration/protocols/conftest.py`, `tests/integration/protocols/dumpparse/__init__.py`
- Create: `tests/integration/protocols/dumpparse/http1.py`
- Test: `tests/integration/protocols/dumpparse/test_http1.py`

**Interfaces:**
- Produces: `dumpparse.http1.parse_exchange(c2s: bytes, s2c: bytes) -> Parsed`, where `Parsed` has `.requests: list[Message]`, `.responses: list[Message]`, `.level: int` (1=framing, 2=body de-transferred), `.error: str`. `Message` has `.kind`, `.method`, `.target`, `.status`, `.reason`, `.http_version`, `.headers: list[(str,str)]`, `.body: bytes`, `.informational: list[int]`, and `.header(name) -> str|None`.

- [ ] **Step 1: Create the Python scaffolding**

`tests/integration/protocols/requirements.txt`:
```
h11>=0.14
botocore>=1.34
pytest>=7
```

`tests/integration/protocols/conftest.py`:
```python
# Make protocols/ the import root so `import dumpparse`, `import _util`,
# `import cases.*` resolve under `python3 -m pytest` run from this directory.
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
```

`tests/integration/protocols/dumpparse/__init__.py`: *(empty file)*

Install deps: `python3 -m pip install -r tests/integration/protocols/requirements.txt`

- [ ] **Step 2: Write the failing test**

`tests/integration/protocols/dumpparse/test_http1.py`:
```python
from dumpparse.http1 import parse_exchange


def test_single_get():
    c2s = b"GET /hello HTTP/1.1\r\nHost: server.test\r\n\r\n"
    s2c = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello"
    p = parse_exchange(c2s, s2c)
    assert p.error == ""
    assert len(p.requests) == 1 and p.requests[0].method == "GET" and p.requests[0].target == "/hello"
    assert len(p.responses) == 1 and p.responses[0].status == 200 and p.responses[0].body == b"hello"
    assert p.level == 2


def test_keepalive_three():
    req = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n"
    c2s = req.replace(b"/a", b"/1") + req.replace(b"/a", b"/2") + req.replace(b"/a", b"/3")
    s2c = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nX" * 3
    p = parse_exchange(c2s, s2c)
    assert [r.target for r in p.requests] == ["/1", "/2", "/3"]
    assert len(p.responses) == 3 and all(r.status == 200 for r in p.responses)


def test_chunked_response_dechunked():
    c2s = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"
    s2c = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
           b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
    p = parse_exchange(c2s, s2c)
    assert p.responses[0].body == b"hello world"   # dechunked -> L2
    assert p.level == 2


def test_http10_eof_body():
    c2s = b"GET / HTTP/1.0\r\n\r\n"
    s2c = b"HTTP/1.0 200 OK\r\n\r\nbody-until-eof"   # no CL; EOF-delimited
    p = parse_exchange(c2s, s2c)
    assert p.responses[0].status == 200 and p.responses[0].body == b"body-until-eof"


def test_head_no_body():
    c2s = b"HEAD / HTTP/1.1\r\nHost: h\r\n\r\n"
    s2c = b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n"   # HEAD: no body despite CL
    p = parse_exchange(c2s, s2c)
    assert p.requests[0].method == "HEAD" and p.responses[0].body == b""


def test_garbage_is_error_not_crash():
    p = parse_exchange(b"\x00\x01not http", b"\xff\xfe")
    assert p.error != "" or (not p.requests and not p.responses)
```

- [ ] **Step 3: Run it to verify it fails**

Run: `cd tests/integration/protocols && python3 -m pytest dumpparse/test_http1.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'dumpparse.http1'`.

- [ ] **Step 4: Implement `dumpparse/http1.py`**

```python
"""Reconstruct HTTP/1.x messages from the proxy's raw decrypted dump bytes.

The proxy is a byte pipe: `<conn>.c2s` is the exact client->server plaintext,
`<conn>.s2c` the server->client plaintext. We re-parse those blobs with h11 (a
sans-IO HTTP/1.1 state machine) to prove the dump is *parseable*: every request
and response across a keep-alive/pipelined connection is recovered with framing
decoded (dechunked / Content-Length / EOF body).

Response framing depends on the request method (HEAD/204/304 -> no body). The
two streams are dumped independently, so we parse requests first, then drive an
h11 CLIENT with synthetic requests carrying the real methods.
"""
from dataclasses import dataclass, field
from typing import List, Tuple
import h11


@dataclass
class Message:
    kind: str
    method: str = ""
    target: str = ""
    status: int = 0
    reason: str = ""
    http_version: str = ""
    headers: List[Tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    informational: List[int] = field(default_factory=list)

    def header(self, name: str):
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None


@dataclass
class Parsed:
    requests: List[Message] = field(default_factory=list)
    responses: List[Message] = field(default_factory=list)
    level: int = 0
    error: str = ""


def _hdrs(headers):
    return [(k.decode("latin-1"), v.decode("latin-1")) for (k, v) in headers]


def _parse_requests(c2s: bytes) -> List[Message]:
    conn = h11.Connection(h11.SERVER)
    conn.receive_data(c2s)
    conn.receive_data(b"")
    out, cur = [], None
    while True:
        try:
            ev = conn.next_event()
        except h11.RemoteProtocolError:
            break
        if ev is h11.NEED_DATA or ev is h11.PAUSED:
            break
        if isinstance(ev, h11.Request):
            cur = Message("request", method=ev.method.decode("ascii"),
                          target=ev.target.decode("latin-1"),
                          http_version=ev.http_version.decode("ascii"),
                          headers=_hdrs(ev.headers))
        elif isinstance(ev, h11.Data):
            if cur is not None:
                cur.body += bytes(ev.data)
        elif isinstance(ev, h11.EndOfMessage):
            if cur is not None:
                out.append(cur); cur = None
            # Advance our (server) state with a synthetic response so h11 will
            # permit the next cycle and we can parse further pipelined requests.
            try:
                conn.send(h11.Response(status_code=200, headers=[("Content-Length", "0")]))
                conn.send(h11.EndOfMessage())
                conn.start_next_cycle()
            except h11.LocalProtocolError:
                break
        elif isinstance(ev, h11.ConnectionClosed):
            break
    return out


def _parse_responses(s2c: bytes, methods: List[str]) -> List[Message]:
    conn = h11.Connection(h11.CLIENT)
    conn.receive_data(s2c)
    conn.receive_data(b"")
    out, cur, pending = [], None, []
    idx = 0

    def send_request(method):
        conn.send(h11.Request(method=method, target="/",
                              headers=[("Host", "x"), ("Content-Length", "0")]))
        conn.send(h11.EndOfMessage())

    if methods:
        send_request(methods[0]); idx = 1
    while True:
        try:
            ev = conn.next_event()
        except h11.RemoteProtocolError:
            break
        if ev is h11.NEED_DATA or ev is h11.PAUSED:
            break
        if isinstance(ev, h11.InformationalResponse):
            pending.append(ev.status_code)
        elif isinstance(ev, h11.Response):
            cur = Message("response", status=ev.status_code,
                          reason=(ev.reason or b"").decode("latin-1"),
                          http_version=ev.http_version.decode("ascii"),
                          headers=_hdrs(ev.headers), informational=list(pending))
            pending = []
        elif isinstance(ev, h11.Data):
            if cur is not None:
                cur.body += bytes(ev.data)
        elif isinstance(ev, h11.EndOfMessage):
            if cur is not None:
                out.append(cur); cur = None
            try:
                conn.start_next_cycle()
            except h11.LocalProtocolError:
                break
            if idx < len(methods):
                send_request(methods[idx]); idx += 1
        elif isinstance(ev, h11.ConnectionClosed):
            break
    return out


def parse_exchange(c2s: bytes, s2c: bytes) -> Parsed:
    p = Parsed()
    try:
        p.requests = _parse_requests(c2s)
        methods = [m.method for m in p.requests] or ["GET"]
        p.responses = _parse_responses(s2c, methods)
    except Exception as e:
        p.error = f"{type(e).__name__}: {e}"
        return p
    if p.requests or p.responses:
        p.level = 2 if any(m.body for m in p.requests + p.responses) else 1
    return p
```

- [ ] **Step 5: Run it to verify it passes**

Run: `cd tests/integration/protocols && python3 -m pytest dumpparse/test_http1.py -q`
Expected: PASS (6 passed).

- [ ] **Step 6: Commit**

```bash
git add tests/integration/protocols/requirements.txt tests/integration/protocols/conftest.py tests/integration/protocols/dumpparse/
git commit -m "test(protocols): dumpparse.http1 message reconstruction (h11)"
```

---

## Task 3: `dumpparse/eventstream.py` — SSE parser (pure, TDD)

**Files:**
- Create: `tests/integration/protocols/dumpparse/eventstream.py`
- Test: `tests/integration/protocols/dumpparse/test_eventstream.py`

**Interfaces:**
- Produces: `dumpparse.eventstream.parse_events(body: bytes) -> list[dict]`, each event `{"event": str|None, "data": str, "id": str|None, "retry": str|None, "comments": list[str]}`. Input `body` is the already-dechunked response body (feed `dumpparse.http1` first, then its `response.body` here).

- [ ] **Step 1: Write the failing test**

`tests/integration/protocols/dumpparse/test_eventstream.py`:
```python
from dumpparse.eventstream import parse_events


def test_basic_events():
    body = (b": stream open\n\n"
            b"event: greeting\ndata: hello\nid: 1\n\n"
            b"data: line-a\ndata: line-b\n\n"
            b"retry: 3000\ndata: last\n\n")
    ev = parse_events(body)
    assert len(ev) == 3
    assert ev[0]["event"] == "greeting" and ev[0]["data"] == "hello" and ev[0]["id"] == "1"
    assert ev[0]["comments"] == [] and ev[0] is not None
    assert ev[1]["data"] == "line-a\nline-b"     # multi-line data joined by \n
    assert ev[2]["retry"] == "3000" and ev[2]["data"] == "last"


def test_leading_comment_only_block_is_not_an_event():
    ev = parse_events(b": just a comment\n\ndata: x\n\n")
    assert len(ev) == 1 and ev[0]["data"] == "x"


def test_count_matches_expected():
    body = b"".join(b"data: %d\n\n" % i for i in range(10))
    assert len(parse_events(body)) == 10
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd tests/integration/protocols && python3 -m pytest dumpparse/test_eventstream.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'dumpparse.eventstream'`.

- [ ] **Step 3: Implement `dumpparse/eventstream.py`**

```python
"""Parse a text/event-stream body (RFC: the SSE line format) into events.

Feed the already-dechunked HTTP response body (dumpparse.http1 first). A blank
line dispatches an event; lines starting with ':' are comments; 'field: value'
lines accumulate. 'data' fields join with '\n'. A block that carries only
comments (no field) is not dispatched as an event.
"""
from typing import List, Dict


def parse_events(body: bytes) -> List[Dict]:
    text = body.decode("utf-8", "replace")
    events: List[Dict] = []
    cur = {"event": None, "data": [], "id": None, "retry": None, "comments": []}

    def flush():
        has_field = bool(cur["data"] or cur["event"] or cur["id"] or cur["retry"])
        if has_field:
            events.append({"event": cur["event"], "data": "\n".join(cur["data"]),
                           "id": cur["id"], "retry": cur["retry"],
                           "comments": list(cur["comments"])})
        cur.update(event=None, data=[], id=None, retry=None, comments=[])

    for raw in text.split("\n"):
        line = raw.rstrip("\r")
        if line == "":
            flush(); continue
        if line.startswith(":"):
            cur["comments"].append(line[1:]); continue
        if ":" in line:
            field, val = line.split(":", 1)
            if val.startswith(" "):
                val = val[1:]
        else:
            field, val = line, ""
        if field == "data":
            cur["data"].append(val)
        elif field == "event":
            cur["event"] = val
        elif field == "id":
            cur["id"] = val
        elif field == "retry":
            cur["retry"] = val
    flush()
    return events
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cd tests/integration/protocols && python3 -m pytest dumpparse/test_eventstream.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add tests/integration/protocols/dumpparse/eventstream.py tests/integration/protocols/dumpparse/test_eventstream.py
git commit -m "test(protocols): dumpparse.eventstream SSE parser"
```

---

## Task 4: `report.py` + `manifest.tsv` — matrix render + verdict comparison (pure, TDD)

**Files:**
- Create: `tests/integration/protocols/manifest.tsv`
- Create: `tests/integration/protocols/report.py`
- Test: `tests/integration/protocols/test_report.py`

**Interfaces:**
- Produces: `report.status_for(exp: dict, act: dict) -> "PASS"|"FAIL"|"SKIP"|"ERROR"`; `report.read_tsv(path, cols) -> list[dict]`; a CLI `python3 report.py --manifest M --results R [--json-out J] [--mode ebpf]` that prints the matrix and exits nonzero if any row is FAIL/ERROR.
- Consumes (from the driver, Task 5): `results.tsv` with columns `name, act_fwd, act_dump, act_level, srcip`.
- `manifest.tsv` columns (TAB-separated): `name, kind, group, class, exp_fwd, exp_dump, exp_level, note`. `kind ∈ {simple, custom}`.

- [ ] **Step 1: Create `manifest.tsv` (the full P0 expected matrix — columns are TAB-separated)**

```
# name	kind	group	class	exp_fwd	exp_dump	exp_level	note
http1	simple	A	PIPE	ok	ok	2	HTTP/1.1 GET/POST/HEAD baseline
http1_0	simple	A	PIPE	ok	ok	2	HTTP/1.0 EOF-delimited body
keepalive	simple	A	PIPE	ok	ok	2	>=3 requests on one connection
streaming	simple	A	PIPE	ok	ok	2	chunked long-lived incremental delivery
pump	simple	A	PIPE	ok	ok	1	full-duplex + idle + large reassembly (raw bytes; half-close deferred to P1)
sse	simple	A	PIPE	ok	ok	2	text/event-stream incremental
sigv4	simple	F	integrity	ok	ok	2	SigV4 header + presigned survive byte-exact
pinning	simple	D	positive	ok	ok	2	SPKI pin succeeds (genuine leaf); HSTS in dump
newconn	custom	E	PIPE	ok	ok	2	fresh SYN after attach is intercepted
preexisting	custom	E	PIPE	fail	na	0	missed-SYN mid-stream flow reset (documented)
restart	custom	E	PIPE	fail	na	0	proxy restart drops in-flight conn (documented)
```

- [ ] **Step 2: Write the failing test**

`tests/integration/protocols/test_report.py`:
```python
import importlib.util, os

_spec = importlib.util.spec_from_file_location(
    "report", os.path.join(os.path.dirname(__file__), "report.py"))
report = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(report)


def test_status_pass_when_match():
    exp = {"exp_fwd": "ok", "exp_dump": "ok", "exp_level": "2"}
    act = {"act_fwd": "ok", "act_dump": "ok", "act_level": "2", "srcip": "ok"}
    assert report.status_for(exp, act) == "PASS"


def test_status_fail_on_forward_mismatch():
    exp = {"exp_fwd": "ok", "exp_dump": "ok", "exp_level": "2"}
    act = {"act_fwd": "fail", "act_dump": "ok", "act_level": "2", "srcip": "ok"}
    assert report.status_for(exp, act) == "FAIL"


def test_expected_fail_is_pass():
    exp = {"exp_fwd": "fail", "exp_dump": "na", "exp_level": "0"}
    act = {"act_fwd": "fail", "act_dump": "na", "act_level": "0", "srcip": "na"}
    assert report.status_for(exp, act) == "PASS"


def test_level_floor_enforced():
    exp = {"exp_fwd": "ok", "exp_dump": "ok", "exp_level": "2"}
    act = {"act_fwd": "ok", "act_dump": "ok", "act_level": "1", "srcip": "ok"}
    assert report.status_for(exp, act) == "FAIL"


def test_boxleak_fails():
    exp = {"exp_fwd": "ok", "exp_dump": "ok", "exp_level": "2"}
    act = {"act_fwd": "ok", "act_dump": "ok", "act_level": "2", "srcip": "BOXLEAK"}
    assert report.status_for(exp, act) == "FAIL"


def test_skip_is_skip():
    exp = {"exp_fwd": "ok", "exp_dump": "ok", "exp_level": "2"}
    act = {"act_fwd": "skip", "act_dump": "skip", "act_level": "0", "srcip": ""}
    assert report.status_for(exp, act) == "SKIP"
```

- [ ] **Step 3: Run it to verify it fails**

Run: `cd tests/integration/protocols && python3 -m pytest test_report.py -q`
Expected: FAIL — `FileNotFoundError`/`AttributeError` (no `report.py`).

- [ ] **Step 4: Implement `report.py`**

```python
#!/usr/bin/env python3
"""Render the protocol-coverage matrix from manifest.tsv (expected) + results.tsv (actual).

Exit 0 iff every case's actual (Fwd, Dump[, level, srcip]) matches its expected
verdict. SKIP rows (missing tool) are reported but never counted as pass and do
not fail the run.
"""
import argparse, json, sys

SYMB = {"ok": "✓", "degrade": "~", "fail": "✗", "na": "n/a",
        "skip": "SKIP", "err": "ERR", "": "?"}

MANIFEST_COLS = ["name", "kind", "group", "class", "exp_fwd", "exp_dump", "exp_level", "note"]
RESULT_COLS = ["name", "act_fwd", "act_dump", "act_level", "srcip"]


def read_tsv(path, cols):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            rows.append(dict(zip(cols, parts + [""] * (len(cols) - len(parts)))))
    return rows


def status_for(exp, act):
    if act.get("act_fwd") == "skip":
        return "SKIP"
    if act.get("act_fwd") == "err" or act.get("act_dump") == "err":
        return "ERROR"
    ok = (act.get("act_fwd") == exp["exp_fwd"] and act.get("act_dump") == exp["exp_dump"])
    if ok and exp["exp_dump"] == "ok":
        try:
            ok = int(act.get("act_level") or 0) >= int(exp["exp_level"] or 0)
        except ValueError:
            ok = False
    if act.get("srcip") not in (None, "", "ok", "na"):
        ok = False
    return "PASS" if ok else "FAIL"


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")   # robust on non-UTF-8 consoles
    except Exception:
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--results", required=True)
    ap.add_argument("--json-out")
    ap.add_argument("--mode", default="")
    args = ap.parse_args()

    manifest = {r["name"]: r for r in read_tsv(args.manifest, MANIFEST_COLS)}
    results = {r["name"]: r for r in read_tsv(args.results, RESULT_COLS)}

    rows, npass, nfail, nskip = [], 0, 0, 0
    print(f"\n=== mymitmproxy protocol coverage - P0 (mode={args.mode or '?'}) ===\n")
    hdr = f"{'CASE':<14}{'GRP':<4}{'CLASS':<10}{'FWD':<5}{'DUMP':<6}{'LVL':<4}{'STATUS':<7}NOTE"
    print(hdr); print("-" * len(hdr))
    for name, exp in manifest.items():
        act = results.get(name, {"act_fwd": "err", "act_dump": "err", "act_level": "0", "srcip": ""})
        st = status_for(exp, act)
        npass += st == "PASS"; nskip += st == "SKIP"; nfail += st in ("FAIL", "ERROR")
        print(f"{name:<14}{exp['group']:<4}{exp['class']:<10}"
              f"{SYMB.get(act.get('act_fwd',''),'?'):<5}{SYMB.get(act.get('act_dump',''),'?'):<6}"
              f"{(act.get('act_level') or '-'):<4}{st:<7}{exp['note']}")
        rows.append({"name": name, "group": exp["group"], "class": exp["class"],
                     "expected": {"fwd": exp["exp_fwd"], "dump": exp["exp_dump"], "level": exp["exp_level"]},
                     "actual": {"fwd": act.get("act_fwd"), "dump": act.get("act_dump"),
                                "level": act.get("act_level"), "srcip": act.get("srcip")},
                     "status": st})
    print("-" * len(hdr))
    print(f"\n{npass} PASS   {nfail} FAIL   {nskip} SKIP   ({len(manifest)} rows)\n")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump({"mode": args.mode, "pass": npass, "fail": nfail, "skip": nskip, "rows": rows},
                      fh, indent=2, ensure_ascii=False)
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 5: Run it to verify it passes**

Run: `cd tests/integration/protocols && python3 -m pytest test_report.py -q`
Expected: PASS (6 passed).

- [ ] **Step 6: Commit**

```bash
git add tests/integration/protocols/manifest.tsv tests/integration/protocols/report.py tests/integration/protocols/test_report.py
git commit -m "test(protocols): coverage-matrix report + expected-verdict manifest"
```

---

## Task 5: `run_matrix.sh` driver + `_util.py` + `cases/http1.py` (walking skeleton)

This is the integration task that wires topology → server → proxy → client → dump-parse → report for one real protocol. Requires **sudo/WSL2**.

**Files:**
- Create: `tests/integration/protocols/_util.py`
- Create: `tests/integration/protocols/cases/__init__.py` *(empty)*
- Create: `tests/integration/protocols/cases/http1.py`
- Create: `tests/integration/protocols/run_matrix.sh`

**Interfaces:**
- Produces: `_util.server_ctx(cert,key)`, `_util.client_ctx(cafile)`, `_util.connect_tls(ctx,host,port,server_name,bind_addr=None,timeout=15) -> ssl.SSLSocket`, `_util.read_conn(dump_dir) -> (conn_id, c2s: bytes, s2c: bytes, rec: dict)`, `_util.records(dump_dir) -> list[dict]`, `_util.case_main(server, client, parse)` (standard `server`/`client`/`parse` subcommand contract shared by every simple case).
- Consumes: `dumpparse.http1.parse_exchange` (Task 2); `manifest.tsv` + `report.py` (Task 4); `lib.sh` (Task 1).
- Case CLI contract (every simple case): `server --cert --key --bind --port --ready --peerfile` (serve until killed; write ready file; append each peer IP to peerfile) · `client --cafile --host --port --server-name --bind-addr` (print `FORWARD_OK ...`/`FORWARD_FAIL ...`, exit 0 on forward success) · `parse --dump-dir` (print one of `DUMP_OK level=<n> ...` / `DUMP_PARTIAL level=<n> ...` / `DUMP_FAIL <reason>` / `DUMP_NA <reason>`).

- [ ] **Step 1: Create `_util.py`**

```python
"""Shared helpers for protocol case modules. Dependency-free (stdlib + argparse)."""
import argparse, json, os, socket, ssl, sys


def server_ctx(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx


def client_ctx(cafile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=cafile)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    return ctx


def connect_tls(ctx, host, port, server_name, bind_addr=None, timeout=15):
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    if bind_addr:
        raw.bind((bind_addr, 0))
    raw.connect((host, port))
    return ctx.wrap_socket(raw, server_hostname=server_name)


def _read(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except FileNotFoundError:
        return b""


def read_conn(dump_dir):
    """(conn_id, c2s, s2c, record) for the FIRST connection in index.jsonl."""
    idx = os.path.join(dump_dir, "index.jsonl")
    rec = None
    with open(idx, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rec = json.loads(line); break
    if rec is None:
        raise ValueError("empty index.jsonl")
    cid = rec.get("conn_id") or rec.get("id")
    return cid, _read(os.path.join(dump_dir, f"{cid}.c2s")), _read(os.path.join(dump_dir, f"{cid}.s2c")), rec


def records(dump_dir):
    """All index.jsonl records (multi-connection cases)."""
    idx = os.path.join(dump_dir, "index.jsonl")
    out = []
    if os.path.exists(idx):
        with open(idx, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
    return out


def case_main(server, client, parse):
    """Standard server/client/parse CLI shared by every simple case module."""
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="role", required=True)
    s = sub.add_parser("server")
    for f in ("--cert", "--key", "--bind", "--ready", "--peerfile"):
        s.add_argument(f, required=True)
    s.add_argument("--port", type=int, required=True)
    c = sub.add_parser("client")
    for f in ("--cafile", "--host", "--server-name"):
        c.add_argument(f, required=True)
    c.add_argument("--port", type=int, required=True)
    c.add_argument("--bind-addr", default=None)
    p = sub.add_parser("parse")
    p.add_argument("--dump-dir", required=True)
    a = ap.parse_args()
    if a.role == "server":
        server(a)
    elif a.role == "client":
        sys.exit(client(a) or 0)
    else:
        parse(a)
```

- [ ] **Step 2: Create `cases/__init__.py`** *(empty file)*

- [ ] **Step 3: Create `cases/http1.py`**

```python
#!/usr/bin/env python3
"""HTTP/1.1 baseline: GET (small+large) + HEAD + POST over one keep-alive conn."""
import hashlib, http.client, os, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _util
from dumpparse.http1 import parse_exchange

LARGE_N = 100_000
SMALL_BODY = b"hello-http1"


def run_server(a):
    peerfile = a.peerfile

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _record(self):
            with open(peerfile, "a") as fh:
                fh.write(self.client_address[0] + "\n")

        def _send(self, body, head_only=False):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if not head_only:
                self.wfile.write(body)

        def do_GET(self):
            self._record()
            self._send(b"X" * LARGE_N if self.path.startswith("/large") else SMALL_BODY)

        def do_HEAD(self):
            self._record(); self._send(SMALL_BODY, head_only=True)

        def do_POST(self):
            self._record()
            n = int(self.headers.get("Content-Length", "0"))
            data = self.rfile.read(n) if n else b""
            self._send(b"posted:" + hashlib.sha256(data).hexdigest().encode())

        def log_message(self, *a_):
            pass

    httpd = ThreadingHTTPServer((a.bind, a.port), H)
    httpd.socket = _util.server_ctx(a.cert, a.key).wrap_socket(httpd.socket, server_side=True)
    with open(a.ready, "w") as fh:
        fh.write("ready\n")
    httpd.serve_forever()


def run_client(a):
    ctx = _util.client_ctx(a.cafile)
    tls = _util.connect_tls(ctx, a.host, a.port, a.server_name, a.bind_addr)
    conn = http.client.HTTPSConnection(a.server_name, a.port, context=ctx, timeout=15)
    conn.sock = tls  # dial by IP with SNI=server_name, but keep Host: server_name
    out = []
    conn.request("GET", "/small");  r = conn.getresponse(); out.append((r.status, r.read()))
    conn.request("GET", "/large");  r = conn.getresponse(); out.append((r.status, len(r.read())))
    conn.request("HEAD", "/small"); r = conn.getresponse(); out.append((r.status, len(r.read())))
    payload = b"the-body-to-post"
    conn.request("POST", "/echo", body=payload, headers={"Content-Length": str(len(payload))})
    r = conn.getresponse(); out.append((r.status, r.read()))
    conn.close()

    want_post = b"posted:" + hashlib.sha256(payload).hexdigest().encode()
    ok = (out[0] == (200, SMALL_BODY) and out[1] == (200, LARGE_N)
          and out[2] == (200, 0) and out[3] == (200, want_post))
    if ok:
        print("FORWARD_OK http1 get/large/head/post keep-alive"); return 0
    print(f"FORWARD_FAIL out={out}"); return 1


def run_parse(a):
    _, c2s, s2c, _ = _util.read_conn(a.dump_dir)
    p = parse_exchange(c2s, s2c)
    if p.error:
        print(f"DUMP_FAIL {p.error}"); return
    methods = [r.method for r in p.requests]
    statuses = [r.status for r in p.responses]
    if len(p.requests) >= 4 and statuses[:4] == [200, 200, 200, 200]:
        print(f"DUMP_OK level={p.level} reqs={methods} statuses={statuses}")
    else:
        print(f"DUMP_PARTIAL level={p.level} reqs={methods} statuses={statuses}")


if __name__ == "__main__":
    _util.case_main(run_server, run_client, run_parse)
```

- [ ] **Step 4: Create `run_matrix.sh`**

```bash
#!/usr/bin/env bash
# Protocol-coverage matrix driver. Root/WSL2. Reuses lib.sh netns plumbing.
#   sudo bash tests/integration/protocols/run_matrix.sh [--mode ebpf|iproute] [--only NAME]
set -u
PROTO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$PROTO_DIR/../lib.sh"
export PYTHONPATH="$PROTO_DIR"

MODE=ebpf; ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="$2"; shift 2;;
    --only) ONLY="$2"; shift 2;;
    *) red "unknown arg: $1"; exit 2;;
  esac
done
[ "$(id -u)" -eq 0 ] || { red "must run as root (sudo)"; exit 1; }
[ -x "$BIN" ] || { red "release binary not found: $BIN (cargo build -p mymitm --release)"; exit 1; }

WORK="$(mktemp -d /tmp/mymitm-matrix.XXXXXX)"          # transient scratch
RUN_DIR="$(report_run_dir matrix "$MODE")"             # persistent, organized report folder
CERT="$WORK/leaf.pem"; KEY="$WORK/leaf.key"; TOML="$WORK/mymitm.toml"
RESULTS="$WORK/results.tsv"; : > "$RESULTS"
ART="$RUN_DIR/dumps"                                   # per-case dumps land straight in the report folder
info "scratch:       $WORK   mode: $MODE"
info "report folder: $RUN_DIR"

trap 'stop_proxy; topo_down' EXIT
topo_reset
topo_up "$MODE"
gen_cert "$CERT" "$KEY"

emit() { printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >> "$RESULTS"; }

run_simple() {  # run_simple <name>
  local name="$1"
  local dump="$WORK/dumps"; rm -rf "$dump"; mkdir -p "$dump"
  local ready="$WORK/$name.ready" peer="$WORK/$name.peer"
  rm -f "$ready"; : > "$peer"
  write_toml "$TOML" "$MODE" "$CERT" "$KEY" "$dump"

  ip netns exec "$NS_SRV" env PYTHONPATH="$PROTO_DIR" python3 "$PROTO_DIR/cases/$name.py" server \
    --cert "$CERT" --key "$KEY" --bind "$SERVER_IP" --port 443 \
    --ready "$ready" --peerfile "$peer" >"$WORK/$name.server.log" 2>&1 &
  local spid=$!
  if ! wait_file "$ready"; then
    warn "[$name] server never became ready"; cat "$WORK/$name.server.log"
    kill "$spid" 2>/dev/null; emit "$name" err err 0 ""; return
  fi

  start_proxy "$TOML" "$WORK/$name.proxy.log"
  if ! wait_proxy "$WORK/$name.proxy.log"; then
    stop_proxy; kill "$spid" 2>/dev/null; emit "$name" err err 0 ""; return
  fi

  ip netns exec "$NS_CLI" env PYTHONPATH="$PROTO_DIR" python3 "$PROTO_DIR/cases/$name.py" client \
    --cafile "$CERT" --host "$SERVER_IP" --port 443 \
    --server-name "$SERVER_NAME" --bind-addr "$CLIENT_IP" \
    >"$WORK/$name.client.log" 2>&1
  local crc=$?
  stop_proxy; kill "$spid" 2>/dev/null; wait "$spid" 2>/dev/null

  local afwd=fail
  { [ $crc -eq 0 ] && grep -q FORWARD_OK "$WORK/$name.client.log"; } && afwd=ok

  local srcip=missing
  if grep -qF "$BOX_IP" "$peer"; then srcip=BOXLEAK
  elif grep -qF "$CLIENT_IP" "$peer"; then srcip=ok; fi

  local adump=err alvl=0 pout
  pout="$(python3 "$PROTO_DIR/cases/$name.py" parse --dump-dir "$dump" 2>"$WORK/$name.parse.log")"
  echo "$pout" > "$WORK/$name.parse.out"
  case "$pout" in
    DUMP_OK*)      adump=ok;      alvl="$(printf '%s' "$pout" | sed -n 's/.*level=\([0-9]*\).*/\1/p')";;
    DUMP_PARTIAL*) adump=degrade; alvl="$(printf '%s' "$pout" | sed -n 's/.*level=\([0-9]*\).*/\1/p')";;
    DUMP_FAIL*)    adump=fail;;
    DUMP_NA*)      adump=na;;
    *)             adump=err;;
  esac
  [ -z "$alvl" ] && alvl=0

  cp -r "$dump" "$ART/$name" 2>/dev/null || true
  emit "$name" "$afwd" "$adump" "$alvl" "$srcip"
  info "[$name] fwd=$afwd dump=$adump level=$alvl srcip=$srcip"
}

# Placeholder for custom lifecycle cases; replaced in Task 12.
run_custom() { warn "[$1] custom lifecycle case not yet implemented"; emit "$1" err err 0 ""; }

run_case() {
  case "$2" in
    simple) run_simple "$1";;
    custom) run_custom "$1";;
    *) emit "$1" err err 0 "";;
  esac
}

while IFS=$'\t' read -r name kind group class exp_fwd exp_dump exp_level note; do
  case "$name" in ''|\#*) continue;; esac
  [ -n "$ONLY" ] && [ "$name" != "$ONLY" ] && continue
  run_case "$name" "$kind"
done < "$PROTO_DIR/manifest.tsv"

stop_proxy; topo_down; trap - EXIT
python3 "$PROTO_DIR/report.py" --manifest "$PROTO_DIR/manifest.tsv" \
  --results "$RESULTS" --json-out "$RUN_DIR/report.json" --mode "$MODE" | tee "$RUN_DIR/report.txt"
rc=${PIPESTATUS[0]}
cp "$PROTO_DIR/manifest.tsv" "$RESULTS" "$RUN_DIR/" 2>/dev/null || true
cp "$WORK"/*.log "$WORK"/*.parse.out "$RUN_DIR/logs/" 2>/dev/null || true
{ echo "suite=matrix"; echo "mode=$MODE"; echo "date=$(date -u +%FT%TZ)"; \
  echo "git=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null)"; echo "binary=$BIN"; } > "$RUN_DIR/meta.txt"
green "REPORT: $RUN_DIR"
info  "  report.txt | report.json | dumps/<case>/ | logs/<case>.*.log"
exit $rc
```

- [ ] **Step 5: Run the http1 row to verify the whole pipeline (eBPF)**

Run: `cargo build -p mymitm --release && sudo bash tests/integration/protocols/run_matrix.sh --only http1`
Expected: the matrix prints a row `http1  A  PIPE  ✓  ✓  2  PASS  ...`. (Other rows show ERROR because `--only` skipped them — that is expected; the walking skeleton is proven by the `http1 ... PASS` line and `[http1] fwd=ok dump=ok level=2 srcip=ok`.)

- [ ] **Step 6: Run the http1 row under iproute**

Run: `sudo bash tests/integration/protocols/run_matrix.sh --mode iproute --only http1`
Expected: same `http1 ... PASS` line, `srcip=ok`.

- [ ] **Step 7: Commit**

```bash
git add tests/integration/protocols/_util.py tests/integration/protocols/cases/ tests/integration/protocols/run_matrix.sh
git commit -m "test(protocols): matrix driver + http1 walking skeleton"
```

---

## Task 6: `cases/http1_0.py` + `cases/keepalive.py`

**Files:**
- Create: `tests/integration/protocols/cases/http1_0.py`
- Create: `tests/integration/protocols/cases/keepalive.py`

**Interfaces:**
- Consumes: `_util.case_main`, `_util.connect_tls`/`server_ctx`/`client_ctx`/`read_conn`, `dumpparse.http1.parse_exchange`. No new produced symbols.

- [ ] **Step 1: Run the matrix for the two new rows to verify they ERROR (RED)**

Run: `sudo bash tests/integration/protocols/run_matrix.sh --only http1_0` then `--only keepalive`
Expected: each prints its row as `ERROR` (case module does not exist yet → server never ready).

- [ ] **Step 2: Create `cases/http1_0.py`**

```python
#!/usr/bin/env python3
"""HTTP/1.0: response body delimited by connection close (no Content-Length)."""
import os, socket, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _util
from dumpparse.http1 import parse_exchange

BODY = b"http10-eof-delimited-body-payload"


def run_server(a):
    ctx = _util.server_ctx(a.cert, a.key)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.bind, a.port)); srv.listen(8)
    with open(a.ready, "w") as fh:
        fh.write("ready\n")
    while True:
        raw, peer = srv.accept()
        with open(a.peerfile, "a") as fh:
            fh.write(peer[0] + "\n")
        try:
            tls = ctx.wrap_socket(raw, server_side=True)
        except OSError:
            raw.close(); continue
        try:
            tls.recv(4096)  # consume request line/headers
            # HTTP/1.0, no Content-Length: body ends when we close the socket.
            tls.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n" + BODY)
        except OSError:
            pass
        finally:
            try:
                tls.close()  # close == EOF that delimits the body
            except OSError:
                pass


def run_client(a):
    ctx = _util.client_ctx(a.cafile)
    tls = _util.connect_tls(ctx, a.host, a.port, a.server_name, a.bind_addr)
    tls.sendall(b"GET / HTTP/1.0\r\nHost: " + a.server_name.encode() + b"\r\n\r\n")
    chunks = []
    while True:
        d = tls.recv(4096)
        if not d:
            break
        chunks.append(d)
    tls.close()
    resp = b"".join(chunks)
    if resp.startswith(b"HTTP/1.0 200") and resp.endswith(BODY):
        print("FORWARD_OK http1.0 eof-delimited body"); return 0
    print(f"FORWARD_FAIL got={resp[:80]!r}"); return 1


def run_parse(a):
    _, c2s, s2c, _ = _util.read_conn(a.dump_dir)
    p = parse_exchange(c2s, s2c)
    if p.error:
        print(f"DUMP_FAIL {p.error}"); return
    if p.responses and p.responses[0].status == 200 and p.responses[0].body == BODY:
        print(f"DUMP_OK level={p.level}")
    else:
        print(f"DUMP_PARTIAL level={p.level} resp={[(r.status, len(r.body)) for r in p.responses]}")


if __name__ == "__main__":
    _util.case_main(run_server, run_client, run_parse)
```

- [ ] **Step 3: Create `cases/keepalive.py`**

```python
#!/usr/bin/env python3
"""Keep-alive: >=5 requests on ONE connection; the dump parser must walk all."""
import http.client, os, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _util
from dumpparse.http1 import parse_exchange

N_REQ = 5


def run_server(a):
    peerfile = a.peerfile

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            with open(peerfile, "a") as fh:
                fh.write(self.client_address[0] + "\n")
            body = ("resp" + self.path).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a_):
            pass

    httpd = ThreadingHTTPServer((a.bind, a.port), H)
    httpd.socket = _util.server_ctx(a.cert, a.key).wrap_socket(httpd.socket, server_side=True)
    with open(a.ready, "w") as fh:
        fh.write("ready\n")
    httpd.serve_forever()


def run_client(a):
    ctx = _util.client_ctx(a.cafile)
    tls = _util.connect_tls(ctx, a.host, a.port, a.server_name, a.bind_addr)
    conn = http.client.HTTPSConnection(a.server_name, a.port, context=ctx, timeout=15)
    conn.sock = tls
    statuses = []
    for i in range(N_REQ):
        conn.request("GET", f"/{i}")
        r = conn.getresponse()
        body = r.read()
        statuses.append((r.status, body == f"resp/{i}".encode()))
    conn.close()
    if len(statuses) == N_REQ and all(s == 200 and okbody for s, okbody in statuses):
        print(f"FORWARD_OK keepalive {N_REQ} requests one connection"); return 0
    print(f"FORWARD_FAIL statuses={statuses}"); return 1


def run_parse(a):
    _, c2s, s2c, _ = _util.read_conn(a.dump_dir)
    p = parse_exchange(c2s, s2c)
    if p.error:
        print(f"DUMP_FAIL {p.error}"); return
    if len(p.requests) >= N_REQ and len([r for r in p.responses if r.status == 200]) >= N_REQ:
        print(f"DUMP_OK level={p.level} walked {len(p.requests)} reqs / {len(p.responses)} resps")
    else:
        print(f"DUMP_PARTIAL level={p.level} reqs={len(p.requests)} resps={len(p.responses)}")


if __name__ == "__main__":
    _util.case_main(run_server, run_client, run_parse)
```

- [ ] **Step 4: Run both rows to verify they PASS (GREEN)**

Run: `sudo bash tests/integration/protocols/run_matrix.sh --only http1_0` then `--only keepalive`
Expected: `http1_0 ... ✓ ✓ 2 PASS` and `keepalive ... ✓ ✓ 2 PASS`, each `srcip=ok`.

- [ ] **Step 5: Commit**

```bash
git add tests/integration/protocols/cases/http1_0.py tests/integration/protocols/cases/keepalive.py
git commit -m "test(protocols): http/1.0 EOF-body + keep-alive multi-request cases"
```

---

## Task 7: `cases/streaming.py` — chunked long-lived, incremental delivery

**Files:**
- Create: `tests/integration/protocols/cases/streaming.py`

**Interfaces:**
- Consumes: `_util.*`, `dumpparse.http1.parse_exchange`. The forward assertion proves **incremental delivery** (arrival spread over wall-clock time, i.e. no head-of-line buffering in the pipe); the dump assertion proves dechunk reassembly (L2).

- [ ] **Step 1: Run to verify ERROR (RED)**

Run: `sudo bash tests/integration/protocols/run_matrix.sh --only streaming`
Expected: `streaming ... ERROR`.

- [ ] **Step 2: Create `cases/streaming.py`**

```python
#!/usr/bin/env python3
"""Chunked, long-lived response streamed with gaps; client must see it arrive
incrementally (proves the byte pipe does not buffer-before-forward)."""
import http.client, os, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _util
from dumpparse.http1 import parse_exchange

CHUNKS = [b"chunk-%02d\n" % i for i in range(10)]
FULL = b"".join(CHUNKS)
GAP = 0.05


def run_server(a):
    peerfile = a.peerfile

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            with open(peerfile, "a") as fh:
                fh.write(self.client_address[0] + "\n")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for c in CHUNKS:
                self.wfile.write(b"%X\r\n%b\r\n" % (len(c), c))
                self.wfile.flush()
                time.sleep(GAP)
            self.wfile.write(b"0\r\n\r\n"); self.wfile.flush()

        def log_message(self, *a_):
            pass

    httpd = ThreadingHTTPServer((a.bind, a.port), H)
    httpd.socket = _util.server_ctx(a.cert, a.key).wrap_socket(httpd.socket, server_side=True)
    with open(a.ready, "w") as fh:
        fh.write("ready\n")
    httpd.serve_forever()


def run_client(a):
    ctx = _util.client_ctx(a.cafile)
    tls = _util.connect_tls(ctx, a.host, a.port, a.server_name, a.bind_addr)
    conn = http.client.HTTPSConnection(a.server_name, a.port, context=ctx, timeout=20)
    conn.sock = tls
    conn.request("GET", "/stream")
    r = conn.getresponse()
    buf = b""; times = []; t0 = time.monotonic()
    while True:
        d = r.read(16)
        if not d:
            break
        buf += d; times.append(time.monotonic() - t0)
    conn.close()
    spread = (times[-1] - times[0]) if len(times) > 1 else 0.0
    if r.status == 200 and buf == FULL and spread > 0.1:
        print(f"FORWARD_OK streaming incremental spread={spread:.2f}s"); return 0
    print(f"FORWARD_FAIL status={r.status} len={len(buf)}/{len(FULL)} spread={spread:.2f}"); return 1


def run_parse(a):
    _, c2s, s2c, _ = _util.read_conn(a.dump_dir)
    p = parse_exchange(c2s, s2c)
    if p.error:
        print(f"DUMP_FAIL {p.error}"); return
    if p.responses and p.responses[0].body == FULL:
        print(f"DUMP_OK level={p.level} dechunked {len(FULL)} bytes")
    else:
        print(f"DUMP_PARTIAL level={p.level} body={len(p.responses[0].body) if p.responses else 0}/{len(FULL)}")


if __name__ == "__main__":
    _util.case_main(run_server, run_client, run_parse)
```

- [ ] **Step 3: Run to verify PASS (GREEN)**

Run: `sudo bash tests/integration/protocols/run_matrix.sh --only streaming`
Expected: `streaming ... ✓ ✓ 2 PASS`; log shows `spread=` well above 0.1s (≈0.45s).

- [ ] **Step 4: Commit**

```bash
git add tests/integration/protocols/cases/streaming.py
git commit -m "test(protocols): chunked streaming incremental-delivery case"
```

---

## Task 8: `cases/pump.py` — full-duplex + idle + large reassembly (flagship pipe test)

**Files:**
- Create: `tests/integration/protocols/cases/pump.py`

**Scope note (read before implementing):** This is the most important *correctness* test for a byte pipe, grounded in `proxy.rs:253,265`. It deterministically exercises: (a) **full-duplex** — client uploads while concurrently downloading; (b) **idle** — a 0.5 s mid-stream gap must not trigger a timeout; (c) **large reassembly** — 200 KiB each way crosses the proxy's 16 KiB pump-chunk boundary; (d) **app-level end signaling** — the client marks end-of-send with a sentinel and the server replies only after receiving the complete upload. **Deferred:** true TCP/TLS *half-close* FIN propagation (proxy's `shutdown(peer_write)` on `Ok(0)`) is **not** asserted here — Python's `ssl` cannot cleanly half-close one direction (no per-direction `close_notify`), and a bare `SHUT_WR` sends a TCP FIN without `close_notify` that rustls may treat as truncation. Half-close propagation moves to P1 with a raw client that can emit a proper TLS half-close (or a Rust integration test). This is a documented harness limitation, not a proxy defect.

**Interfaces:**
- Consumes: `_util.server_ctx`/`client_ctx`/`connect_tls`/`read_conn`, `_util.case_main`. Dump parse is raw byte-equality (no protocol parser) → level 1.

- [ ] **Step 1: Run to verify ERROR (RED)**

Run: `sudo bash tests/integration/protocols/run_matrix.sh --only pump`
Expected: `pump ... ERROR`.

- [ ] **Step 2: Create `cases/pump.py`**

```python
#!/usr/bin/env python3
"""Byte-pipe correctness: concurrent full-duplex transfer, a mid-stream idle
gap, and 200 KiB each way (crosses the proxy's 16 KiB pump chunk). End-of-upload
is signaled at the application layer (SENTINEL) so no TLS half-close is needed."""
import os, socket, sys, threading, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _util

C2S_BODY = (b"C2S-" * 50000)[:200000]
SENTINEL = b"<<C2S-END>>"
C2S = C2S_BODY + SENTINEL
S2C = (b"S2C-" * 50000)[:200000]
TRAILER = b"<<S2C-DONE>>"


def _serve_conn(tls):
    recv = bytearray()

    def reader():
        while True:
            try:
                d = tls.recv(65536)
            except OSError:
                break
            if not d:
                break
            recv.extend(d)
            if recv.endswith(SENTINEL):
                break

    rt = threading.Thread(target=reader); rt.start()
    try:
        half = len(S2C) // 2
        tls.sendall(S2C[:half])
        time.sleep(0.5)                 # idle mid-stream; must not time out
        tls.sendall(S2C[half:])
        rt.join(timeout=15)
        tls.sendall(TRAILER if bytes(recv) == C2S else b"<<S2C-BADUP>>")
    except OSError:
        pass
    finally:
        try:
            tls.close()
        except OSError:
            pass


def run_server(a):
    ctx = _util.server_ctx(a.cert, a.key)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.bind, a.port)); srv.listen(8)
    with open(a.ready, "w") as fh:
        fh.write("ready\n")
    while True:
        raw, peer = srv.accept()
        with open(a.peerfile, "a") as fh:
            fh.write(peer[0] + "\n")
        try:
            tls = ctx.wrap_socket(raw, server_side=True)
        except OSError:
            raw.close(); continue
        threading.Thread(target=_serve_conn, args=(tls,), daemon=True).start()


def run_client(a):
    ctx = _util.client_ctx(a.cafile)
    tls = _util.connect_tls(ctx, a.host, a.port, a.server_name, a.bind_addr, timeout=30)
    err = []

    def writer():
        try:
            tls.sendall(C2S)            # upload while the reader below downloads
        except OSError as e:
            err.append(str(e))

    wt = threading.Thread(target=writer); wt.start()
    recv = bytearray()
    while True:
        try:
            d = tls.recv(65536)
        except OSError:
            break
        if not d:
            break
        recv.extend(d)
        if recv.endswith(TRAILER):
            break
    wt.join(timeout=15)
    try:
        tls.close()
    except OSError:
        pass
    data = bytes(recv)
    if data == S2C + TRAILER:
        print(f"FORWARD_OK pump full-duplex+idle+large ({len(data)} B down, {len(C2S)} B up)"); return 0
    print(f"FORWARD_FAIL down={len(data)}/{len(S2C) + len(TRAILER)} err={err} tail={data[-16:]!r}"); return 1


def run_parse(a):
    _, c2s, s2c, _ = _util.read_conn(a.dump_dir)
    if c2s == C2S and s2c == S2C + TRAILER:
        print("DUMP_OK level=1 raw byte-exact both directions")
    else:
        print(f"DUMP_PARTIAL level=1 c2s={len(c2s)}/{len(C2S)} s2c={len(s2c)}/{len(S2C) + len(TRAILER)}")


if __name__ == "__main__":
    _util.case_main(run_server, run_client, run_parse)
```

- [ ] **Step 3: Run to verify PASS (GREEN)**

Run: `sudo bash tests/integration/protocols/run_matrix.sh --only pump`
Expected: `pump ... ✓ ✓ 1 PASS`; log shows `200000 B down, 200011 B up`.

- [ ] **Step 4: Commit**

```bash
git add tests/integration/protocols/cases/pump.py
git commit -m "test(protocols): pump full-duplex/idle/large byte-pipe correctness"
```

---

## Task 9: `cases/sse.py` — Server-Sent Events

**Files:**
- Create: `tests/integration/protocols/cases/sse.py`

**Scope note:** A **bounded** event stream (N events + chunk terminator, then close) so the dump holds a complete chunked response that `h11` parses cleanly. This still proves incremental delivery (arrival time-spread) + event-stream parseability — the P0 goal. Unbounded / client-closes-early SSE is a P2 refinement.

**Interfaces:**
- Consumes: `_util.*`, `dumpparse.http1.parse_exchange`, `dumpparse.eventstream.parse_events`.

- [ ] **Step 1: Run to verify ERROR (RED)**

Run: `sudo bash tests/integration/protocols/run_matrix.sh --only sse`
Expected: `sse ... ERROR`.

- [ ] **Step 2: Create `cases/sse.py`**

```python
#!/usr/bin/env python3
"""Server-Sent Events over HTTP/1.1: incremental text/event-stream delivery,
then parse the dumped body back into events. Passing is a differentiator vs
mitmproxy (which buffers + warns on SSE)."""
import http.client, os, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _util
from dumpparse.http1 import parse_exchange
from dumpparse.eventstream import parse_events

N_EVENTS = 10
GAP = 0.03


def run_server(a):
    peerfile = a.peerfile

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            with open(peerfile, "a") as fh:
                fh.write(self.client_address[0] + "\n")
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()

            def w(b):
                self.wfile.write(b"%X\r\n%b\r\n" % (len(b), b)); self.wfile.flush()

            w(b": stream open\n\n")
            for i in range(N_EVENTS):
                w(b"event: tick\ndata: %d\nid: %d\n\n" % (i, i))
                time.sleep(GAP)
            self.wfile.write(b"0\r\n\r\n"); self.wfile.flush()

        def log_message(self, *a_):
            pass

    httpd = ThreadingHTTPServer((a.bind, a.port), H)
    httpd.socket = _util.server_ctx(a.cert, a.key).wrap_socket(httpd.socket, server_side=True)
    with open(a.ready, "w") as fh:
        fh.write("ready\n")
    httpd.serve_forever()


def run_client(a):
    ctx = _util.client_ctx(a.cafile)
    tls = _util.connect_tls(ctx, a.host, a.port, a.server_name, a.bind_addr, timeout=20)
    conn = http.client.HTTPSConnection(a.server_name, a.port, context=ctx, timeout=20)
    conn.sock = tls
    conn.request("GET", "/events")
    r = conn.getresponse()
    buf = b""; times = []; t0 = time.monotonic()
    while True:
        d = r.read(32)
        if not d:
            break
        buf += d; times.append(time.monotonic() - t0)
    conn.close()
    ticks = [e for e in parse_events(buf) if e["event"] == "tick"]
    spread = (times[-1] - times[0]) if len(times) > 1 else 0.0
    if r.status == 200 and len(ticks) >= N_EVENTS and spread > 0.1:
        print(f"FORWARD_OK sse {len(ticks)} events spread={spread:.2f}s"); return 0
    print(f"FORWARD_FAIL status={r.status} ticks={len(ticks)}/{N_EVENTS} spread={spread:.2f}"); return 1


def run_parse(a):
    _, c2s, s2c, _ = _util.read_conn(a.dump_dir)
    p = parse_exchange(c2s, s2c)
    if p.error:
        print(f"DUMP_FAIL {p.error}"); return
    if not p.responses or "event-stream" not in (p.responses[0].header("content-type") or ""):
        print(f"DUMP_PARTIAL level={p.level} not-event-stream"); return
    ticks = [e for e in parse_events(p.responses[0].body) if e["event"] == "tick"]
    if len(ticks) >= N_EVENTS:
        print(f"DUMP_OK level={p.level} parsed {len(ticks)} SSE events")
    else:
        print(f"DUMP_PARTIAL level={p.level} ticks={len(ticks)}/{N_EVENTS}")


if __name__ == "__main__":
    _util.case_main(run_server, run_client, run_parse)
```

- [ ] **Step 3: Run to verify PASS (GREEN)**

Run: `sudo bash tests/integration/protocols/run_matrix.sh --only sse`
Expected: `sse ... ✓ ✓ 2 PASS`; log shows ≥10 events, `spread≈0.3s`.

- [ ] **Step 4: Commit**

```bash
git add tests/integration/protocols/cases/sse.py
git commit -m "test(protocols): SSE incremental delivery + event-stream parse"
```

---

## Task 10: `cases/sigv4.py` + `test_sigv4.py` — request-integrity probe

**Files:**
- Create: `tests/integration/protocols/cases/sigv4.py`
- Test: `tests/integration/protocols/test_sigv4.py`

**Why:** A SigV4 signature hashes the canonical request (method, path, sorted signed headers with exact names/casing, payload hash). If the server independently recomputes it from the bytes it received and it still matches, the proxy provably preserved the request byte-exact. The sign/validate logic is factored into importable functions and validated **in-process** by pytest first (no proxy), so botocore behavior is pinned before the netns run.

**Interfaces:**
- Produces: `cases.sigv4.sign_headers(method, url, body) -> (dict, bytes)`; `cases.sigv4.validate_headers(method, url, headers, body) -> bool`; `cases.sigv4.presign(method, url) -> str`; `cases.sigv4.validate_presigned(method, full_url, host) -> bool`.
- Consumes: `botocore` (auth + awsrequest + credentials), `_util.*`, `dumpparse.http1`.

- [ ] **Step 1: Write the failing in-process test**

`tests/integration/protocols/test_sigv4.py`:
```python
from cases.sigv4 import sign_headers, validate_headers, presign, validate_presigned

HOST = "server.test"


def test_header_auth_roundtrip_and_tamper():
    body = b"PUT-body-bytes"
    headers, out_body = sign_headers("PUT", f"https://{HOST}/bucket/key", body)
    url = f"https://{HOST}/bucket/key"
    assert validate_headers("PUT", url, headers, out_body) is True
    # Any byte change to the signed request must break validation:
    assert validate_headers("PUT", url, headers, out_body + b"x") is False
    assert validate_headers("POST", url, headers, out_body) is False


def test_presigned_roundtrip_and_tamper():
    purl = presign("GET", f"https://{HOST}/bucket/obj")
    assert validate_presigned("GET", purl, HOST) is True
    assert validate_presigned("GET", purl.replace("bucket", "bukket"), HOST) is False
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd tests/integration/protocols && python3 -m pytest test_sigv4.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'cases.sigv4'`.

- [ ] **Step 3: Implement `cases/sigv4.py`**

```python
#!/usr/bin/env python3
"""AWS SigV4 (header + presigned) integrity probe.

The server independently recomputes the signature over the bytes it received and
compares it to the client's; a match proves the proxy did not reorder headers,
change casing, alter the body, or re-chunk. Logic is importable + unit-tested by
test_sigv4.py; the netns run then proves byte-transparency through the pipe."""
import http.client, os, sys
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _util
from dumpparse.http1 import parse_exchange
from botocore.auth import SigV4Auth, SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

CREDS = Credentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
REGION = "us-east-1"
SERVICE = "mymitmtest"


# ---- signing (client) ----------------------------------------------------
def sign_headers(method, url, body):
    req = AWSRequest(method=method, url=url, data=body, headers={})
    SigV4Auth(CREDS, SERVICE, REGION).add_auth(req)
    p = req.prepare()
    return dict(p.headers), (p.body if isinstance(p.body, (bytes, bytearray)) else body)


def presign(method, url):
    req = AWSRequest(method=method, url=url, data=b"", headers={})
    SigV4QueryAuth(CREDS, SERVICE, REGION, expires=300).add_auth(req)
    return req.prepare().url


# ---- validation (server) -------------------------------------------------
def _parse_authz(authz):
    body = authz[len("AWS4-HMAC-SHA256 "):]
    out = {}
    for part in body.split(", "):
        k, v = part.split("=", 1)
        out[k] = v
    return out


def validate_headers(method, url, headers, body):
    low = {k.lower(): v for k, v in headers.items()}
    authz = low.get("authorization")
    amz_date = low.get("x-amz-date")
    if not authz or not authz.startswith("AWS4-HMAC-SHA256 ") or not amz_date:
        return False
    parsed = _parse_authz(authz)
    signed = parsed["SignedHeaders"].split(";")
    # SigV4 signs `host` as the URL authority; it may not appear as a literal
    # header in the captured set, so derive it from the request URL when absent.
    if "host" not in low:
        low["host"] = urlsplit(url).netloc
    rebuilt = {h: low.get(h) for h in signed}
    if any(v is None for v in rebuilt.values()):
        return False
    req = AWSRequest(method=method, url=url, data=body, headers=rebuilt)
    auth = SigV4Auth(CREDS, SERVICE, REGION)
    req.context["timestamp"] = amz_date
    cr = auth.canonical_request(req)
    sts = auth.string_to_sign(req, cr)
    return auth.signature(sts, req) == parsed["Signature"]


def validate_presigned(method, full_url, host):
    parts = urlsplit(full_url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    recv_sig = dict(pairs).get("X-Amz-Signature")
    amz_date = dict(pairs).get("X-Amz-Date")
    if not recv_sig or not amz_date:
        return False
    kept = [(k, v) for k, v in pairs if k != "X-Amz-Signature"]
    url_wo = urlunsplit((parts.scheme or "https", host, parts.path, urlencode(kept), ""))
    req = AWSRequest(method=method, url=url_wo, data=b"", headers={"host": host})
    auth = SigV4QueryAuth(CREDS, SERVICE, REGION)
    req.context["timestamp"] = amz_date
    cr = auth.canonical_request(req)
    sts = auth.string_to_sign(req, cr)
    return auth.signature(sts, req) == recv_sig


# ---- roles ---------------------------------------------------------------
def run_server(a):
    peerfile = a.peerfile
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _ok(self, valid):
            body = b"SIGV4_OK" if valid else b"SIGV4_BAD"
            self.send_response(200 if valid else 401)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)

        def _host(self):
            return self.headers.get("Host", "server.test")

        def do_PUT(self):
            with open(peerfile, "a") as fh:
                fh.write(self.client_address[0] + "\n")
            n = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(n) if n else b""
            url = f"https://{self._host()}{self.path}"
            self._ok(validate_headers("PUT", url, dict(self.headers.items()), body))

        def do_GET(self):
            with open(peerfile, "a") as fh:
                fh.write(self.client_address[0] + "\n")
            full = f"https://{self._host()}{self.path}"
            self._ok(validate_presigned("GET", full, self._host()))

        def log_message(self, *a_):
            pass

    httpd = ThreadingHTTPServer((a.bind, a.port), H)
    httpd.socket = _util.server_ctx(a.cert, a.key).wrap_socket(httpd.socket, server_side=True)
    with open(a.ready, "w") as fh:
        fh.write("ready\n")
    httpd.serve_forever()


def run_client(a):
    ctx = _util.client_ctx(a.cafile)
    tls = _util.connect_tls(ctx, a.host, a.port, a.server_name, a.bind_addr)
    conn = http.client.HTTPSConnection(a.server_name, a.port, context=ctx, timeout=15)
    conn.sock = tls
    # (1) header-auth PUT
    body = b"sigv4-put-body"
    headers, out_body = sign_headers("PUT", f"https://{a.server_name}/bucket/key", body)
    send_h = {k: v for k, v in headers.items() if k.lower() != "host"}
    conn.request("PUT", "/bucket/key", body=out_body, headers=send_h)
    r1 = conn.getresponse(); b1 = r1.read()
    # (2) presigned GET
    purl = presign("GET", f"https://{a.server_name}/bucket/obj")
    sp = urlsplit(purl)
    conn.request("GET", sp.path + "?" + sp.query)
    r2 = conn.getresponse(); b2 = r2.read()
    conn.close()
    if r1.status == 200 and b1 == b"SIGV4_OK" and r2.status == 200 and b2 == b"SIGV4_OK":
        print("FORWARD_OK sigv4 header+presigned validated byte-exact"); return 0
    print(f"FORWARD_FAIL put=({r1.status},{b1!r}) get=({r2.status},{b2!r})"); return 1


def run_parse(a):
    _, c2s, s2c, _ = _util.read_conn(a.dump_dir)
    p = parse_exchange(c2s, s2c)
    if p.error:
        print(f"DUMP_FAIL {p.error}"); return
    has_authz = b"AWS4-HMAC-SHA256" in c2s
    has_qsig = b"X-Amz-Signature" in c2s
    oks = [r.status for r in p.responses if r.status == 200]
    if len(p.requests) >= 2 and len(oks) >= 2 and has_authz and has_qsig:
        print(f"DUMP_OK level={p.level} authz+presigned recovered, {len(oks)} x 200")
    else:
        print(f"DUMP_PARTIAL level={p.level} reqs={len(p.requests)} oks={len(oks)} authz={has_authz} qsig={has_qsig}")


if __name__ == "__main__":
    _util.case_main(run_server, run_client, run_parse)
```

- [ ] **Step 4: Run the in-process test to verify it passes**

Run: `cd tests/integration/protocols && python3 -m pytest test_sigv4.py -q`
Expected: PASS (2 passed). If a botocore version difference breaks canonicalization parity, fix `validate_headers`/`validate_presigned` here until the tamper tests pass — this is the deterministic gate before the netns run.

- [ ] **Step 5: Run the netns row to verify PASS (GREEN)**

Run: `sudo bash tests/integration/protocols/run_matrix.sh --only sigv4`
Expected: `sigv4 ... ✓ ✓ 2 PASS` — the server accepted both signatures **through the proxy**, proving byte-transparency.

- [ ] **Step 6: Commit**

```bash
git add tests/integration/protocols/cases/sigv4.py tests/integration/protocols/test_sigv4.py
git commit -m "test(protocols): SigV4 header+presigned request-integrity probe"
```

---

## Task 11: `cases/pinning.py` — cert-pinning / HSTS win (the differentiator)

**Files:**
- Create: `tests/integration/protocols/cases/pinning.py`

**Why:** Because the proxy presents the **genuine** leaf (`with_single_cert` + upstream DER pin), a client that pins the whole leaf certificate **succeeds** — where a CA-forging MITM would fail. HSTS is a header the byte pipe forwards verbatim; we assert it survives into the dump. (The `--cafile` the driver passes *is* the leaf, so the client reads it as the expected pin.)

**Interfaces:**
- Consumes: `_util.*`, `ssl.PEM_cert_to_DER_cert`, `dumpparse.http1`.

- [ ] **Step 1: Run to verify ERROR (RED)**

Run: `sudo bash tests/integration/protocols/run_matrix.sh --only pinning`
Expected: `pinning ... ERROR`.

- [ ] **Step 2: Create `cases/pinning.py`**

```python
#!/usr/bin/env python3
"""Cert-pinning / HSTS win: the proxy presents the GENUINE leaf, so a whole-cert
pin matches (a forging MITM's cert would not). HSTS header forwarded verbatim."""
import http.client, os, ssl, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _util
from dumpparse.http1 import parse_exchange

HSTS = "max-age=31536000; includeSubDomains"
BODY = b"pinned-ok"


def run_server(a):
    peerfile = a.peerfile

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            with open(peerfile, "a") as fh:
                fh.write(self.client_address[0] + "\n")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Strict-Transport-Security", HSTS)
            self.send_header("Content-Length", str(len(BODY)))
            self.end_headers(); self.wfile.write(BODY)

        def log_message(self, *a_):
            pass

    httpd = ThreadingHTTPServer((a.bind, a.port), H)
    httpd.socket = _util.server_ctx(a.cert, a.key).wrap_socket(httpd.socket, server_side=True)
    with open(a.ready, "w") as fh:
        fh.write("ready\n")
    httpd.serve_forever()


def run_client(a):
    ctx = _util.client_ctx(a.cafile)
    tls = _util.connect_tls(ctx, a.host, a.port, a.server_name, a.bind_addr)
    presented = tls.getpeercert(binary_form=True)
    with open(a.cafile) as fh:
        expected = ssl.PEM_cert_to_DER_cert(fh.read())
    pin_ok = presented == expected
    conn = http.client.HTTPSConnection(a.server_name, a.port, context=ctx, timeout=15)
    conn.sock = tls
    conn.request("GET", "/")
    r = conn.getresponse(); body = r.read()
    hsts = r.getheader("Strict-Transport-Security")
    conn.close()
    if pin_ok and r.status == 200 and body == BODY and hsts == HSTS:
        print("FORWARD_OK pinning genuine-leaf pin matched + HSTS present"); return 0
    print(f"FORWARD_FAIL pin_ok={pin_ok} status={r.status} hsts={hsts!r}"); return 1


def run_parse(a):
    _, c2s, s2c, _ = _util.read_conn(a.dump_dir)
    p = parse_exchange(c2s, s2c)
    if p.error:
        print(f"DUMP_FAIL {p.error}"); return
    if (p.responses and p.responses[0].status == 200
            and p.responses[0].header("strict-transport-security") == HSTS):
        print(f"DUMP_OK level={p.level} HSTS header recovered from dump")
    else:
        print(f"DUMP_PARTIAL level={p.level}")


if __name__ == "__main__":
    _util.case_main(run_server, run_client, run_parse)
```

- [ ] **Step 3: Run to verify PASS (GREEN)**

Run: `sudo bash tests/integration/protocols/run_matrix.sh --only pinning`
Expected: `pinning ... ✓ ✓ 2 PASS`; client log `pin matched + HSTS present`.

- [ ] **Step 4: Commit**

```bash
git add tests/integration/protocols/cases/pinning.py
git commit -m "test(protocols): cert-pinning + HSTS win (genuine-leaf differentiator)"
```

---

## Task 12: `cases/lifecycle_client.py` + `run_matrix.sh` custom orchestration

The lifecycle rows assert behavior that depends on **proxy attach/detach timing**, so the sequencing lives in bash (which owns proxy lifecycle); the Python side is just a controllable client.

- **newconn** — proxy attached, fresh connection → intercepted (`ok`/`ok`).
- **preexisting** — connection established **before** the proxy attaches (plain-routed), then a mid-stream request **after** attach → the flag-agnostic divert (`lib.rs:65`) DNATs a packet to a socket that never saw the SYN → kernel RST → `fail` (documented). **eBPF-only:** under iproute the conntrack entry for the pre-existing flow has no DNAT, so the flow may survive — different, arguably better, behavior; asserted under `ebpf`, **SKIP** under `iproute` with reason.
- **restart** — connection intercepted, proxy restarted mid-connection → in-flight drops (`fail`); a fresh connection afterward recovers (logged).

**Files:**
- Create: `tests/integration/protocols/cases/lifecycle_client.py`
- Modify: `tests/integration/protocols/run_matrix.sh` (replace the `run_custom` placeholder from Task 5 with real orchestration)

**Interfaces:**
- Produces: `lifecycle_client.py` CLI — `once --cafile --host --port --server-name --bind-addr` (single request; prints `FORWARD_OK`/`FORWARD_FAIL`) and `hold ... --connected FILE --go FILE` (connect + first request, write `connected`, wait for `go`, second request on the same connection; prints `SECOND_OK`/`SECOND_RESET`).

- [ ] **Step 1: Run to verify the three rows ERROR (RED)**

Run: `sudo bash tests/integration/protocols/run_matrix.sh --only newconn`
Expected: `newconn ... ERROR` (placeholder `run_custom` emits err).

- [ ] **Step 2: Create `cases/lifecycle_client.py`**

```python
#!/usr/bin/env python3
"""Controllable TLS client for the bash-orchestrated lifecycle scenarios."""
import argparse, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _util


def _get(tls, path, server_name):
    try:
        tls.sendall(b"GET " + path.encode() + b" HTTP/1.1\r\nHost: "
                    + server_name.encode() + b"\r\nConnection: keep-alive\r\n\r\n")
        tls.settimeout(5)
        data = b""
        while b"\r\n\r\n" not in data:
            d = tls.recv(4096)
            if not d:
                break
            data += d
        return data
    except OSError:
        return None


def cmd_once(a):
    ctx = _util.client_ctx(a.cafile)
    try:
        tls = _util.connect_tls(ctx, a.host, a.port, a.server_name, a.bind_addr)
    except OSError as e:
        print(f"FORWARD_FAIL connect: {e}"); return 1
    resp = _get(tls, "/once", a.server_name)
    try:
        tls.close()
    except OSError:
        pass
    if resp and b" 200 " in resp:
        print("FORWARD_OK newconn intercepted"); return 0
    print(f"FORWARD_FAIL resp={resp!r}"); return 1


def cmd_hold(a):
    ctx = _util.client_ctx(a.cafile)
    try:
        tls = _util.connect_tls(ctx, a.host, a.port, a.server_name, a.bind_addr)
    except OSError as e:
        print(f"HOLD_CONNECT_FAIL {e}"); return 1
    first = _get(tls, "/first", a.server_name)
    if not (first and b" 200 " in first):
        print(f"HOLD_INITIAL_FAIL resp={first!r}")
        try:
            tls.close()
        except OSError:
            pass
        return 1
    with open(a.connected, "w") as fh:
        fh.write("ok\n")
    for _ in range(200):
        if os.path.exists(a.go):
            break
        time.sleep(0.1)
    second = _get(tls, "/second", a.server_name)
    try:
        tls.close()
    except OSError:
        pass
    if second and b" 200 " in second:
        print("SECOND_OK"); return 0
    print("SECOND_RESET"); return 2


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("once", "hold"):
        s = sub.add_parser(name)
        for f in ("--cafile", "--host", "--server-name"):
            s.add_argument(f, required=True)
        s.add_argument("--port", type=int, required=True)
        s.add_argument("--bind-addr", default=None)
        if name == "hold":
            s.add_argument("--connected", required=True)
            s.add_argument("--go", required=True)
    a = ap.parse_args()
    sys.exit(cmd_once(a) if a.cmd == "once" else cmd_hold(a))


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Replace the `run_custom` placeholder in `run_matrix.sh`**

Replace this block (added in Task 5):

```bash
# Placeholder for custom lifecycle cases; replaced in Task 12.
run_custom() { warn "[$1] custom lifecycle case not yet implemented"; emit "$1" err err 0 ""; }
```

with:

```bash
# --- custom lifecycle orchestration ---------------------------------------
_lc_server() {  # start the generic http1 server; args: <ready> <peer> <log>
  ip netns exec "$NS_SRV" env PYTHONPATH="$PROTO_DIR" python3 "$PROTO_DIR/cases/http1.py" server \
    --cert "$CERT" --key "$KEY" --bind "$SERVER_IP" --port 443 \
    --ready "$1" --peerfile "$2" >"$3" 2>&1 &
  echo $!
}

lc_newconn() {
  local dump="$WORK/dumps"; rm -rf "$dump"; mkdir -p "$dump"
  local ready="$WORK/newconn.ready" peer="$WORK/newconn.peer"; rm -f "$ready"; : > "$peer"
  write_toml "$TOML" "$MODE" "$CERT" "$KEY" "$dump"
  local spid; spid="$(_lc_server "$ready" "$peer" "$WORK/newconn.server.log")"
  wait_file "$ready" || { kill "$spid" 2>/dev/null; emit newconn err err 0 ""; return; }
  start_proxy "$TOML" "$WORK/newconn.proxy.log"
  wait_proxy "$WORK/newconn.proxy.log" || { stop_proxy; kill "$spid" 2>/dev/null; emit newconn err err 0 ""; return; }
  ip netns exec "$NS_CLI" env PYTHONPATH="$PROTO_DIR" python3 "$PROTO_DIR/cases/lifecycle_client.py" once \
    --cafile "$CERT" --host "$SERVER_IP" --port 443 --server-name "$SERVER_NAME" --bind-addr "$CLIENT_IP" \
    >"$WORK/newconn.client.log" 2>&1
  local crc=$?; stop_proxy; kill "$spid" 2>/dev/null; wait "$spid" 2>/dev/null
  local afwd=fail; { [ $crc -eq 0 ] && grep -q FORWARD_OK "$WORK/newconn.client.log"; } && afwd=ok
  local adump=fail alvl=0; if grep -rq "GET /once" "$dump" 2>/dev/null; then adump=ok; alvl=2; fi
  local srcip=missing; if grep -qF "$BOX_IP" "$peer"; then srcip=BOXLEAK; elif grep -qF "$CLIENT_IP" "$peer"; then srcip=ok; fi
  cp -r "$dump" "$ART/newconn" 2>/dev/null || true
  emit newconn "$afwd" "$adump" "$alvl" "$srcip"
  info "[newconn] fwd=$afwd dump=$adump srcip=$srcip"
}

lc_preexisting() {
  if [ "$MODE" != ebpf ]; then
    info "[preexisting] SKIP: conntrack path differs under iproute (asserted under ebpf)"
    emit preexisting skip skip 0 na; return
  fi
  local dump="$WORK/dumps"; rm -rf "$dump"; mkdir -p "$dump"
  local ready="$WORK/pre.ready" peer="$WORK/pre.peer"; rm -f "$ready"; : > "$peer"
  local connected="$WORK/pre.connected" go="$WORK/pre.go"; rm -f "$connected" "$go"
  write_toml "$TOML" "$MODE" "$CERT" "$KEY" "$dump"
  local spid; spid="$(_lc_server "$ready" "$peer" "$WORK/pre.server.log")"
  wait_file "$ready" || { kill "$spid" 2>/dev/null; emit preexisting err err 0 na; return; }
  # Client connects + first request while the proxy is NOT yet attached (plain-routed).
  ip netns exec "$NS_CLI" env PYTHONPATH="$PROTO_DIR" python3 "$PROTO_DIR/cases/lifecycle_client.py" hold \
    --cafile "$CERT" --host "$SERVER_IP" --port 443 --server-name "$SERVER_NAME" --bind-addr "$CLIENT_IP" \
    --connected "$connected" --go "$go" >"$WORK/pre.client.log" 2>&1 &
  local cpid=$!
  if ! wait_file "$connected" 100; then
    warn "[preexisting] pre-attach connection never established:"; cat "$WORK/pre.client.log"
    kill "$cpid" "$spid" 2>/dev/null; emit preexisting err err 0 na; return
  fi
  start_proxy "$TOML" "$WORK/pre.proxy.log"
  wait_proxy "$WORK/pre.proxy.log" || { stop_proxy; kill "$cpid" "$spid" 2>/dev/null; emit preexisting err err 0 na; return; }
  touch "$go"                    # release the second (mid-stream) request now that divert is attached
  wait "$cpid" 2>/dev/null
  stop_proxy; kill "$spid" 2>/dev/null; wait "$spid" 2>/dev/null
  local afwd=ok
  grep -q SECOND_RESET "$WORK/pre.client.log" && afwd=fail
  emit preexisting "$afwd" na 0 na
  info "[preexisting] second-request afwd=$afwd (expected fail = reset)"
}

lc_restart() {
  local dump="$WORK/dumps"; rm -rf "$dump"; mkdir -p "$dump"
  local ready="$WORK/rst.ready" peer="$WORK/rst.peer"; rm -f "$ready"; : > "$peer"
  local connected="$WORK/rst.connected" go="$WORK/rst.go"; rm -f "$connected" "$go"
  write_toml "$TOML" "$MODE" "$CERT" "$KEY" "$dump"
  local spid; spid="$(_lc_server "$ready" "$peer" "$WORK/rst.server.log")"
  wait_file "$ready" || { kill "$spid" 2>/dev/null; emit restart err err 0 na; return; }
  start_proxy "$TOML" "$WORK/rst.proxy1.log"
  wait_proxy "$WORK/rst.proxy1.log" || { stop_proxy; kill "$spid" 2>/dev/null; emit restart err err 0 na; return; }
  ip netns exec "$NS_CLI" env PYTHONPATH="$PROTO_DIR" python3 "$PROTO_DIR/cases/lifecycle_client.py" hold \
    --cafile "$CERT" --host "$SERVER_IP" --port 443 --server-name "$SERVER_NAME" --bind-addr "$CLIENT_IP" \
    --connected "$connected" --go "$go" >"$WORK/rst.client.log" 2>&1 &
  local cpid=$!
  if ! wait_file "$connected" 100; then
    warn "[restart] intercepted connection never established:"; cat "$WORK/rst.client.log"
    stop_proxy; kill "$cpid" "$spid" 2>/dev/null; emit restart err err 0 na; return
  fi
  stop_proxy                     # kill the proxy mid-connection
  start_proxy "$TOML" "$WORK/rst.proxy2.log"
  wait_proxy "$WORK/rst.proxy2.log" || { stop_proxy; kill "$cpid" "$spid" 2>/dev/null; emit restart err err 0 na; return; }
  touch "$go"
  wait "$cpid" 2>/dev/null
  local afwd=ok
  grep -q SECOND_RESET "$WORK/rst.client.log" && afwd=fail
  # recovery: a fresh connection through the restarted proxy should work
  ip netns exec "$NS_CLI" env PYTHONPATH="$PROTO_DIR" python3 "$PROTO_DIR/cases/lifecycle_client.py" once \
    --cafile "$CERT" --host "$SERVER_IP" --port 443 --server-name "$SERVER_NAME" --bind-addr "$CLIENT_IP" \
    >"$WORK/rst.newclient.log" 2>&1
  grep -q FORWARD_OK "$WORK/rst.newclient.log" && info "[restart] fresh connection recovered after restart" \
    || warn "[restart] fresh connection did NOT recover"
  stop_proxy; kill "$spid" 2>/dev/null; wait "$spid" 2>/dev/null
  emit restart "$afwd" na 0 na
  info "[restart] in-flight afwd=$afwd (expected fail = dropped)"
}

run_custom() {
  case "$1" in
    newconn)     lc_newconn;;
    preexisting) lc_preexisting;;
    restart)     lc_restart;;
    *) emit "$1" err err 0 "";;
  esac
}
```

- [ ] **Step 4: Run the three rows to verify PASS (GREEN) under eBPF**

Run: `sudo bash tests/integration/protocols/run_matrix.sh --only newconn` then `--only preexisting` then `--only restart`
Expected: `newconn ... ✓ ✓ 2 PASS`; `preexisting ... ✗ n/a - PASS` (reset matched the documented gap); `restart ... ✗ n/a - PASS` (in-flight dropped, log shows `recovered`).

- [ ] **Step 5: Verify the iproute SKIP for preexisting**

Run: `sudo bash tests/integration/protocols/run_matrix.sh --mode iproute --only preexisting`
Expected: `preexisting ... SKIP` with the log line `SKIP: conntrack path differs under iproute`.

- [ ] **Step 6: Commit**

```bash
git add tests/integration/protocols/cases/lifecycle_client.py tests/integration/protocols/run_matrix.sh
git commit -m "test(protocols): connection-lifecycle rows (newconn/preexisting/restart)"
```

---

## Task 13: full-matrix green + report-folder collection + docs/skill wiring

**Files:**
- Modify: `.claude/skills/mymitm-testing/SKILL.md` (Quick-reference row + Running/reading paragraph + Setup line + a Test-report-folder section)
- Modify: `tests/PROTOCOL_COVERAGE.md` (§1 status note: P0 implemented)
- Modify: `tests/vm/lib.sh` + `tests/vm/run.sh` (collect VM B's dumps into the report folder)

- [ ] **Step 1: Run the whole unit suite (no root)**

Run: `cd tests/integration/protocols && python3 -m pytest -q`
Expected: PASS — the dumpparse (http1, eventstream), report, and sigv4 tests all green.

- [ ] **Step 2: Run the full matrix under eBPF (GREEN)**

Run: `cargo build -p mymitm --release && sudo bash tests/integration/protocols/run_matrix.sh`
Expected: every row PASS — `http1/http1_0/keepalive/streaming/pump/sse/sigv4/pinning/newconn` as `✓`, and `preexisting`/`restart` as `✗ n/a` **PASS** (documented gaps matched). Summary `11 PASS   0 FAIL   0 SKIP`. Exit code 0.

- [ ] **Step 3: Run the full matrix under iproute**

Run: `sudo bash tests/integration/protocols/run_matrix.sh --mode iproute`
Expected: `preexisting` shows `SKIP`; every other row PASS. Summary `10 PASS   0 FAIL   1 SKIP`. Exit code 0.

- [ ] **Step 4: Update `.claude/skills/mymitm-testing/SKILL.md` — Quick-reference row**

Replace:
```
| Protocol matrix | **planned** — see `tests/PROTOCOL_COVERAGE.md` | yes | per-protocol *forward* + *dump-parse* (HTTP/1/2/3, WS, SSE, gRPC, TLS, …) | matrix + JSON report (once implemented) |
```
with:
```
| Protocol matrix (P0) | `sudo bash tests/integration/protocols/run_matrix.sh [--mode ebpf\|iproute] [--only NAME]` | yes | per-protocol *forward* + *dump-parse* (P0: HTTP/1.x, keep-alive, streaming, pump, SSE, SigV4, pinning, lifecycle) | printed matrix + `report.json` under the printed `workdir` |
```

- [ ] **Step 5: Update `SKILL.md` — add a Running/reading paragraph**

After the `**netns e2e** (...)` paragraph in "Running & reading each suite", add:

```
**Protocol matrix** (`tests/integration/protocols/run_matrix.sh`) — **build the release binary first**, then `python3 -m pip install -r tests/integration/protocols/requirements.txt`. It reuses the netns topology (`lib.sh`), brings it up once, and runs each `manifest.tsv` row sequentially (one server → one proxy → one client → dump-parse). Each row reports **Fwd** (client got the correct result) and **Dump** (an external parser re-parsed the raw `.c2s`/`.s2c`) against the row's *expected* verdict; a documented gap (e.g. `preexisting`) whose forward correctly `✗`s is a **PASS**. `--only NAME` runs one row; `--mode iproute` switches the data plane. Results: a printed matrix + machine-readable `report.json`, and per-case dump artifacts, organized under the report folder `tests/reports/<suite>-<mode>-<stamp>/` (report.txt, report.json, dumps/<case>/, logs/), printed at the end. Pure-Python parsers/logic have fast unit tests: `cd tests/integration/protocols && python3 -m pytest -q` (no root).
```

- [ ] **Step 6: Update `SKILL.md` — Setup line**

In "Setup", after the `cargo install bpf-linker --locked` line's block, add:
```
- **Protocol-matrix deps:** `python3 -m pip install -r tests/integration/protocols/requirements.txt` (h11 + botocore + pytest). Missing deps make affected rows report `SKIP`, never a false pass.
```

- [ ] **Step 7: Update `tests/PROTOCOL_COVERAGE.md` §1 status note**

Replace the opening status sentence:
```
_Status: PLAN (2026-07-21). This is the agreed test plan; no protocol test code has been
written yet. It explains the **existing** test suite and specifies the **new**
application-protocol coverage we intend to add. It incorporates two research passes — a
survey of mitmproxy's protocol coverage/tests, and a web-protocol + TLS-feature survey._
```
with:
```
_Status: P0 IMPLEMENTED (2026-07-21). The P0 harness (§13) ships under
`tests/integration/protocols/` — matrix driver, dump-parser library, and the green-today
rows (HTTP/1.x, keep-alive, streaming, pump, SSE, SigV4, pinning, lifecycle). P1/P2 remain
planned. This doc explains the existing suite and specifies the full application-protocol
coverage; it incorporates two research passes — a survey of mitmproxy's coverage/tests, and
a web-protocol + TLS-feature survey._
```

- [ ] **Step 8: Wire the 3-VM harness to collect B's dumps into the report folder**

Add to `tests/vm/lib.sh` (its `REPO_ROOT` already points at the repo root, so the folder is shared with the matrix):
```bash
REPORT_DIR="${REPORT_DIR:-$REPO_ROOT/tests/reports}"
report_run_dir() {  # <suite> <mode> ; echoes the created run dir
  local ts; ts="$(date -u +%Y%m%dT%H%M%SZ)"
  local dir="$REPORT_DIR/$1-$2-$ts"; mkdir -p "$dir/dumps" "$dir/logs"
  echo "$1-$2-$ts" > "$REPORT_DIR/LATEST"; echo "$dir"
}
vm_scp_from() { local vm="$1" src="$2" dst="$3"; scp "${SSH_OPTS[@]}" -P "$(ssh_port_for "$vm")" "ubuntu@127.0.0.1:$src" "$dst"; }
```

In `tests/vm/run.sh`, inside `cmd_proxy`, right after the `pass "phase2: C saw src=$A_IP ..."` line and before `vm_ssh B "sudo systemctl stop mymitm" || true`, add:
```bash
  # Collect B's decrypted dumps into the local report folder (no manual fetch).
  local run_dir; run_dir="$(report_run_dir vm "$DATA_PLANE")"
  if vm_ssh B "sudo tar czf /tmp/mymitm-dumps.tgz -C /opt/mymitm dumps && sudo chown ubuntu /tmp/mymitm-dumps.tgz" 2>/dev/null; then
    vm_scp_from B /tmp/mymitm-dumps.tgz "$run_dir/dumps.tgz" \
      && tar xzf "$run_dir/dumps.tgz" -C "$run_dir" && rm -f "$run_dir/dumps.tgz"
    { echo "suite=vm"; echo "data_plane=$DATA_PLANE"; echo "date=$(date -u +%FT%TZ)"; } > "$run_dir/meta.txt"
    pass "phase2: B's dumps collected -> $run_dir"
  else
    info "could not archive B's dumps for collection"
  fi
```

- [ ] **Step 9: Verify VM collection**

Run: `sudo bash tests/vm/run.sh all` (heavy — boots 3 VMs; first run downloads ~1 GB of images).
Expected: after phase 2, `tests/reports/vm-ebpf-<stamp>/dumps/index.jsonl` and the `.c2s`/`.s2c` files exist locally (fetched from VM B), and `tests/reports/LATEST` names that run.

- [ ] **Step 10: Update `.claude/skills/mymitm-testing/SKILL.md` — Quick-reference row + Running/reading paragraph + Setup line**

Replace the Quick-reference row:
```
| Protocol matrix | **planned** — see `tests/PROTOCOL_COVERAGE.md` | yes | per-protocol *forward* + *dump-parse* (HTTP/1/2/3, WS, SSE, gRPC, TLS, …) | matrix + JSON report (once implemented) |
```
with:
```
| Protocol matrix (P0) | `sudo bash tests/integration/protocols/run_matrix.sh [--mode ebpf\|iproute] [--only NAME]` | yes | per-protocol *forward* + *dump-parse* (P0: HTTP/1.x, keep-alive, streaming, pump, SSE, SigV4, pinning, lifecycle) | `tests/reports/matrix-<mode>-<stamp>/` (report.txt + report.json + dumps/ + logs/) |
```
After the `**netns e2e** (...)` paragraph in "Running & reading each suite", add:
```
**Protocol matrix** (`tests/integration/protocols/run_matrix.sh`) — **build the release binary first**, then `python3 -m pip install -r tests/integration/protocols/requirements.txt`. It reuses the netns topology (`lib.sh`), brings it up once, and runs each `manifest.tsv` row sequentially (one server → one proxy → one client → dump-parse). Each row reports **Fwd** vs **Dump** against the row's *expected* verdict; a documented gap (e.g. `preexisting`) that correctly `✗`s forward is a **PASS**. `--only NAME` runs one row; `--mode iproute` switches the data plane. All output is organized in the report folder (below). Pure-Python parsers/logic have fast unit tests: `cd tests/integration/protocols && python3 -m pytest -q` (no root).
```
In "Setup", after the `cargo install bpf-linker --locked` block, add:
```
- **Protocol-matrix deps:** `python3 -m pip install -r tests/integration/protocols/requirements.txt` (h11 + botocore + pytest). Missing deps make affected rows report `SKIP`, never a false pass.
```

- [ ] **Step 11: Update `.claude/skills/mymitm-testing/SKILL.md` — add a Test-report-folder section**

After the `## Dump format` section, add:
```
## Test report folder

Every harness run drops its artifacts into `tests/reports/<suite>-<mode>-<UTC>/` (gitignored; override with `REPORT_DIR=`). On the Windows box that path is `C:\projects\mymitmproxy\...\tests\reports\` — open it directly, nothing to fetch. Each run holds `report.txt`/`report.json` (the matrix), `dumps/<case>/` (decrypted `.c2s`/`.s2c` + `index.jsonl`), `logs/`, and `meta.txt`; `tests/reports/LATEST` names the newest run. The 3-VM harness `scp`s VM B's `/opt/mymitm/dumps` back here automatically at the end of phase 2, so kernel-4.15 dumps land locally too.
```

- [ ] **Step 12: Update `tests/PROTOCOL_COVERAGE.md` §1 status note**

Replace the opening status sentence:
```
_Status: PLAN (2026-07-21). This is the agreed test plan; no protocol test code has been
written yet. It explains the **existing** test suite and specifies the **new**
application-protocol coverage we intend to add. It incorporates two research passes — a
survey of mitmproxy's protocol coverage/tests, and a web-protocol + TLS-feature survey._
```
with:
```
_Status: P0 IMPLEMENTED (2026-07-21). The P0 harness (§13) ships under
`tests/integration/protocols/` — matrix driver, dump-parser library, and the green-today
rows (HTTP/1.x, keep-alive, streaming, pump, SSE, SigV4, pinning, lifecycle). All runs
collect dumps + report into `tests/reports/`. P1/P2 remain planned. This doc explains the
existing suite and specifies the full application-protocol coverage; it incorporates two
research passes — a survey of mitmproxy's coverage/tests, and a web-protocol + TLS-feature
survey._
```

- [ ] **Step 13: Commit**

```bash
git add .claude/skills/mymitm-testing/SKILL.md tests/PROTOCOL_COVERAGE.md tests/vm/lib.sh tests/vm/run.sh
git commit -m "feat(tests): collect all harness dumps into tests/reports/; document in skill"
```

---

## Self-Review

**Spec coverage (against `PROTOCOL_COVERAGE.md` §13 P0):** matrix driver + dump-parser lib (Tasks 2–5) ✓; HTTP/1.1 (Task 5) ✓; HTTP/1.0 + keep-alive (Task 6) ✓; chunked/streaming (Task 7) ✓; pump full-duplex/idle (Task 8, half-close deferred → P1, documented) ✓; SSE (Task 9) ✓; SigV4 header+presigned (Task 10) ✓; cert-pinning/HSTS win (Task 11) ✓; connection lifecycle pre-existing + restart + newconn (Task 12) ✓; two data planes (Task 1 `lib.sh`, driver `--mode`) ✓; skip-with-reason (iproute preexisting SKIP) ✓; source-IP re-asserted per simple case ✓. **Deferred within P0, explicitly:** half-close FIN propagation (Python TLS limitation) → P1. Not in P0 (correctly out of scope): HTTP/2, gRPC, WebSocket, IPv6, QUIC, mTLS, TLS-version matrix, content-encodings, SigV3/NTLM — all P1/P2. **Cross-cutting (user request):** a persistent, organized **report folder** (`tests/reports/`, gitignored) that every harness writes to automatically — `lib.sh` helper (Task 1), matrix driver (Task 5), and the 3-VM harness `scp`-back + skill docs (Task 13) — so dumps never need manual fetching.

**Type/name consistency:** case CLI contract (`server`/`client`/`parse`) and `_util.case_main` signature are uniform across Tasks 5–11; custom rows use `lifecycle_client.py`'s `once`/`hold` (Task 12) driven by bash. `dumpparse.http1.parse_exchange -> Parsed(.requests,.responses,.level,.error)` and `Message.header()` are used consistently by http1/http1_0/keepalive/streaming/sse/sigv4/pinning. `manifest.tsv` columns match `report.MANIFEST_COLS`; `results.tsv` columns (emitted by `emit`) match `report.RESULT_COLS` (`name,act_fwd,act_dump,act_level,srcip`). Verdict tokens (`ok/degrade/fail/na/skip/err`) are consistent between driver `emit` calls, `manifest.tsv`, and `report.SYMB`.

**Placeholder scan:** every code step contains complete, runnable content; the one intentional interim stub (`run_custom` in Task 5) is real code that emits `err` and is explicitly replaced in Task 12 Step 3 with exact old/new text.

**Known risks flagged inline (not placeholders):** (a) `SigV4` botocore canonicalization parity is gated by the in-process pytest in Task 10 before the netns run; (b) `pump` half-close deferred; (c) `preexisting` is eBPF-only (iproute conntrack differs) and SKIPs under iproute; (d) `REPORT_DIR`/`report_run_dir` are **intentionally duplicated** in `tests/integration/lib.sh` and `tests/vm/lib.sh` — the two harnesses are deliberately independent, and both resolve to the same `tests/reports/` via their own `REPO_ROOT`; do not "DRY" them into a shared source file.

---

## Execution Handoff

**Plan complete and saved to `tests/plans/2026-07-21-protocol-matrix-p0.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration. **Caveat for this plan:** Tasks 1 and 5–13 need `sudo` + WSL2 + netns/eBPF and the real musl binary; a sandboxed subagent can't run them. Practical split — subagents do the pure-Python, unit-tested tasks (2, 3, 4, and the logic of 10) end-to-end; the root/netns integration verification (Tasks 1, 5–9, 11, 12, 13) runs in your interactive WSL2 session.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints for review.

**Which approach?**
