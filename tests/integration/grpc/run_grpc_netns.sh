#!/usr/bin/env bash
# gRPC end-to-end conformance against the REAL mymitm release binary (Task 7),
# prototyped in netns (fast loop) before promotion to the qemu VM harness.
#
# Proves the byte-relay + ALPN-mirror MITM carries a real grpcio conversation
# end-to-end for ALL FOUR RPC shapes — unary, server-stream, client-stream, and
# BiDi (full-duplex, the shape the earlier spike never exercised) — with ALPN
# negotiated as h2 on BOTH TLS legs and the decrypted h2 bytes teed to the dump.
#
# Topology mirrors run_e2e.sh (eBPF, single client). Run: sudo bash run_grpc_netns.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BIN="$REPO_ROOT/target/x86_64-unknown-linux-musl/release/mymitm"
VENV="${VENV:-$SCRIPT_DIR/.venv}"
PY="$VENV/bin/python3"

WORK="$(mktemp -d /tmp/mymitm-grpc.XXXXXX)"
DUMP_DIR="$WORK/dumps"
CERT="$WORK/leaf.pem"; KEY="$WORK/leaf.key"; TOML="$WORK/mymitm.toml"
READYFILE="$WORK/server_ready.txt"
SRV_LOG="$WORK/server.log"; PROXY_LOG="$WORK/proxy.log"; CLIENT_LOG="$WORK/client.log"

NS_CLI=mmcli; NS_SRV=mmsrv
VROOT=mmvroot; VCLI=mmvcli; VETH0=mmveth0; VSRV=mmvsrv
CLIENT_IP=10.8.0.5; SERVER_IP=192.168.1.50; BOX_IP=192.168.1.10
SERVER_PID=""; PROXY_PID=""

red(){ printf '\033[31m%s\033[0m\n' "$*"; }
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
info(){ printf '\033[36m[grpc-harness]\033[0m %s\n' "$*"; }

teardown(){
  info "tearing down"
  [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  sleep 0.5
  [ -n "$PROXY_PID" ] && kill -9 "$PROXY_PID" 2>/dev/null
  [ -n "$SERVER_PID" ] && kill -9 "$SERVER_PID" 2>/dev/null
  ip netns del "$NS_CLI" 2>/dev/null; ip netns del "$NS_SRV" 2>/dev/null
  ip link del "$VROOT" 2>/dev/null; ip link del "$VETH0" 2>/dev/null
}
trap teardown EXIT

fail(){
  red "ASSERTION FAILED: $*"; echo
  red "----- proxy.log -----"; cat "$PROXY_LOG" 2>/dev/null
  red "----- server.log -----"; cat "$SRV_LOG" 2>/dev/null
  red "----- client.log -----"; cat "$CLIENT_LOG" 2>/dev/null
  exit 1
}

[ "$(id -u)" -eq 0 ] || { red "must run as root (sudo)"; exit 1; }
[ -x "$BIN" ] || { red "release binary not found: $BIN (cargo build -p mymitm --release --target x86_64-unknown-linux-musl)"; exit 1; }

# Bootstrap a self-contained venv with grpcio + grpcio-tools (idempotent), then
# (re)generate the pb2 stubs so they always match the installed grpcio — the
# stubs are gitignored, not committed. Needs python3-venv and network for pip.
if [ ! -x "$PY" ]; then
  info "bootstrapping grpc venv at $VENV (grpcio + grpcio-tools)"
  python3 -m venv "$VENV" || { red "python3 -m venv failed (need python3-venv)"; exit 1; }
  "$PY" -m pip install --quiet --upgrade pip || { red "pip upgrade failed"; exit 1; }
  "$PY" -m pip install --quiet grpcio grpcio-tools || { red "grpcio install failed (network?)"; exit 1; }
fi
info "regenerating gRPC stubs from echo.proto"
"$PY" -m grpc_tools.protoc -I"$SCRIPT_DIR" \
  --python_out="$SCRIPT_DIR" --grpc_python_out="$SCRIPT_DIR" \
  "$SCRIPT_DIR/echo.proto" || { red "protoc stub generation failed"; exit 1; }
info "binary: $BIN"; info "venv:   $PY"; info "workdir: $WORK"

# cleanup any leftovers
ip netns del "$NS_CLI" 2>/dev/null; ip netns del "$NS_SRV" 2>/dev/null
ip link del "$VROOT" 2>/dev/null; ip link del "$VETH0" 2>/dev/null

info "generating leaf cert (CN=server.test)"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" -days 2 \
  -subj "/CN=server.test" -addext "subjectAltName=DNS:server.test" >/dev/null 2>&1 \
  || fail "openssl cert generation failed"

info "building netns + veth topology"
ip netns add "$NS_CLI"; ip netns add "$NS_SRV"
ip link add "$VROOT" type veth peer name "$VCLI"
ip link set "$VCLI" netns "$NS_CLI"
ip addr add 10.8.0.1/24 dev "$VROOT"; ip link set "$VROOT" up
sysctl -wq net.ipv4.conf."$VROOT".route_localnet=1
ip netns exec "$NS_CLI" ip addr add "$CLIENT_IP/24" dev "$VCLI"
ip netns exec "$NS_CLI" ip link set "$VCLI" up
ip netns exec "$NS_CLI" ip link set lo up
ip netns exec "$NS_CLI" ip route add default via 10.8.0.1
ip link add "$VETH0" type veth peer name "$VSRV"
ip link set "$VSRV" netns "$NS_SRV"
ip addr add "$BOX_IP/24" dev "$VETH0"; ip link set "$VETH0" up
ip netns exec "$NS_SRV" ip addr add "$SERVER_IP/24" dev "$VSRV"
ip netns exec "$NS_SRV" ip link set "$VSRV" up
ip netns exec "$NS_SRV" ip link set lo up
ip netns exec "$NS_SRV" ip route add 10.8.0.0/24 via "$BOX_IP"

mkdir -p "$DUMP_DIR"
cat > "$TOML" <<EOF
target_server_ip = "$SERVER_IP"
target_server_port = 443
box_ip = "$BOX_IP"
cert_path = "$CERT"
key_path = "$KEY"
tun_iface = "$VROOT"
egress_iface = "$VETH0"
local_addr = "10.8.0.1"
local_port = 8443
fwmark = 0x1337
dump_path = "$DUMP_DIR"
stdout_log_level = "info"
server_name = "server.test"
data_plane = "ebpf"
EOF

info "starting gRPC server in netns $NS_SRV"
ip netns exec "$NS_SRV" bash -c "cd '$SCRIPT_DIR' && '$PY' grpc_server.py --cert '$CERT' --key '$KEY' --bind '$SERVER_IP' --port 443 --readyfile '$READYFILE'" >"$SRV_LOG" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 100); do [ -f "$READYFILE" ] && break; sleep 0.1; done
[ -f "$READYFILE" ] || fail "gRPC server not ready; log: $(cat "$SRV_LOG")"
green "gRPC server ready"

info "starting mymitm (real release binary) in root ns"
RUST_LOG=info "$BIN" --config "$TOML" >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!
for _ in $(seq 1 100); do
  grep -q "proxy listening" "$PROXY_LOG" && break
  kill -0 "$PROXY_PID" 2>/dev/null || fail "mymitm exited early; log: $(cat "$PROXY_LOG")"
  sleep 0.1
done
grep -q "proxy listening" "$PROXY_LOG" || fail "mymitm never logged 'proxy listening'; log: $(cat "$PROXY_LOG")"
green "mymitm data plane attached + proxy listening"

info "running gRPC conformance client in netns $NS_CLI (src $CLIENT_IP -> $SERVER_IP:443)"
ip netns exec "$NS_CLI" bash -c "cd '$SCRIPT_DIR' && '$PY' grpc_client.py --cafile '$CERT' --host '$SERVER_IP' --port 443 --server-name server.test" >"$CLIENT_LOG" 2>&1
CLIENT_RC=$?
echo "----- grpc client output -----"; cat "$CLIENT_LOG"; echo "------------------------------"
sleep 0.5

echo; info "evaluating assertions"

[ "$CLIENT_RC" -eq 0 ] || fail "gRPC client exited nonzero (rc=$CLIENT_RC)"
for tok in UNARY_OK SERVERSTREAM_OK CLIENTSTREAM_OK BIDI_OK ALL_GRPC_OK; do
  grep -q "$tok" "$CLIENT_LOG" || fail "client did not report $tok"
done
green "ASSERTION 1 PASS: all four gRPC RPC shapes succeeded (unary, server-stream, client-stream, BiDi)"

# tracing emits ANSI color escapes between field name and value, so strip them
# before matching (`upstream<esc>=<esc>h2`).
PLOG_PLAIN="$(sed 's/\x1b\[[0-9;]*m//g' "$PROXY_LOG")"
echo "$PLOG_PLAIN" | grep -q "upstream=h2" || fail "proxy did not negotiate upstream ALPN h2; log: $(echo "$PLOG_PLAIN" | grep alpn)"
echo "$PLOG_PLAIN" | grep -q "downstream=h2" || fail "proxy did not present downstream ALPN h2; log: $(echo "$PLOG_PLAIN" | grep alpn)"
green "ASSERTION 2 PASS: ALPN negotiated h2 on BOTH legs (upstream=h2 downstream=h2)"

IDX="$DUMP_DIR/index.jsonl"
[ -s "$IDX" ] || fail "dump index missing/empty: $IDX"
CONN_ID="$($PY - "$IDX" <<'PYEOF'
import json,sys
for l in open(sys.argv[1]):
    l=l.strip()
    if not l: continue
    o=json.loads(l); cid=o.get('conn_id') or o.get('id')
    if cid: print(cid); break
PYEOF
)"
[ -n "$CONN_ID" ] || fail "could not extract conn_id from index.jsonl"
C2S="$DUMP_DIR/$CONN_ID.c2s"; S2C="$DUMP_DIR/$CONN_ID.s2c"
[ -s "$C2S" ] || fail "c2s dump missing/empty: $C2S"
[ -s "$S2C" ] || fail "s2c dump missing/empty: $S2C"
# gRPC content-type appears in the relayed (decrypted) HPACK-decoded... no — HPACK
# is compressed, so assert on raw byte volume + the h2 connection preface instead.
grep -qa "PRI \* HTTP/2.0" "$C2S" || fail "c2s dump lacks the HTTP/2 client preface; not h2 bytes?"
green "ASSERTION 3 PASS: decrypted h2 bytes teed to dump (conn_id=$CONN_ID, c2s=$(wc -c <"$C2S")B s2c=$(wc -c <"$S2C")B, preface present)"

echo
green "================================================================"
green " ALL gRPC CONFORMANCE ASSERTIONS PASS (netns, real binary)"
green " unary + server-stream + client-stream + BiDi over one MITM h2 conn"
green "================================================================"
exit 0
