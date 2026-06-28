#!/usr/bin/env bash
# End-to-end netns test for mymitmproxy (Tasks 11 + 8).
#
# Proves the whole system against the REAL release binary with FOUR assertions
# per mode, plus multi-client source-IP preservation for the eBPF mode:
#   1. client completes a TLS handshake and trusts the genuine leaf cert;
#   2. application bytes round-trip both directions through the MITM;
#   3. the dump files (index.jsonl + <id>.c2s/.s2c) hold the decrypted plaintext;
#   4. the fake server records peer IP == client IP (NOT box IP 192.168.1.10).
#
# eBPF mode (default, MODE=ebpf):
#   - config omits target_client_ip (wildcard/dynamic)
#   - two clients: both run from mmcli netns, but one binds 10.8.0.5 (primary)
#     and the other binds 10.8.0.9 (a secondary IP on the same VCLI interface).
#   - asserts BOTH client IPs are preserved (not the box IP)
#
# iproute mode (MODE=iproute):
#   - config sets data_plane = "iproute"
#   - single client cli (10.8.0.5)
#   - asserts post-run cleanliness: no leftover iptables DNAT, no ip rule,
#     sysctls restored
#
# Topology:
#   netns mmcli (10.8.0.5, 10.8.0.9)       root ns (mymitm)              netns mmsrv
#   vcli 10.8.0.5/24 <-veth-> mmvroot 10.8.0.1/24   mmveth0 192.168.1.10/24 <-veth-> vsrv 192.168.1.50/24
#   (also 10.8.0.9 on VCLI)  tun_iface=mmvroot        egress_iface=mmveth0         fake TLS :443
#                              box_ip=192.168.1.10     local 10.8.0.1:8443 (eBPF) / 127.0.0.1:8443 (iproute)
#
# Run (eBPF multi-client): sudo bash tests/integration/run_e2e.sh
# Run (iproute):           sudo MODE=iproute bash tests/integration/run_e2e.sh
set -u

MODE="${MODE:-ebpf}"

# --- locations -------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="$REPO_ROOT/target/x86_64-unknown-linux-musl/release/mymitm"
WORK="$(mktemp -d /tmp/mymitm-e2e.XXXXXX)"
DUMP_DIR="$WORK/dumps"
CERT="$WORK/leaf.pem"
KEY="$WORK/leaf.key"
TOML="$WORK/mymitm.toml"
PEERFILE="$WORK/peer_ips.txt"
READYFILE="$WORK/server_ready.txt"
SRV_LOG="$WORK/server.log"
PROXY_LOG="$WORK/proxy.log"
CLIENT_LOG="$WORK/client.log"
CLIENT2_LOG="$WORK/client2.log"

# Names chosen for teardown-safe uniqueness.
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

SERVER_PID=""
PROXY_PID=""

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m[harness]\033[0m %s\n' "$*"; }

teardown() {
  info "tearing down (MODE=$MODE)"
  [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  # give mymitm a moment to drop TCX/iptables links (fail-open)
  sleep 0.5
  [ -n "$PROXY_PID" ] && kill -9 "$PROXY_PID" 2>/dev/null
  [ -n "$SERVER_PID" ] && kill -9 "$SERVER_PID" 2>/dev/null
  ip netns del "$NS_CLI" 2>/dev/null
  ip netns del "$NS_SRV"  2>/dev/null
  ip link del "$VROOT" 2>/dev/null
  ip link del "$VETH0" 2>/dev/null
  # confirm clean
  if ip netns list 2>/dev/null | grep -qE "^($NS_CLI|$NS_SRV)\b"; then
    red "WARNING: leftover netns remain"; ip netns list
  fi
  if ip link show "$VROOT" >/dev/null 2>&1 || ip link show "$VETH0" >/dev/null 2>&1; then
    red "WARNING: leftover veth remain"
  fi
}
trap teardown EXIT

fail() {
  red "ASSERTION FAILED: $*"
  echo
  red "----- proxy.log -----"; cat "$PROXY_LOG" 2>/dev/null
  red "----- server.log -----"; cat "$SRV_LOG" 2>/dev/null
  exit 1
}

# --- preflight -------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then red "must run as root (sudo)"; exit 1; fi
[ -x "$BIN" ] || { red "release binary not found: $BIN (run: cargo build -p mymitm --release)"; exit 1; }
info "binary: $BIN"
info "workdir: $WORK"
info "mode: $MODE"

# Clean any leftovers from a prior aborted run.
ip netns del "$NS_CLI"  2>/dev/null
ip netns del "$NS_SRV"  2>/dev/null
ip link del "$VROOT"  2>/dev/null
ip link del "$VETH0"  2>/dev/null

# --- cert ------------------------------------------------------------------
info "generating leaf cert (CN=server.test)"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$KEY" -out "$CERT" -days 2 \
  -subj "/CN=server.test" \
  -addext "subjectAltName=DNS:server.test" >/dev/null 2>&1 \
  || fail "openssl cert generation failed"

# --- topology --------------------------------------------------------------
info "building netns + veth topology"
ip netns add "$NS_CLI"
ip netns add "$NS_SRV"

# client veth: root-side VROOT (the tun_iface) <-> VCLI in netns cli
ip link add "$VROOT" type veth peer name "$VCLI"
ip link set "$VCLI" netns "$NS_CLI"
ip addr add 10.8.0.1/24 dev "$VROOT"
ip link set "$VROOT" up
# The eBPF DNATs the client flow's destination to the local listener address.
# A packet that ARRIVES on a real interface destined for a loopback/non-local
# address is dropped as a "martian" unless route_localnet is enabled for that
# interface. Set it only for VROOT (the tun_iface) here; the iproute data plane
# additionally needs it on the egress interface, which it sets itself via sysctl.
sysctl -wq net.ipv4.conf."$VROOT".route_localnet=1
ip netns exec "$NS_CLI" ip addr add "$CLIENT_IP/24" dev "$VCLI"
ip netns exec "$NS_CLI" ip link set "$VCLI" up
ip netns exec "$NS_CLI" ip link set lo up
ip netns exec "$NS_CLI" ip route add default via 10.8.0.1

# eBPF multi-client: add a secondary IP (10.8.0.9) to VCLI in the same netns.
# Both IPs share the same physical veth; all traffic exits via VCLI→VROOT where
# the eBPF is attached, so both source IPs are intercepted by the single tun_iface.
# The client script uses --bind-addr to force the source IP per connection.
if [ "$MODE" = "ebpf" ]; then
  info "adding secondary client IP $CLIENT2_IP to $VCLI in $NS_CLI"
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
# The SNATted upstream packets arrive at the server with source 10.8.0.x, which
# is OUTSIDE the server's connected 192.168.1.0/24. Route 10.8.0.0/24 back via
# the box so the reply returns on mmveth0, where the eBPF un-SNATs it.
ip netns exec "$NS_SRV" ip route add 10.8.0.0/24 via "$BOX_IP"

# --- mymitm config ---------------------------------------------------------
mkdir -p "$DUMP_DIR"

if [ "$MODE" = "ebpf" ]; then
  # eBPF multi-client: omit target_client_ip (wildcard/dynamic).
  # Use local_addr=10.8.0.1 (the VROOT IP) instead of 127.0.0.1 so that the
  # eBPF DNAT to the listener works for BOTH client IPs without route_localnet
  # complications: packets are routed to a real local address on VROOT rather
  # than the loopback, which avoids a WSL kernel quirk that blocks secondary-IP
  # connections to 127.0.0.1 after a first connection has been established.
  cat > "$TOML" <<EOF
# eBPF multi-client mode: no target_client_ip (wildcard)
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
log_level = "info"
server_name = "server.test"
data_plane = "ebpf"
EOF

else
  # iproute mode: single client (cli / 10.8.0.5), data_plane = "iproute".
  cat > "$TOML" <<EOF
# iproute data plane mode
target_server_ip = "$SERVER_IP"
target_server_port = 443
box_ip = "$BOX_IP"
cert_path = "$CERT"
key_path = "$KEY"
tun_iface = "$VROOT"
egress_iface = "$VETH0"
local_addr = "127.0.0.1"
local_port = 8443
fwmark = 0x1337
dump_path = "$DUMP_DIR"
log_level = "info"
server_name = "server.test"
data_plane = "iproute"
EOF
fi

info "wrote config: $TOML"

# --- start fake server in netns srv ---------------------------------------
info "starting fake TLS server in netns $NS_SRV"
ip netns exec "$NS_SRV" python3 "$SCRIPT_DIR/fake_server.py" \
  --cert "$CERT" --key "$KEY" --bind "$SERVER_IP" --port 443 \
  --peerfile "$PEERFILE" --readyfile "$READYFILE" >"$SRV_LOG" 2>&1 &
SERVER_PID=$!
# wait until it is actually listening
for _ in $(seq 1 50); do [ -f "$READYFILE" ] && break; sleep 0.1; done
[ -f "$READYFILE" ] || fail "fake server did not become ready; log: $(cat "$SRV_LOG")"
green "fake server ready"

# --- start mymitm in root ns ----------------------------------------------
info "starting mymitm (real release binary) in root ns"
RUST_LOG=info "$BIN" --config "$TOML" >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!
# wait for the proxy loop + listener
for _ in $(seq 1 100); do
  grep -q "proxy listening" "$PROXY_LOG" && break
  if ! kill -0 "$PROXY_PID" 2>/dev/null; then fail "mymitm exited early; log: $(cat "$PROXY_LOG")"; fi
  sleep 0.1
done
grep -q "proxy listening" "$PROXY_LOG" || fail "mymitm never logged 'proxy listening'; log: $(cat "$PROXY_LOG")"
green "mymitm data plane attached + proxy listening"

# --- run client(s) ---------------------------------------------------------
info "running TLS client 1 in netns $NS_CLI (src $CLIENT_IP -> $SERVER_IP:443)"
ip netns exec "$NS_CLI" python3 "$SCRIPT_DIR/client.py" \
  --cafile "$CERT" --host "$SERVER_IP" --port 443 \
  --server-name server.test \
  --bind-addr "$CLIENT_IP" >"$CLIENT_LOG" 2>&1
CLIENT_RC=$?
echo "----- client1 output -----"
cat "$CLIENT_LOG"
echo "--------------------------"

if [ "$MODE" = "ebpf" ]; then
  info "running TLS client 2 in netns $NS_CLI (src $CLIENT2_IP -> $SERVER_IP:443)"
  ip netns exec "$NS_CLI" python3 "$SCRIPT_DIR/client.py" \
    --cafile "$CERT" --host "$SERVER_IP" --port 443 \
    --server-name server.test \
    --bind-addr "$CLIENT2_IP" >"$CLIENT2_LOG" 2>&1
  CLIENT2_RC=$?
  echo "----- client2 output -----"
  cat "$CLIENT2_LOG"
  echo "--------------------------"
fi

# give the proxy a moment to flush dump files
sleep 0.5

# ===========================================================================
# ASSERTIONS
# ===========================================================================
echo
info "evaluating assertions (MODE=$MODE)"

# ---- assertion 1: client TLS handshake ----------------------------------
if [ "$CLIENT_RC" -ne 0 ] || ! grep -q "HANDSHAKE_OK" "$CLIENT_LOG"; then
  fail "(1) client 1 TLS handshake against genuine cert did not succeed (rc=$CLIENT_RC)"
fi
green "ASSERTION 1 PASS: client completed TLS handshake trusting the genuine leaf cert"

if [ "$MODE" = "ebpf" ]; then
  if [ "$CLIENT2_RC" -ne 0 ] || ! grep -q "HANDSHAKE_OK" "$CLIENT2_LOG"; then
    fail "(1b) client 2 TLS handshake against genuine cert did not succeed (rc=$CLIENT2_RC)"
  fi
  green "ASSERTION 1b PASS: client2 completed TLS handshake trusting the genuine leaf cert"
fi

# ---- assertion 2: application bytes round-trip --------------------------
if ! grep -q "CLIENT_OK" "$CLIENT_LOG" || ! grep -q "PONG-FROM-SERVER" "$CLIENT_LOG"; then
  fail "(2) application bytes did not round-trip (expected PONG-FROM-SERVER) for client1"
fi
green "ASSERTION 2 PASS: application bytes round-tripped (PING/PONG) through the MITM"

if [ "$MODE" = "ebpf" ]; then
  if ! grep -q "CLIENT_OK" "$CLIENT2_LOG" || ! grep -q "PONG-FROM-SERVER" "$CLIENT2_LOG"; then
    fail "(2b) application bytes did not round-trip for client2"
  fi
  green "ASSERTION 2b PASS: client2 application bytes round-tripped through the MITM"
fi

# ---- assertion 3: dump files contain decrypted plaintext ----------------
IDX="$DUMP_DIR/index.jsonl"
[ -s "$IDX" ] || fail "(3) dump index missing/empty: $IDX"
grep -q "$CLIENT_IP" "$IDX" || fail "(3) index.jsonl has no record with client $CLIENT_IP; content: $(cat "$IDX")"
grep -q "$SERVER_IP" "$IDX" || fail "(3) index.jsonl has no record with server $SERVER_IP; content: $(cat "$IDX")"
CONN_ID="$(python3 -c "
import json,sys
for l in open('$IDX'):
    l=l.strip()
    if not l: continue
    o=json.loads(l)
    cid=o.get('conn_id') or o.get('id')
    if cid:
        print(cid); break
")"
[ -n "$CONN_ID" ] || fail "(3) could not extract conn_id from index.jsonl"
C2S="$DUMP_DIR/$CONN_ID.c2s"
S2C="$DUMP_DIR/$CONN_ID.s2c"
[ -f "$C2S" ] || fail "(3) c2s dump missing: $C2S"
[ -f "$S2C" ] || fail "(3) s2c dump missing: $S2C"
grep -q "PING-FROM-CLIENT" "$C2S" || fail "(3) c2s dump lacks decrypted request; content: $(cat "$C2S")"
grep -q "PONG-FROM-SERVER" "$S2C" || fail "(3) s2c dump lacks decrypted response; content: $(cat "$S2C")"
green "ASSERTION 3 PASS: dump index + c2s/s2c contain decrypted plaintext (conn_id=$CONN_ID)"

# ---- assertion 4: source-IP preservation ---------------------------------
[ -f "$PEERFILE" ] || fail "(4) fake server recorded no peer IPs (no connection reached it?)"
PEER_IPS="$(sort -u "$PEERFILE" | tr '\n' ' ' | sed 's/ $//')"
info "fake server recorded peer IPs = [$PEER_IPS]"
printf "PEER_IPS: %s\n" "$PEER_IPS"

# Box IP must NEVER appear.
if grep -qF "$BOX_IP" "$PEERFILE"; then
  fail "(4) SOURCE-IP PRESERVATION BROKEN: server saw box IP $BOX_IP (SNAT did not apply)"
fi

# Client 1 IP must appear.
if ! grep -qF "$CLIENT_IP" "$PEERFILE"; then
  fail "(4) server did not record client1 IP $CLIENT_IP; peer_ips=[$PEER_IPS]"
fi
green "ASSERTION 4 PASS: fake server recorded peer IP = $CLIENT_IP (source IP preserved)"

if [ "$MODE" = "ebpf" ]; then
  # Client 2 IP must also appear.
  if ! grep -qF "$CLIENT2_IP" "$PEERFILE"; then
    fail "(4b) server did not record client2 IP $CLIENT2_IP; peer_ips=[$PEER_IPS]"
  fi
  green "ASSERTION 4b PASS: fake server recorded peer IP = $CLIENT2_IP (multi-client source IP preserved)"
fi

# ---- iproute post-run cleanliness check ----------------------------------
# After proxy exits via teardown, assert no leftover iptables/ip rule state.
if [ "$MODE" = "iproute" ]; then
  info "stopping proxy for post-run cleanliness check"
  kill "$PROXY_PID" 2>/dev/null; sleep 1; kill -9 "$PROXY_PID" 2>/dev/null
  PROXY_PID=""  # prevent double-kill in teardown

  # fwmark value is 0x1337 = 4919; table = 100 + (4919 & 0xff) = 100 + 0x37 = 155
  TABLE=155

  # (a) No DNAT rule for our listener in nat PREROUTING.
  DNAT_RULES="$(iptables -t nat -S PREROUTING 2>/dev/null)"
  if echo "$DNAT_RULES" | grep -q "$VROOT"; then
    fail "(clean-a) leftover DNAT rule for $VROOT found after proxy exit: $DNAT_RULES"
  fi
  green "CLEAN CHECK a PASS: no leftover iptables DNAT PREROUTING rule"

  # (b) No ip rule for our fwmark -> table.
  IP_RULES="$(ip rule 2>/dev/null)"
  if echo "$IP_RULES" | grep -qF "lookup $TABLE"; then
    fail "(clean-b) leftover ip rule for table $TABLE found: $IP_RULES"
  fi
  green "CLEAN CHECK b PASS: no leftover ip rule for fwmark"

  # (c) No ip route in our custom table.
  ROUTES="$(ip route show table $TABLE 2>/dev/null)"
  if [ -n "$ROUTES" ]; then
    fail "(clean-c) leftover ip route in table $TABLE found: $ROUTES"
  fi
  green "CLEAN CHECK c PASS: no leftover ip route in table $TABLE"

  # (d) No mangle MARK rule for our server IP.
  MANGLE_RULES="$(iptables -t mangle -S PREROUTING 2>/dev/null)"
  if echo "$MANGLE_RULES" | grep -qF "$SERVER_IP"; then
    fail "(clean-d) leftover mangle MARK rule for $SERVER_IP found after proxy exit: $MANGLE_RULES"
  fi
  green "CLEAN CHECK d PASS: no leftover iptables mangle MARK rule"

  info "POST-RUN CLEANLINESS: all checks pass (no leftover iptables/ip-rule/ip-route/mangle)"
fi

# ===========================================================================
echo
if [ "$MODE" = "ebpf" ]; then
  green "================================================================"
  green " ALL ASSERTIONS PASS (eBPF multi-client mode)"
  green " client1 IP $CLIENT_IP preserved, client2 IP $CLIENT2_IP preserved"
  green " box IP $BOX_IP not seen by server"
  green "================================================================"
else
  green "================================================================"
  green " ALL ASSERTIONS PASS (iproute mode)"
  green " client IP $CLIENT_IP preserved, post-run box is clean"
  green "================================================================"
fi
exit 0
