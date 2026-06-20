#!/usr/bin/env bash
# End-to-end netns test for mymitmproxy (Task 11).
#
# Proves the whole system against the REAL release binary with FOUR assertions:
#   1. client completes a TLS handshake and trusts the genuine leaf cert;
#   2. application bytes round-trip both directions through the MITM;
#   3. the dump files (index.jsonl + <id>.c2s/.s2c) hold the decrypted plaintext;
#   4. the fake server records peer IP == 10.8.0.5 (NOT 192.168.1.10) -- the
#      core source-IP-preservation proof.
#
# Topology (real TCP via netns + veth, eBPF does ALL diversion/SNAT):
#
#   netns mmcli                  root ns (mymitm)                   netns mmsrv
#   vcli 10.8.0.5/24 <-veth-> mmvroot 10.8.0.1/24   mmveth0 192.168.1.10/24 <-veth-> vsrv 192.168.1.50/24
#   default via 10.8.0.1      tun_iface=mmvroot     egress_iface=mmveth0           fake TLS :443
#                             box_ip=192.168.1.10   local 127.0.0.1:8443
#
# Run: sudo bash tests/integration/run_e2e.sh
set -u

# --- locations -------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="$REPO_ROOT/target/x86_64-unknown-linux-musl/release/mymitm"
WORK="$(mktemp -d /tmp/mymitm-e2e.XXXXXX)"
DUMP_DIR="$WORK/dumps"
CERT="$WORK/leaf.pem"
KEY="$WORK/leaf.key"
TOML="$WORK/mymitm.toml"
PEERFILE="$WORK/peer_ip.txt"
READYFILE="$WORK/server_ready.txt"
SRV_LOG="$WORK/server.log"
PROXY_LOG="$WORK/proxy.log"
CLIENT_LOG="$WORK/client.log"

# Names chosen for teardown-safe uniqueness.
NS_CLI=mmcli
NS_SRV=mmsrv
VROOT=mmvroot   # root-side client veth == tun_iface
VCLI=mmvcli     # in netns mmcli
VETH0=mmveth0   # root-side server veth == egress_iface
VSRV=mmvsrv     # in netns mmsrv

CLIENT_IP=10.8.0.5
SERVER_IP=192.168.1.50
BOX_IP=192.168.1.10

SERVER_PID=""
PROXY_PID=""
ORIG_ALL_ROUTE_LOCALNET=""

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m[harness]\033[0m %s\n' "$*"; }

teardown() {
  info "tearing down"
  [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  # give mymitm a moment to drop TCX links (fail-open)
  sleep 0.5
  [ -n "$PROXY_PID" ] && kill -9 "$PROXY_PID" 2>/dev/null
  [ -n "$SERVER_PID" ] && kill -9 "$SERVER_PID" 2>/dev/null
  ip netns del "$NS_CLI" 2>/dev/null
  ip netns del "$NS_SRV" 2>/dev/null
  ip link del "$VROOT" 2>/dev/null
  ip link del "$VETH0" 2>/dev/null
  # restore the global route_localnet sysctl to its original value (the
  # per-interface knob on $VROOT vanished with the interface).
  [ -n "$ORIG_ALL_ROUTE_LOCALNET" ] && \
    sysctl -wq net.ipv4.conf.all.route_localnet="$ORIG_ALL_ROUTE_LOCALNET" 2>/dev/null
  # confirm clean
  if ip netns list 2>/dev/null | grep -qE "^($NS_CLI|$NS_SRV)\b"; then
    red "WARNING: leftover netns remain"; ip netns list
  fi
  if ip link show "$VROOT" >/dev/null 2>&1 || ip link show "$VETH0" >/dev/null 2>&1; then
    red "WARNING: leftover veth remain"
  fi
}
trap teardown EXIT

fail() { red "ASSERTION FAILED: $*"; echo; red "----- proxy.log -----"; cat "$PROXY_LOG" 2>/dev/null; red "----- server.log -----"; cat "$SRV_LOG" 2>/dev/null; exit 1; }

# --- preflight -------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then red "must run as root (sudo)"; exit 1; fi
[ -x "$BIN" ] || { red "release binary not found: $BIN (run: cargo build -p mymitm --release)"; exit 1; }
info "binary: $BIN"
info "workdir: $WORK"

# Clean any leftovers from a prior aborted run.
ip netns del "$NS_CLI" 2>/dev/null
ip netns del "$NS_SRV" 2>/dev/null
ip link del "$VROOT" 2>/dev/null
ip link del "$VETH0" 2>/dev/null

# --- cert ------------------------------------------------------------------
# ONE self-signed leaf cert (CN=server.test, SAN includes the dnsname). Used as:
# the mymitm cert/key (presented to client), the fake server's identity, and the
# client's trust anchor.
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
# The eBPF DNATs the client flow's destination to 127.0.0.1:8443. A packet that
# ARRIVES on a real interface destined for a loopback address is dropped as a
# "martian" unless route_localnet is enabled for that interface. This is the
# same mechanism iptables transparent proxies (and Docker) rely on. We do NOT
# add any ip route / iptables NAT here -- only permit the local delivery the
# eBPF rewrite requires.
ORIG_ALL_ROUTE_LOCALNET="$(cat /proc/sys/net/ipv4/conf/all/route_localnet 2>/dev/null)"
sysctl -wq net.ipv4.conf."$VROOT".route_localnet=1
sysctl -wq net.ipv4.conf.all.route_localnet=1
ip netns exec "$NS_CLI" ip addr add "$CLIENT_IP/24" dev "$VCLI"
ip netns exec "$NS_CLI" ip link set "$VCLI" up
ip netns exec "$NS_CLI" ip link set lo up
ip netns exec "$NS_CLI" ip route add default via 10.8.0.1

# server veth: root-side VETH0 (egress_iface) <-> VSRV in netns srv
ip link add "$VETH0" type veth peer name "$VSRV"
ip link set "$VSRV" netns "$NS_SRV"
ip addr add "$BOX_IP/24" dev "$VETH0"
ip link set "$VETH0" up
ip netns exec "$NS_SRV" ip addr add "$SERVER_IP/24" dev "$VSRV"
ip netns exec "$NS_SRV" ip link set "$VSRV" up
ip netns exec "$NS_SRV" ip link set lo up
# The SNATted upstream packets arrive at the server with source 10.8.0.5, which
# is OUTSIDE the server's connected 192.168.1.0/24. Without a route back the
# server's SYN-ACK would be dropped. Route 10.8.0.0/24 back via the box so the
# reply returns on mmveth0, where cls_eth_ingress un-SNATs it to the box.
ip netns exec "$NS_SRV" ip route add 10.8.0.0/24 via "$BOX_IP"

# --- mymitm config ---------------------------------------------------------
mkdir -p "$DUMP_DIR"
cat > "$TOML" <<EOF
target_client_ip = "$CLIENT_IP"
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
EOF
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

# --- run the client in netns cli ------------------------------------------
info "running TLS client in netns $NS_CLI (src $CLIENT_IP -> $SERVER_IP:443)"
ip netns exec "$NS_CLI" python3 "$SCRIPT_DIR/client.py" \
  --cafile "$CERT" --host "$SERVER_IP" --port 443 \
  --server-name server.test >"$CLIENT_LOG" 2>&1
CLIENT_RC=$?
echo "----- client output -----"
cat "$CLIENT_LOG"
echo "-------------------------"

# give the proxy a moment to flush dump files
sleep 0.5

# ===========================================================================
# ASSERTIONS
# ===========================================================================
echo
info "evaluating FOUR assertions"

# (1) client handshake succeeded against the pinned/trusted genuine cert
if [ "$CLIENT_RC" -ne 0 ] || ! grep -q "HANDSHAKE_OK" "$CLIENT_LOG"; then
  fail "(1) client TLS handshake against genuine cert did not succeed (rc=$CLIENT_RC)"
fi
green "ASSERTION 1 PASS: client completed TLS handshake trusting the genuine leaf cert"

# (2) application bytes round-trip correctly
if ! grep -q "CLIENT_OK" "$CLIENT_LOG" || ! grep -q "PONG-FROM-SERVER" "$CLIENT_LOG"; then
  fail "(2) application bytes did not round-trip (expected PONG-FROM-SERVER)"
fi
green "ASSERTION 2 PASS: application bytes round-tripped (PING/PONG) through the MITM"

# (3) dump files contain the decrypted plaintext
IDX="$DUMP_DIR/index.jsonl"
[ -s "$IDX" ] || fail "(3) dump index missing/empty: $IDX"
# the index record must carry the client 10.8.0.5 and server 192.168.1.50:443
grep -q "$CLIENT_IP" "$IDX" || fail "(3) index.jsonl has no record with client $CLIENT_IP; content: $(cat "$IDX")"
grep -q "$SERVER_IP" "$IDX" || fail "(3) index.jsonl has no record with server $SERVER_IP; content: $(cat "$IDX")"
CONN_ID="$(python3 -c "import json,sys
for l in open('$IDX'):
    l=l.strip()
    if not l: continue
    o=json.loads(l)
    cid=o.get('conn_id') or o.get('id')
    if cid:
        print(cid); break")"
[ -n "$CONN_ID" ] || fail "(3) could not extract conn_id from index.jsonl"
C2S="$DUMP_DIR/$CONN_ID.c2s"
S2C="$DUMP_DIR/$CONN_ID.s2c"
[ -f "$C2S" ] || fail "(3) c2s dump missing: $C2S"
[ -f "$S2C" ] || fail "(3) s2c dump missing: $S2C"
grep -q "PING-FROM-CLIENT" "$C2S" || fail "(3) c2s dump lacks decrypted request; content: $(cat "$C2S")"
grep -q "PONG-FROM-SERVER" "$S2C" || fail "(3) s2c dump lacks decrypted response; content: $(cat "$S2C")"
green "ASSERTION 3 PASS: dump index + c2s/s2c contain decrypted plaintext (conn_id=$CONN_ID)"

# (4) THE CORE PROOF: fake server saw peer IP == client IP (10.8.0.5)
[ -f "$PEERFILE" ] || fail "(4) fake server recorded no peer IP (no connection reached it?)"
PEER_IP="$(tr -d '[:space:]' < "$PEERFILE")"
info "fake server recorded peer IP = $PEER_IP"
if [ "$PEER_IP" = "$BOX_IP" ]; then
  fail "(4) SOURCE-IP PRESERVATION BROKEN: server saw box IP $BOX_IP (SNAT did not apply)"
fi
if [ "$PEER_IP" != "$CLIENT_IP" ]; then
  fail "(4) server saw unexpected peer IP '$PEER_IP' (expected $CLIENT_IP)"
fi
green "ASSERTION 4 PASS: fake server recorded peer IP = $CLIENT_IP (source IP preserved via eBPF SNAT)"

echo
green "================================================================"
green " ALL FOUR ASSERTIONS PASS (incl. source-IP = $CLIENT_IP)"
green "================================================================"
exit 0
