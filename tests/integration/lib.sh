#!/usr/bin/env bash
# Shared plumbing for the netns e2e + protocol-matrix harnesses. Source, don't execute.
# Extracted from run_e2e.sh so both harnesses share one proven topology.

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
  # Drop the FORWARD-allow rules topo_up may have added (loop clears stale copies
  # left by a crashed run). filter-table only; untouched by the iproute
  # post-run cleanliness checks (they inspect nat/mangle PREROUTING + ip rule).
  while iptables -D FORWARD -i "$VROOT" -o "$VETH0" -j ACCEPT 2>/dev/null; do :; done
  while iptables -D FORWARD -i "$VETH0" -o "$VROOT" -j ACCEPT 2>/dev/null; do :; done
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

  # The lifecycle "pre-attach" connection is plain-L3-forwarded through the box
  # (client -> VROOT -> [FORWARD] -> VETH0 -> server) before any proxy attaches.
  # The ambient FORWARD policy may be DROP (Docker Desktop sets this on WSL2, and
  # some hardened hosts default to it), which silently blackholes that path while
  # every proxied flow still works (the proxy terminates both legs locally and
  # never traverses FORWARD). Explicitly allow the two harness veths so the direct
  # path is deterministic regardless of ambient policy. Removed in topo_reset;
  # a no-op where FORWARD is already ACCEPT (CI, the 3-VM harness).
  iptables -I FORWARD -i "$VROOT" -o "$VETH0" -j ACCEPT 2>/dev/null || true
  iptables -I FORWARD -i "$VETH0" -o "$VROOT" -j ACCEPT 2>/dev/null || true
}

topo_down() {
  info "tearing down topology"
  ip netns del "$NS_CLI" 2>/dev/null || true
  ip netns del "$NS_SRV" 2>/dev/null || true
  ip link del "$VROOT"   2>/dev/null || true
  ip link del "$VETH0"   2>/dev/null || true
  while iptables -D FORWARD -i "$VROOT" -o "$VETH0" -j ACCEPT 2>/dev/null; do :; done
  while iptables -D FORWARD -i "$VETH0" -o "$VROOT" -j ACCEPT 2>/dev/null; do :; done
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
stdout_log_level = "info"
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
