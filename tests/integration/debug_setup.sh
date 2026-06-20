#!/usr/bin/env bash
# Debug helper: brings up the topology + cert + config WITHOUT running client,
# so we can probe the data plane by hand. Source it or run pieces.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WORK=/tmp/mymitm-dbg
rm -rf "$WORK"; mkdir -p "$WORK/dumps"
CERT="$WORK/leaf.pem"; KEY="$WORK/leaf.key"; TOML="$WORK/mymitm.toml"
NS_CLI=mmcli; NS_SRV=mmsrv; VROOT=mmvroot; VCLI=mmvcli; VETH0=mmveth0; VSRV=mmvsrv
CLIENT_IP=10.8.0.5; SERVER_IP=192.168.1.50; BOX_IP=192.168.1.10

ip netns del "$NS_CLI" 2>/dev/null; ip netns del "$NS_SRV" 2>/dev/null
ip link del "$VROOT" 2>/dev/null; ip link del "$VETH0" 2>/dev/null

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" -days 2 \
  -subj "/CN=server.test" -addext "subjectAltName=DNS:server.test" >/dev/null 2>&1

ip netns add "$NS_CLI"; ip netns add "$NS_SRV"
ip link add "$VROOT" type veth peer name "$VCLI"
ip link set "$VCLI" netns "$NS_CLI"
ip addr add 10.8.0.1/24 dev "$VROOT"; ip link set "$VROOT" up
sysctl -wq net.ipv4.conf."$VROOT".route_localnet=1
sysctl -wq net.ipv4.conf.all.route_localnet=1
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
dump_path = "$WORK/dumps"
log_level = "debug"
server_name = "server.test"
EOF
echo "setup done. WORK=$WORK TOML=$TOML"
