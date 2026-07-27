#!/bin/sh
# Run mymitm inside a network namespace so the host firewall never sees a
# locally-terminated flow.
#
# WHY THIS EXISTS
# ---------------
# Interception turns one FORWARDed flow into two locally-terminated ones: the
# client's SYN is DNAT'd to a local listener (delivered via INPUT) and the proxy
# dials the server itself (locally generated, so OUTPUT). A box whose firewall
# only permits FORWARD -> server therefore drops both legs, in either data plane.
#
# Putting the proxy in its own netns turns both legs back into *forwarded*
# traffic from the host's point of view:
#
#   client --[left iface]--FORWARD--> mmc0 |ns| mmc1 --> DNAT --> listener
#   server <--[egress iface]-FORWARD-- mmu0 |ns| mmu1 <-- upstream socket
#
# The destination address is still the real server for the whole time the packet
# is in the host's stack -- the rewrite to local_addr:local_port happens INSIDE
# the netns, where the chains are empty. So the host's existing
# "FORWARD -d <server> --dport <port> -j ACCEPT" rule matches BOTH legs (verified:
# its counter shows exactly two accepted SYNs per session) and nothing in the
# firewall has to change.
#
# Bonus: net.ipv4.conf.* is namespaced, so the route_localnet / rp_filter changes
# mymitm makes (--manage-sysctls) land inside the netns and never touch the box.
# That retires the box-wide `conf.all.rp_filter=0` caveat.
#
# WHY TWO veth PAIRS AND NOT ONE
# ------------------------------
# One pair (tun_iface == egress_iface) looks tempting and fails subtly. All four
# classifiers then share two hooks, and tc runs them in `pref` order with
# `direct-action`: the FIRST program to return TC_ACT_OK ends the chain. On
# ingress cls_eth_ingress lands at the lower pref, accepts every client packet
# (it only matches replies FROM the server), and cls_tun_ingress never runs -- so
# nothing is DNAT'd. Measured on 4.15: the flow was routed straight through the
# namespace to the server, un-intercepted, while curl still returned 200. Two
# pairs give each hook exactly one program, which is the arrangement the product
# already validates on real interfaces.
#
# The namespace also runs with ip_forward=0 on purpose: if interception ever
# misses, the packet is DROPPED instead of being quietly forwarded to the server
# in the clear. Fail closed, not fail open. (The iproute data plane sets
# ip_forward=1 itself during setup and restores it on exit, so that plane does
# not get this guarantee -- it does not need forwarding here either.)
#
# REQUIREMENTS ON THE HOST FIREWALL (all of which a forwarding box already has)
#   - FORWARD accepts NEW to <server>:<port> WITHOUT an -i/-o interface match
#     (a rule pinned to `-i <left> -o <egress>` will NOT match -o mmc0 / -i mmu0).
#   - FORWARD accepts ESTABLISHED,RELATED (for both return paths).
#   - net.ipv4.ip_forward=1 on the host.
# Verify with: iptables -S FORWARD
#
# USAGE
#   netns-recipe.sh up   <server_ip> <server_port> <client_iface> <egress_iface>
#   netns-recipe.sh down <server_ip> <server_port> <client_iface> <egress_iface>
#   netns-recipe.sh show
#
# Then run the proxy inside the namespace:
#   ip netns exec mitm mymitm --config /etc/mymitm/mymitm.toml
#     with  tun_iface = "mmc1", egress_iface = "mmu1", box_ip = "169.254.8.2"
#
# Overridable via the environment: NS, VC_H/VC_N, VU_H/VU_N, addresses, FWMARK.
set -u

NS="${NS:-mitm}"
# Client-leg pair -> the proxy's tun_iface.
VC_H="${VC_H:-mmc0}"; VC_N="${VC_N:-mmc1}"
CH_ADDR="${CH_ADDR:-169.254.7.1}"; CN_ADDR="${CN_ADDR:-169.254.7.2}"
# Upstream-leg pair -> the proxy's egress_iface, and its box_ip.
VU_H="${VU_H:-mmu0}"; VU_N="${VU_N:-mmu1}"
UH_ADDR="${UH_ADDR:-169.254.8.1}"; UN_ADDR="${UN_ADDR:-169.254.8.2}"
PFX=30                            # RFC3927 link-local /30s: no routable collision
FWMARK="${FWMARK:-4919}"          # 0x1337; only used to derive table ids

# Policy-routing table ids + rule priorities, derived from the mark so two
# instances don't collide. Bases 300/400 stay clear of the iproute data plane's
# own table (100 + (fwmark & 0xff)) and its 30000+table rule priority.
MASK=$((FWMARK & 255))
T_IN=$((300 + MASK))              # client -> server : steer into the netns
T_BACK=$((400 + MASK))            # server replies   : steer into the netns
P_IN=$((31000 + MASK))
P_BACK=$((32000 + MASK))

usage() { echo "usage: $0 {up|down|show} <server_ip> <server_port> <client_iface> <egress_iface>" >&2; exit 2; }

cmd="${1:-}"; [ -n "$cmd" ] || usage
case "$cmd" in
  show)
    echo "== netns ==";           ip netns list | grep -w "$NS" || echo "(no $NS)"
    echo "== host veths ==";      ip -br addr show dev "$VC_H" 2>/dev/null || echo "($VC_H absent)"
                                  ip -br addr show dev "$VU_H" 2>/dev/null || echo "($VU_H absent)"
    echo "== ip rules ==";        ip rule show | grep -E "lookup ($T_IN|$T_BACK)\$" || echo "(none)"
    echo "== table $T_IN ==";     ip route show table "$T_IN" 2>/dev/null
    echo "== table $T_BACK ==";   ip route show table "$T_BACK" 2>/dev/null
    echo "== in-ns addrs ==";     ip netns exec "$NS" ip -br addr 2>/dev/null || true
    echo "== in-ns routes ==";    ip netns exec "$NS" ip route 2>/dev/null || true
    echo "== in-ns forward ==";   ip netns exec "$NS" cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    exit 0;;
  up|down) ;;
  *) usage;;
esac

SERVER="${2:-}"; PORT="${3:-}"; CIF="${4:-}"; EIF="${5:-}"
[ -n "$SERVER" ] && [ -n "$PORT" ] && [ -n "$CIF" ] && [ -n "$EIF" ] || usage
[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }

if [ "$cmd" = up ]; then
  [ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ] \
    || { echo "net.ipv4.ip_forward is 0 -- the box is not forwarding; refusing" >&2; exit 1; }

  # --- namespace + the two veth pairs -------------------------------------
  ip netns add "$NS"
  ip link add "$VC_H" type veth peer name "$VC_N"
  ip link add "$VU_H" type veth peer name "$VU_N"
  ip link set "$VC_N" netns "$NS"
  ip link set "$VU_N" netns "$NS"

  ip addr add "$CH_ADDR/$PFX" dev "$VC_H"; ip link set "$VC_H" up
  ip addr add "$UH_ADDR/$PFX" dev "$VU_H"; ip link set "$VU_H" up

  ip netns exec "$NS" ip link set lo up
  ip netns exec "$NS" ip addr add "$CN_ADDR/$PFX" dev "$VC_N"
  ip netns exec "$NS" ip addr add "$UN_ADDR/$PFX" dev "$VU_N"
  ip netns exec "$NS" ip link set "$VC_N" up
  ip netns exec "$NS" ip link set "$VU_N" up

  # Inside: the upstream leg is the only traffic addressed to the server, so a
  # /32 sends it out the upstream veth; everything else (the listener's replies,
  # whatever the client's address happens to be) takes the default out the
  # client veth. No policy routing needed, and no need to know the client prefix.
  ip netns exec "$NS" ip route add "$SERVER/32" via "$UH_ADDR" dev "$VU_N"
  ip netns exec "$NS" ip route add default via "$CH_ADDR" dev "$VC_N"
  # Fail closed: a packet that was NOT rewritten to the listener must die here
  # rather than be forwarded on to the server unintercepted.
  ip netns exec "$NS" sysctl -wq net.ipv4.ip_forward=0

  # --- steer the client's flow into the namespace -------------------------
  # Scoped by INGRESS interface on purpose. A plain `ip route add <server>/32
  # via <netns>` in the main table would also make the server's own replies
  # arriving on the egress iface look like they came the wrong way, forcing
  # rp_filter off on a real interface. Keeping the steer in a policy table
  # leaves the MAIN route to the server untouched, so the egress iface's
  # reverse path stays symmetric and needs no sysctl change at all.
  ip route add "$SERVER/32" via "$CN_ADDR" dev "$VC_H" table "$T_IN"
  ip rule add priority "$P_IN" iif "$CIF" to "$SERVER" lookup "$T_IN"

  # --- steer the server's replies into the namespace ----------------------
  # With source-IP preservation the reply's destination is the CLIENT's IP, so
  # the main table would send it back out to the real client. Match on
  # (arrived on the egress iface, came from the server) and hand it to the
  # namespace's UPSTREAM leg, where cls_eth_ingress un-SNATs it.
  ip route add default via "$UN_ADDR" dev "$VU_H" table "$T_BACK"
  ip rule add priority "$P_BACK" iif "$EIF" from "$SERVER" lookup "$T_BACK"

  # --- reverse-path filtering on OUR veths only ---------------------------
  # Each host-side veth receives traffic whose source the main table associates
  # with a different interface: mmc0 sees the listener's replies (src = server,
  # main says the egress iface) and mmu0 sees the upstream leg (src = preserved
  # client, main says the client iface). Loose mode accepts both. Note 2 > 1:
  # the kernel takes MAX(conf.all, conf.<iface>), so setting 2 here LOOSENS even
  # on a hardened box with conf.all.rp_filter=1 -- no box-wide change required.
  sysctl -wq "net.ipv4.conf.$VC_H.rp_filter=2"
  sysctl -wq "net.ipv4.conf.$VU_H.rp_filter=2"

  echo "netns '$NS' up:"
  echo "  client leg  : $VC_H($CH_ADDR) <-> $VC_N($CN_ADDR)   -> tun_iface=$VC_N"
  echo "  upstream leg: $VU_H($UH_ADDR) <-> $VU_N($UN_ADDR)   -> egress_iface=$VU_N, box_ip=$UN_ADDR"
  echo "  steer  in   : iif $CIF to $SERVER -> table $T_IN (prio $P_IN)"
  echo "  steer back  : iif $EIF from $SERVER -> table $T_BACK (prio $P_BACK)"
  echo "  run: ip netns exec $NS mymitm --config <cfg>"
else
  # Teardown is the exact inverse, in reverse order, and idempotent: every step
  # tolerates already-absent state so it doubles as crash recovery.
  ip rule del priority "$P_BACK" iif "$EIF" from "$SERVER" lookup "$T_BACK" 2>/dev/null
  ip rule del priority "$P_IN"   iif "$CIF" to   "$SERVER" lookup "$T_IN"   2>/dev/null
  ip route flush table "$T_BACK" 2>/dev/null
  ip route flush table "$T_IN"   2>/dev/null
  # Deleting the namespace destroys the namespace-side veths and, with them,
  # their host-side peers.
  ip netns del "$NS" 2>/dev/null
  ip link del "$VC_H" 2>/dev/null
  ip link del "$VU_H" 2>/dev/null
  echo "netns '$NS' down (rules, tables, veths, namespace removed)"
fi
