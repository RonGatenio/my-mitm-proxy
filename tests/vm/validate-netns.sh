#!/usr/bin/env bash
# Validate that running mymitm inside a network namespace survives a default-DROP
# host firewall WITHOUT changing a single firewall rule.
#
# Models the testers' box: FORWARD permits exactly one service (the RDP server
# stand-in = C:443), INPUT permits ssh + openvpn, OUTPUT permits ntp + logs,
# everything else DROPs. Then, per data plane:
#
#   (S) sanity  -- no firewall, proxy on the host legs: traffic flows.
#                  (baseline; this is the post---manage-sysctls state)
#   (R) repro   -- firewall ON, proxy on the host legs: traffic is BLOCKED.
#                  Reproduces the report. Interception moved the flow out of
#                  FORWARD into INPUT (client leg) + OUTPUT (upstream leg).
#   (P) netns   -- firewall ON *and byte-for-byte unchanged*, proxy inside the
#                  'mitm' netns: traffic flows again, C still sees the client's
#                  preserved source IP, decrypted bytes still land in B's dump.
#
# Plus two invariants for (P):
#   - the live iptables ruleset digest is IDENTICAL before and after,
#   - the HOST's conf.all.rp_filter / <left>.route_localnet are untouched
#     (mymitm's sysctl changes landed inside the namespace).
#
# FW_PROFILE selects HOW that firewall is expressed on B:
#   iptables (default) -- a hand-written default-DROP ruleset (fw-up).
#   ufw                -- the SAME box through real, enabled ufw (fw-up-ufw),
#                         which is what the testers actually run. Adds three
#                         things the hand-written profile cannot check:
#                           * the permission lives two jumps deep in
#                             ufw-user-forward, so `iptables -S FORWARD` is blind
#                             to it -- the defect the preflight fix addressed;
#                           * `ufw deny from <subnet>` is an explicit INPUT DROP,
#                             which is what kills netns=false on that box;
#                           * a UDP 3391 forward permission exists, so the steer
#                             can be checked for blackholing non-TCP traffic.
#
# Assumes the VMs are already up, e.g.:
#     sudo bash tests/vm/run.sh up --kernel 4.15
#     sudo bash tests/vm/validate-netns.sh
#     sudo bash tests/vm/run.sh down --kernel 4.15
#
# The tester box itself (ufw, kernel 5.10, both planes):
#     sudo bash tests/vm/run.sh up --kernel debian11
#     sudo FW_PROFILE=ufw bash tests/vm/validate-netns.sh
#     sudo bash tests/vm/run.sh down --kernel debian11
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib.sh"
[ "$(id -u)" -eq 0 ] || fail "must run as root (sudo)"

# This validator deliberately installs a default-DROP firewall on B, so a
# mistake can strand an in-flight ssh session with no RST -- which hangs the
# driver indefinitely. Keepalives turn that into a ~15s error instead.
SSH_OPTS+=(-o ServerAliveInterval=5 -o ServerAliveCountMax=3)

b_resolve_ifaces
LEFT="$B_LEFT_IFACE"; RIGHT="$B_RIGHT_IFACE"
# Namespace-side interface names + the upstream leg's address; see
# netns/netns-recipe.sh for why the client and upstream legs are separate veths.
NS_TUN=mmc1
NS_EGRESS=mmu1
NS_BOX=169.254.8.2
PORT=443
PLANES="${PLANES:-ebpf iproute}"
FW_PROFILE="${FW_PROFILE:-iptables}"
case "$FW_PROFILE" in iptables|ufw) ;; *) fail "FW_PROFILE must be 'iptables' or 'ufw', got '$FW_PROFILE'";; esac
# The client subnet, as the tester box's rules are written (`from <vpn_subnet>`).
CLIENT_SUBNET="${B_LEFT_IP%.*}.0/24"
# The RD Gateway's UDP transport port, which must NOT be pulled into the namespace.
UDP_PORT=3391
UDP_PROBE=/tmp/udp-probe.py
UDP_SINK=/tmp/udp-$UDP_PORT.log
[ -x "$BIN" ] || fail "missing binary $BIN (run 'run.sh up' or 'cargo build -p mymitm --release' first)"

info "netns firewall validation: kernel=$B_KERNEL left=$LEFT right=$RIGHT planes='$PLANES' fw_profile=$FW_PROFILE"

TK="/opt/mymitm/b-testkit.sh"
RECIPE="/opt/mymitm/netns-recipe.sh"
tk() { vm_ssh B "sudo sh $TK $*"; }

# --- diagnostics dumped on any failure -------------------------------------
diag() {
  echo "----- B: mymitm log -----";      vm_ssh B "sudo sh $TK mm-log" || true
  echo "----- B: iptables -vnL -----";   vm_ssh B "sudo iptables -vnL" || true
  echo "----- B: ip rule -----";         vm_ssh B "ip rule show" || true
  echo "----- B: netns state -----";     vm_ssh B "sudo sh $RECIPE show" || true
  echo "-------------------------------"
}
die() { diag; fail "$*"; }

# This validator leaves a default-DROP firewall and a netns on B if it exits
# mid-run, which poisons every later run. Always undo both.
CLEANED=0
cleanup_b() {
  [ "$CLEANED" = 1 ] && return 0
  CLEANED=1
  vm_ssh B "sudo sh $TK mm-stop"                                >/dev/null 2>&1 || true
  vm_ssh B "sudo sh $RECIPE down $C_IP $PORT $LEFT $RIGHT"      >/dev/null 2>&1 || true
  vm_ssh B "sudo sh $TK fw-down"                                >/dev/null 2>&1 || true
}
trap cleanup_b EXIT

# --- one-time setup on B ---------------------------------------------------
setup_b() {
  # Debian genericcloud is minimal and defaults to nftables, so it may ship with
  # no iptables at all -- and this whole validator speaks iptables (fw-hash,
  # fw-dump, and the product's own preflight). `run.sh up` only installs it for
  # the iproute plane, so do it here too.
  if ! vm_ssh B "command -v iptables >/dev/null 2>&1"; then
    info "installing iptables on B (Debian ships without it)"
    vm_ssh B "sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq && \
              sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables" \
      || fail "B: apt-get install iptables failed (guest needs outbound network)"
  fi
  # Every copy and normalization below is checked. Unchecked, a failed CRLF strip
  # surfaces much later as an opaque `sh` error inside the testkit -- and a broken
  # testkit is exactly what makes a probe return garbage, which used to skip
  # assertions silently rather than fail.
  vm_ssh B "sudo mkdir -p /opt/mymitm/dumps && sudo chown -R ubuntu /opt/mymitm" \
    || fail "B: could not prepare /opt/mymitm"
  vm_scp B "$BIN"                        /opt/mymitm/mymitm       || fail "B: copying the binary failed"
  vm_scp B "$CERT_DIR/leaf.pem"          /opt/mymitm/leaf.pem     || fail "B: copying leaf.pem failed"
  vm_scp B "$CERT_DIR/leaf.key"          /opt/mymitm/leaf.key     || fail "B: copying leaf.key failed"
  vm_scp B "$HERE/netns/b-testkit.sh"    /opt/mymitm/b-testkit.sh || fail "B: copying the testkit failed"
  vm_scp B "$HERE/netns/netns-recipe.sh" /opt/mymitm/netns-recipe.sh || fail "B: copying the recipe failed"
  # Files authored on a Windows checkout can arrive CRLF; /bin/sh then dies on
  # `set: pipefail: invalid option name`-style errors. Normalize in place.
  vm_ssh B "sudo sed -i 's/\r\$//' $TK $RECIPE && chmod +x /opt/mymitm/mymitm" \
    || fail "B: normalizing the guest scripts failed"
  # Prove the testkit actually runs before anything depends on its output.
  vm_ssh B "sudo sh $TK mm-log >/dev/null" || fail "B: the testkit is not executable ($TK)"
  # The UDP steer check needs a sender on A and a sink on C. Python because it is
  # the only interpreter both are guaranteed to have.
  if [ "$FW_PROFILE" = ufw ]; then
    for vm in A C; do
      vm_scp "$vm" "$HERE/netns/udp-probe.py" "$UDP_PROBE" || fail "$vm: copying the UDP probe failed"
      vm_ssh "$vm" "sed -i 's/\r\$//' $UDP_PROBE"          || fail "$vm: normalizing the UDP probe failed"
      vm_ssh "$vm" "python3 $UDP_PROBE 2>&1 | grep -q udp-probe" \
        || fail "$vm: python3 cannot run the UDP probe -- the UDP check would report a harness fault as a steer regression"
    done
  fi
}

# fw_digest <label> -- the live ruleset's digest, or fail. `tk fw-hash` exits
# non-zero when it cannot produce one, and `$(...)` swallows that: an empty FW_REF
# then compared equal to an empty FW_NOW and the headline invariant of this whole
# validator passed while measuring nothing. Demand a sha256.
fw_digest() {
  local h
  h="$(tk fw-hash)" || die "($1) fw-hash failed on B -- cannot verify the firewall is unchanged"
  case "$h" in
    [0-9a-f][0-9a-f]*) [ "${#h}" = 64 ] || die "($1) fw-hash returned '$h', not a sha256" ;;
    *) die "($1) fw-hash returned '$h', not a sha256 -- refusing to compare a non-digest" ;;
  esac
  echo "$h"
}

# --- firewall profile ------------------------------------------------------
fw_up() {
  case "$FW_PROFILE" in
    iptables)
      tk fw-up "$C_IP" "$PORT" || fail "fw-up failed"
      ;;
    ufw)
      tk fw-ufw-install || fail "could not install ufw on B"
      # Their eth1: the NIC carrying ssh + openvpn management, which the
      # interface-pinned `allow in on eth1 ...` rules name. Here that is the
      # user-mode control NIC, resolved by MAC because its kernel name varies
      # by distro (ens3 on Ubuntu, enp0s* on Debian).
      local ctrl
      ctrl="$(vm_iface_by_mac B "$MAC_B_CTRL")"
      [ -n "$ctrl" ] || fail "could not resolve B's management NIC by MAC $MAC_B_CTRL"
      info "B management NIC (stands in for their eth1) = $ctrl"
      vm_ssh B "sudo CTRL=$ctrl sh $TK fw-up-ufw $C_IP $PORT $CLIENT_SUBNET" \
        || fail "fw-up-ufw failed"
      ufw_ruleset_checks
      ;;
  esac
}

# Step 2 of the ufw validation: check the preflight's assumptions against a LIVE,
# enabled ufw rather than against a fixture. `ufw --dry-run` renders the user
# rules but never showed the real FORWARD jump skeleton, so the chain-reachability
# logic -- the whole reason the preflight fix works on ufw -- was unverified.
ufw_ruleset_checks() {
  local dump out="$WORK/ufw-live-iptables-S.txt"
  dump="$(tk fw-dump)"
  printf '%s\n' "$dump" > "$out"
  info "live ufw ruleset ($(printf '%s\n' "$dump" | wc -l) lines) saved to $out"
  printf '%s\n' "$dump" | grep -E '^-A (FORWARD|ufw-before-forward|ufw-user-forward|ufw-user-input) ' \
    | sed 's/^/    /'

  printf '%s\n' "$dump" | grep -E '^-A FORWARD ' | grep -q "$C_IP" \
    && die "the forward permission sits directly in FORWARD; that is not how ufw renders it, so this profile no longer models the tester box" || true
  printf '%s\n' "$dump" | grep -qE '^-A FORWARD -j ufw-before-forward$' \
    || die "no 'FORWARD -j ufw-before-forward' jump in the live ruleset"
  printf '%s\n' "$dump" | grep -qE '^-A ufw-before-forward .*-j ufw-user-forward' \
    || die "ufw-user-forward is not reachable from ufw-before-forward in the live ruleset"
  printf '%s\n' "$dump" | grep -qE -- "^-A ufw-user-forward .*-d $C_IP(/32)? .*--dport $PORT .*-j ACCEPT" \
    || die "no ufw-user-forward ACCEPT for $C_IP:$PORT in the live ruleset"
  pass "(ufw) the permission for $C_IP:$PORT is TWO jumps below FORWARD (FORWARD -> ufw-before-forward -> ufw-user-forward): an 'iptables -S FORWARD' scan cannot see it"

  printf '%s\n' "$dump" | grep -qE -- "^-A ufw-user-input -s ${CLIENT_SUBNET%/*}/[0-9]+ -j DROP" \
    || die "no 'ufw deny from $CLIENT_SUBNET' DROP in ufw-user-input"
  pass "(ufw) 'deny from $CLIENT_SUBNET' is an explicit DROP in ufw-user-input -- the rule that kills netns=false"

  printf '%s\n' "$dump" | grep -qE -- "^-A ufw-user-forward .*-d $C_IP(/32)? .*-p udp .*--dport $UDP_PORT .*-j ACCEPT" \
    || die "no ufw-user-forward ACCEPT for UDP $UDP_PORT to $C_IP (a TCP rule for that port, or a UDP rule to some other host, must not satisfy this)"
  pass "(ufw) UDP $UDP_PORT to $C_IP is permitted too, so the steer can be checked for swallowing it"
}

# --- does the namespace fail closed? --------------------------------------
# `ip_forward=0` inside the namespace is a security guarantee: a packet the
# classifiers did not rewrite DIES there instead of being forwarded on to the
# server in the clear. It is also the premise that makes the UDP check decisive --
# the namespace holds `<server>/32 via <upstream veth>`, so with forwarding ON an
# UNSCOPED steer would pull UDP $UDP_PORT in and forward it to C anyway.
#
# It holds for the eBPF plane only. The iproute plane sets net.ipv4.ip_forward=1
# for itself during setup (mymitm/src/iproute.rs), and inside a namespace that
# overwrites the 0 the plumbing just set -- so that plane is fail-OPEN here.
# Asserting the real behaviour of each plane keeps the difference on the record
# instead of buried.
# assert_no_plumbing <label> -- nothing of the namespace topology survives.
# Every check is written so an ssh failure FAILS rather than reading as "clean":
# `${x:-0}` on an empty result from a dead guest used to mean "no leftover state".
assert_no_plumbing() {
  local left_rules
  left_rules="$(vm_ssh B "ip rule show | grep -cE 'lookup (3|4)[0-9][0-9]' || true")" \
    || die "($1) could not read ip rules from B"
  case "$left_rules" in
    ''|*[!0-9]*) die "($1) unreadable ip-rule count from B ('$left_rules')" ;;
    0) ;;
    *) vm_ssh B "ip rule show"; die "($1) $left_rules netns ip rule(s) left behind" ;;
  esac
  for v in mmc0 mmu0; do
    vm_ssh B "ip link show $v >/dev/null 2>&1" && die "($1) veth $v left behind" || true
  done
  # (P) used to claim "no namespace" in its message without ever checking it, and a
  # leaked one was then silently absorbed by the product's own cleanup in (X).
  vm_ssh B "sudo ip netns list | grep -qw mitm" && die "($1) namespace 'mitm' left behind" || true
  pass "($1) netns plumbing fully removed (no ip rules, no veth, no namespace)"
}

assert_ns_forwarding() {
  v="$(ns_sysctl ip_forward)"
  case "$PLANE" in
    ebpf) want=0 ;;
    *)    want=1 ;;   # the iproute plane sets it for itself; see above
  esac
  [ "$v" = "$want" ]     || die "($1) in-netns ip_forward is '$v', expected $want for the $PLANE plane"
  if [ "$want" = 0 ]; then
    pass "($1) namespace fails closed (in-netns ip_forward=0): an unrewritten packet dies rather than leaking onward"
  else
    info "($1) NOTE: in-netns ip_forward=1 -- the $PLANE plane sets it for itself, so the namespace does NOT fail closed on this plane, and the UDP check below is not decisive about steer scoping"
  fi
}

# --- UDP steer check -------------------------------------------------------
# udp_flows <marker> -> 0 arrived · 1 did not arrive · 2 the listener never started
# The distinction matters: reporting a broken probe as "the steer is swallowing
# non-TCP traffic" is how a harness bug gets recorded as a product regression.
udp_flows() {
  local i
  vm_ssh C "rm -f $UDP_SINK $UDP_SINK.ready; nohup setsid python3 $UDP_PROBE listen $UDP_PORT $UDP_SINK >/dev/null 2>&1 </dev/null & sleep 0.2" \
    || return 2
  # The probe touches <sink>.ready only after bind() succeeds, so this separates
  # "no listener" from "no datagram". Backgrounding it means the ssh exit status is
  # the backgrounding shell's, never the listener's -- so it cannot be used here.
  for i in $(seq 1 20); do
    vm_ssh C "test -f $UDP_SINK.ready" && break
    sleep 0.25
  done
  vm_ssh C "test -f $UDP_SINK.ready" || return 2
  vm_ssh A "python3 $UDP_PROBE send $C_IP $UDP_PORT '$1'" || return 2
  for i in $(seq 1 10); do
    vm_ssh C "grep -q '$1' $UDP_SINK 2>/dev/null" && return 0
    sleep 0.5
  done
  return 1
}

# The steer must be narrowed to TCP $PORT. Anything else addressed to the server
# that enters the namespace dies there (ip_forward=0 inside, and the classifiers
# only rewrite TCP) -- which is exactly what happened to an RD Gateway's UDP 3391
# transport before the steer was scoped. Only checkable under FW_PROFILE=ufw: the
# hand-written profile permits no forwarded UDP at all, so a failure there would
# be the firewall, not the steer.
# check_udp <label> <marker>
check_udp() {
  [ "$FW_PROFILE" = ufw ] || return 0
  if [ "$L4_OK" != yes ]; then
    info "($1) skipping the UDP $UDP_PORT check: this kernel's routing rules take no L4 selectors, so the steer is unscoped and UDP to $C_IP is EXPECTED to be blackholed in the namespace"
    return 0
  fi
  udp_flows "$2"
  case $? in
    0) pass "($1) UDP $UDP_PORT still reaches C: the steer took only TCP $PORT" ;;
    1) die "($1) UDP $UDP_PORT to $C_IP did not reach C -- the steer is swallowing non-TCP traffic (regression of the L4-scoped ip rule)" ;;
    *) die "($1) the UDP probe never came up on C, so nothing was measured -- this is a HARNESS failure, not a steer regression (check $UDP_PROBE reached C and python3 can run it)" ;;
  esac
}

# write_toml <host|nsrecipe|product> <plane>
#   host     - data plane directly on the box's own legs, netns mode OFF.
#              Used for the (S) baseline and the (R) reproduction.
#   nsrecipe - namespace-side interfaces, netns mode OFF; launched by hand under
#              `ip netns exec` with the plumbing from netns/netns-recipe.sh.
#              Proves the TOPOLOGY.
#   product  - the box's own legs with netns mode ON, so mymitm does the
#              plumbing and supervises itself. Proves the IMPLEMENTATION.
write_toml() {
  local mode="$1" plane="$2" tun egress box out ns
  case "$mode" in
    nsrecipe) tun="$NS_TUN"; egress="$NS_EGRESS"; box="$NS_BOX";     ns=false; out=/opt/mymitm/mymitm-ns.toml ;;
    product)  tun="$LEFT";   egress="$RIGHT";     box="$B_RIGHT_IP"; ns=true;  out=/opt/mymitm/mymitm-prod.toml ;;
    *)        tun="$LEFT";   egress="$RIGHT";     box="$B_RIGHT_IP"; ns=false; out=/opt/mymitm/mymitm.toml ;;
  esac
  vm_ssh B "sudo tee $out >/dev/null" <<EOF
netns = $ns
target_server_ip = "$C_IP"
target_server_port = $PORT
box_ip = "$box"
cert_path = "/opt/mymitm/leaf.pem"
key_path = "/opt/mymitm/leaf.key"
tun_iface = "$tun"
egress_iface = "$egress"
local_addr = "127.0.0.1"
local_port = 8443
fwmark = 0x1337
dump_path = "/opt/mymitm/dumps"
stdout_log_level = "info"
server_name = "server.test"
data_plane = "$plane"
preserve_src_ip = true
alpn_protocols = ["h2", "http/1.1"]
EOF
}

listening() { vm_ssh B "sudo sh $TK mm-log" 2>/dev/null | grep -q 'proxy listening'; }
wait_listen() {
  local i; for i in $(seq 1 60); do listening && return 0; sleep 0.4; done; return 1
}

# curl_ok <marker>  -> echoes the curl output; returns 0 only on HTTP 200
curl_try() {
  vm_ssh A "curl -s --max-time 8 -o - -w '\nHTTP:%{http_code}\n' --cacert /tmp/ca.pem https://$C_IP$1" 2>&1
}

# A sysctl read that cannot silently degenerate. The old version echoed "NA" on an
# unreadable path, and "NA == NA" then made the whole invariant a no-op.
host_sysctl() {
  local v
  v="$(vm_ssh B "cat /proc/sys/net/ipv4/$1 2>/dev/null")"
  case "$v" in
    ''|*[!0-9]*) fail "cannot read host sysctl net.ipv4.$1 on B (got '$v') -- the invariant that depends on it would be meaningless" ;;
  esac
  echo "$v"
}
ns_sysctl() { vm_ssh B "sudo ip netns exec mitm cat /proc/sys/net/ipv4/$1 2>/dev/null || echo NA"; }

# intercepted <label> <marker> <log>
#   Demand evidence the PROXY terminated this connection. An HTTP 200 alone proves
#   nothing: the first version of the netns topology returned 200 with the flow
#   routed straight THROUGH the namespace to the server, never touching the proxy.
#   NB: match the address on its own -- tracing writes ANSI colour escapes between
#   a field name, its '=' and the value, so a literal "peer=<ip>" never matches.
intercepted() {
  local label="$1" marker="$2" log="$3"
  echo "$log" | grep -q "alpn negotiated" \
    || { echo "$log"; die "($label) HTTP 200 but the proxy logged NO connection -- the traffic BYPASSED the proxy"; }
  echo "$log" | grep "alpn negotiated" | grep -q "$A_IP" \
    || { echo "$log"; die "($label) proxy handled a connection, but not one from $A_IP"; }
  # Ties THIS request to actual decryption, not merely "a connection happened".
  sleep 0.5   # the dump is written as the flow closes; don't race it
  vm_ssh B "sudo grep -rl '$marker' /opt/mymitm/dumps/" >/dev/null 2>&1 \
    || { vm_ssh B "sudo ls -la /opt/mymitm/dumps/"; die "($label) decrypted marker $marker not found in any B dump"; }
}

setup_b

# Gate the UDP expectation on what the PRODUCT will decide. The product itself does
# NOT probe -- it attempts the scoped steer rule and falls back if the kernel
# rejects it, precisely so it adds nothing to a customer's box just to interrogate
# it. This is a throwaway guest, so the harness may probe to form an expectation.
# On a pre-4.17 kernel the fallback is taken and UDP 3391 is legitimately
# blackholed; asserting otherwise there would be asserting a bug.
L4_OK="$(tk l4-probe)"
# Trusting this string blindly would let any ssh hiccup silently disable both UDP
# assertions while printing "this kernel takes no L4 selectors" -- a claim the
# harness would not have established. Only the two known answers are acceptable.
case "$L4_OK" in
  yes|no) ;;
  *) fail "l4-probe returned '$L4_OK' (expected yes|no); refusing to guess whether to expect UDP $UDP_PORT to flow" ;;
esac
info "B routing rules take L4 selectors (ipproto/dport, needs >= 4.17): $L4_OK"

# Reference values for the "host sysctls untouched" invariant, captured BEFORE any
# proxy has run. Captured per-plane after phase (S) they were worthless: (S) runs
# the eBPF plane with manage_sysctls on, which manages exactly conf.all.rp_filter
# and conf.<tun>.{rp_filter,route_localnet} -- so a leak from (S) became the
# reference and every later comparison passed.
#
# conf.all.rp_filter is then deliberately set to 1: mymitm only ever writes 0
# there, and Debian's default is already 0, so on the very target this validator
# was built for the assertion could not fail whatever the product did. Setting 1
# gives it teeth AND exercises the design claim that a per-veth 2 loosens without
# any box-wide change (the kernel takes MAX(conf.all, conf.<iface>)).
vm_ssh B "sudo sysctl -wq net.ipv4.conf.all.rp_filter=1" \
  || fail "could not set conf.all.rp_filter=1 on B (needed to give the sysctl invariant teeth)"
ALL_RPF_REF="$(host_sysctl conf/all/rp_filter)"
LEFT_RLN_REF="$(host_sysctl "conf/$LEFT/route_localnet")"
[ "$ALL_RPF_REF" = 1 ] || fail "conf.all.rp_filter is '$ALL_RPF_REF' after setting it to 1"
info "host sysctl refs (pre-proxy): all.rp_filter=$ALL_RPF_REF $LEFT.route_localnet=$LEFT_RLN_REF"

# ===========================================================================
# Per-plane run
# ===========================================================================
for PLANE in $PLANES; do
  green "================ data plane: $PLANE ================"
  MARK="/netns-$PLANE-$$"

  # --- (S) sanity: no firewall, host legs -----------------------------------
  info "=== ($PLANE/S) no firewall, proxy on the host legs: expect traffic to FLOW ==="
  tk mm-stop >/dev/null
  write_toml host "$PLANE"
  vm_ssh B "sudo rm -f /opt/mymitm/dumps/*"
  tk mm-start plain /opt/mymitm/mymitm.toml >/dev/null
  wait_listen || die "($PLANE/S) proxy never logged 'proxy listening' with NO firewall"
  out="$(curl_try "$MARK-sanity")"
  echo "curl A->C: $out"
  echo "$out" | grep -q "HTTP:200" || die "($PLANE/S) baseline failed with no firewall -- fix the setup before blaming the firewall"
  # The SAME interception gate as (P) and (X). Without it, an un-attached data
  # plane still returns 200 here by plain forwarding, "baseline OK" is printed, and
  # (R) then blames the firewall PROFILE for what is really a broken data plane.
  intercepted "$PLANE/S" "$MARK-sanity" "$(vm_ssh B "sudo sh $TK mm-log")"
  pass "($PLANE/S) baseline OK without a firewall, and the proxy really intercepted it"
  tk mm-stop >/dev/null

  # --- firewall ON ----------------------------------------------------------
  info "=== ($PLANE) applying the testers' default-DROP firewall on B (profile: $FW_PROFILE) ==="
  fw_up
  FW_REF="$(fw_digest "$PLANE ref")"
  info "firewall digest: $FW_REF"

  # Control for the UDP checks in (P) and (X): with the firewall up but nothing
  # else in play, UDP $UDP_PORT must already reach C by plain forwarding. Without
  # this, a later UDP failure could be the profile or the probe rather than the
  # steer -- and it would be read as the steer.
  if [ "$FW_PROFILE" = ufw ] && [ "$L4_OK" = yes ]; then
    udp_flows "$MARK-udp-control" \
      || { diag; tk fw-down >/dev/null; fail "($PLANE) UDP $UDP_PORT does not reach C with plain forwarding under ufw -- the profile or the UDP probe is broken, not the steer"; }
    pass "($PLANE) control: UDP $UDP_PORT reaches C by plain forwarding under ufw"
  fi

  # --- (R) reproduce: firewall ON, host legs -------------------------------
  info "=== ($PLANE/R) firewall ON, proxy on the host legs: expect traffic BLOCKED ==="
  vm_ssh B "sudo rm -f /opt/mymitm/dumps/*"
  tk mm-start plain /opt/mymitm/mymitm.toml >/dev/null
  wait_listen || { diag; tk fw-down >/dev/null; fail "($PLANE/R) proxy never listened; expected it to start fine (the firewall blocks traffic, not startup)"; }
  out="$(curl_try "$MARK-repro")"
  echo "curl A->C: $out"
  if echo "$out" | grep -q "HTTP:200"; then
    diag; tk fw-down >/dev/null
    fail "($PLANE/R) traffic FLOWED with the default-DROP firewall -- the repro is invalid, the profile is not blocking"
  fi
  # "not 200" alone credits ANY interception bug as "the report reproduced". The
  # client leg is dropped at INPUT, so the proxy must have logged no connection at
  # all -- if it did, the flow reached it and something else broke.
  jR="$(vm_ssh B "sudo sh $TK mm-log")"
  echo "$jR" | grep -q "alpn negotiated"     && { echo "$jR"; diag; tk fw-down >/dev/null; fail "($PLANE/R) the proxy DID terminate a connection, so the firewall is not what blocked the flow -- this is not the reported failure"; } || true
  pass "($PLANE/R) reproduced the report: firewall ON + host legs => blocked (proxy healthy, saw no connection)"
  tk mm-stop >/dev/null

  # --- (P) the fix: same firewall, proxy in a netns -------------------------
  info "=== ($PLANE/P) firewall ON *unchanged*, proxy inside netns 'mitm': expect FLOW ==="
  vm_ssh B "sudo sh $RECIPE down $C_IP $PORT $LEFT $RIGHT" >/dev/null 2>&1 || true
  vm_ssh B "sudo sh $RECIPE up $C_IP $PORT $LEFT $RIGHT" \
    || { diag; tk fw-down >/dev/null; fail "($PLANE/P) netns-recipe up failed"; }
  write_toml nsrecipe "$PLANE"
  vm_ssh B "sudo rm -f /opt/mymitm/dumps/*"
  vm_ssh C "sudo truncate -s0 /var/log/tls_server.log"
  tk mm-start netns /opt/mymitm/mymitm-ns.toml >/dev/null
  if ! wait_listen; then
    diag; vm_ssh B "sudo sh $RECIPE down $C_IP $PORT $LEFT $RIGHT" >/dev/null 2>&1
    tk fw-down >/dev/null
    fail "($PLANE/P) proxy never listened inside the netns"
  fi

  # (P) runs on mmc1/mmu1 -- TWO veth pairs, one program per tc hook. That is the
  # whole point of the recipe: with a single pair all four classifiers share two
  # hooks, cls_eth_ingress wins the pref order and ends the chain, and nothing is
  # DNAT'd (the original false pass). Surface the attach path so a partial attach
  # is visible rather than silent.
  echo "----- B: attach / sysctl lines (P) -----"
  vm_ssh B "sudo sh $TK mm-log" | grep -Ei "attach|manage-sysctls|listening|probe" || true
  echo "----------------------------------------"

  out="$(curl_try "$MARK-netns")"
  echo "curl A->C: $out"
  if ! echo "$out" | grep -q "HTTP:200"; then
    diag; vm_ssh B "sudo sh $RECIPE down $C_IP $PORT $LEFT $RIGHT" >/dev/null 2>&1
    tk fw-down >/dev/null
    fail "($PLANE/P) curl A->C failed with the proxy in the netns"
  fi
  pass "($PLANE/P) traffic flows through the netns with the firewall untouched"

  jP="$(vm_ssh B "sudo sh $TK mm-log")"
  intercepted "$PLANE/P" "$MARK-netns" "$jP"
  pass "($PLANE/P) the proxy really terminated the connection (alpn negotiated, peer=$A_IP) and decrypted it"

  # source-IP preservation still intact end to end
  log="$(vm_ssh C "cat /var/log/tls_server.log")"
  echo "C tls_server.log: $log"
  echo "$log" | grep -q "^$A_IP "       || die "($PLANE/P) C did not log the preserved client IP $A_IP"
  echo "$log" | grep -q "^$B_RIGHT_IP " && die "($PLANE/P) C saw the box IP $B_RIGHT_IP (source not preserved)" || true
  echo "$log" | grep -q "^$NS_BOX " && die "($PLANE/P) C saw the namespace address $NS_BOX (source not preserved)" || true
  pass "($PLANE/P) C saw preserved src=$A_IP"

  assert_ns_forwarding "$PLANE/P"
  check_udp "$PLANE/P" "$MARK-udp-netns"

  # --- invariants ----------------------------------------------------------
  FW_NOW="$(fw_digest "$PLANE/P")"
  [ "$FW_NOW" = "$FW_REF" ] \
    || { vm_ssh B "sudo sh $TK fw-show"; die "($PLANE/P) the firewall CHANGED ($FW_REF -> $FW_NOW); the whole point is that it must not"; }
  pass "($PLANE/P) firewall ruleset byte-for-byte unchanged ($FW_NOW)"

  ALL_RPF_NOW="$(host_sysctl conf/all/rp_filter)"
  LEFT_RLN_NOW="$(host_sysctl "conf/$LEFT/route_localnet")"
  [ "$ALL_RPF_NOW" = "$ALL_RPF_REF" ] \
    || die "($PLANE/P) HOST conf.all.rp_filter changed ($ALL_RPF_REF -> $ALL_RPF_NOW); netns sysctls must stay in the netns"
  [ "$LEFT_RLN_NOW" = "$LEFT_RLN_REF" ] \
    || die "($PLANE/P) HOST $LEFT.route_localnet changed ($LEFT_RLN_REF -> $LEFT_RLN_NOW); netns sysctls must stay in the netns"
  pass "($PLANE/P) host sysctls untouched (all.rp_filter=$ALL_RPF_NOW, $LEFT.route_localnet=$LEFT_RLN_NOW)"

  # route_localnet WAS set, but inside the namespace, on the veth.
  ns_rln="$(vm_ssh B "sudo ip netns exec mitm cat /proc/sys/net/ipv4/conf/$NS_TUN/route_localnet 2>/dev/null || echo NA")"
  [ "$ns_rln" = 1 ] \
    || die "($PLANE/P) in-netns $NS_TUN.route_localnet is '$ns_rln', want 1 (manage_sysctls should have set it inside the netns)"
  pass "($PLANE/P) in-netns $NS_TUN.route_localnet=1 -- the sysctl fix applied inside the namespace"

  # The design claim, asserted rather than assumed: rp_filter is loosened to 2 on
  # OUR veths only, and that is enough even though conf.all is hardened to 1,
  # because the kernel takes MAX(conf.all, conf.<iface>).
  for v in mmc0 mmu0; do
    got="$(host_sysctl "conf/$v/rp_filter")"
    [ "$got" = 2 ] || die "($PLANE/P) $v.rp_filter is '$got', want 2 (loose) -- with conf.all=1 the return path would be martian-dropped"
  done
  pass "($PLANE/P) rp_filter=2 on mmc0+mmu0 only, with conf.all.rp_filter=1 untouched"

  # --- teardown -----------------------------------------------------------
  tk mm-stop >/dev/null
  vm_ssh B "sudo sh $RECIPE down $C_IP $PORT $LEFT $RIGHT" >/dev/null \
    || fail "($PLANE) netns-recipe down failed"
  assert_no_plumbing "$PLANE/P"

  # === (X) the product's own --netns=true ==================================
  # (P) proved the topology using the hand-written recipe. This proves the
  # SHIPPING implementation: mymitm is pointed at the box's own legs with
  # netns = true and must build the same plumbing itself, supervise a child
  # inside the namespace, and reverse everything on exit.
  info "=== ($PLANE/X) firewall ON *unchanged*, mymitm --netns=true plumbs itself ==="
  write_toml product "$PLANE"
  vm_ssh B "sudo rm -f /opt/mymitm/dumps/*"
  vm_ssh C "sudo truncate -s0 /var/log/tls_server.log"
  tk mm-start plain /opt/mymitm/mymitm-prod.toml >/dev/null
  wait_listen || die "($PLANE/X) proxy never listened under --netns=true"

  echo "----- B: netns / supervisor lines (X) -----"
  vm_ssh B "sudo sh $TK mm-log" | grep -Ei "netns|listening" || true
  echo "-------------------------------------------"

  vm_ssh B "sudo ip netns list | grep -qw mitm" \
    || die "($PLANE/X) --netns=true did not create the 'mitm' namespace"
  for v in mmc0 mmu0; do
    vm_ssh B "ip link show $v >/dev/null 2>&1" \
      || die "($PLANE/X) --netns=true did not create veth $v"
  done
  pass "($PLANE/X) mymitm built the namespace and both veth pairs itself"

  out="$(curl_try "$MARK-product")"
  echo "curl A->C: $out"
  echo "$out" | grep -q "HTTP:200" || die "($PLANE/X) curl A->C failed under --netns=true"
  jX="$(vm_ssh B "sudo sh $TK mm-log")"
  intercepted "$PLANE/X" "$MARK-product" "$jX"
  log="$(vm_ssh C "cat /var/log/tls_server.log")"
  echo "C tls_server.log: $log"
  echo "$log" | grep -q "^$A_IP " || die "($PLANE/X) C did not log the preserved client IP $A_IP"
  # The same negative check (P) makes. Under --netns=true the failure value is the
  # namespace's own address, so name both.
  echo "$log" | grep -q "^$B_RIGHT_IP " && die "($PLANE/X) C saw the box IP $B_RIGHT_IP (source not preserved)" || true
  echo "$log" | grep -q "^$NS_BOX " && die "($PLANE/X) C saw the namespace address $NS_BOX (source not preserved)" || true
  pass "($PLANE/X) --netns=true: intercepted end to end, src=$A_IP preserved, bytes dumped"

  assert_ns_forwarding "$PLANE/X"
  check_udp "$PLANE/X" "$MARK-udp-product"

  # (X) is the only phase that runs the product's own preflight -- it lives in the
  # netns supervisor. Under ufw this is the decisive check on the fix: the
  # permission is two jumps below FORWARD, so a preflight that scanned
  # `iptables -S FORWARD` saw nothing and stayed silent. Demand that it names the
  # ufw chain it found the permission in.
  # NB: match the value, not "rule=<value>" -- tracing writes ANSI escapes between
  # a field name and its value, so the joined form never matches.
  if [ "$FW_PROFILE" = ufw ]; then
    echo "$jX" | grep -q "both legs will match this forward permission" \
      || { echo "$jX"; die "($PLANE/X) the preflight did not confirm a forward permission, though ufw has one for $C_IP:$PORT"; }
    echo "$jX" | grep "both legs will match this forward permission" | grep -q "ufw-user-forward" \
      || { echo "$jX" | grep "forward permission"; die "($PLANE/X) the preflight confirmed a permission but not the ufw-user-forward one"; }
    pass "($PLANE/X) the preflight found the permission inside ufw-user-forward on a LIVE ufw box (two jumps below FORWARD)"
  fi

  FW_NOW="$(fw_digest "$PLANE/X")"
  [ "$FW_NOW" = "$FW_REF" ] \
    || { vm_ssh B "sudo sh $TK fw-show"; die "($PLANE/X) the firewall CHANGED under --netns=true ($FW_REF -> $FW_NOW)"; }
  pass "($PLANE/X) firewall ruleset unchanged by --netns=true"

  # RAII: the supervisor must remove every trace of its own plumbing on exit.
  tk mm-stop >/dev/null
  sleep 2
  assert_no_plumbing "$PLANE/X after stop"
  ALL_RPF_NOW="$(host_sysctl conf/all/rp_filter)"
  [ "$ALL_RPF_NOW" = "$ALL_RPF_REF" ] \
    || die "($PLANE/X) HOST conf.all.rp_filter changed ($ALL_RPF_REF -> $ALL_RPF_NOW)"
  pass "($PLANE/X) RAII teardown complete; host sysctls untouched too"

  tk fw-down >/dev/null || fail "($PLANE) fw-down failed"
done

green "================================================================"
green " NETNS FIREWALL VALIDATION PASS (kernel=$B_KERNEL, fw=$FW_PROFILE, planes: $PLANES)"
green "   (S) baseline flows with no firewall"
green "   (R) default-DROP firewall blocks the proxy on the host legs (report reproduced)"
green "   (P) same firewall, UNCHANGED: proxy in netns 'mitm' flows, src preserved,"
green "       host sysctls untouched, sysctl fix applied inside the namespace"
green "   (X) same firewall, UNCHANGED: mymitm --netns=true does its own plumbing,"
green "       intercepts end to end, and reverses everything on exit"
if [ "$FW_PROFILE" = ufw ]; then
green "   ufw: the permission lives two jumps below FORWARD and the preflight found"
green "        it there; 'deny from $CLIENT_SUBNET' is a real INPUT DROP"
if [ "$L4_OK" = yes ]; then
green "        UDP $UDP_PORT still reaches C: the steer took only TCP $PORT"
else
green "        UDP $UDP_PORT: NOT CHECKED -- this kernel has no L4 routing selectors,"
green "        so the steer is unscoped and that traffic is expected to be dropped"
fi
fi
green "================================================================"
