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
# Assumes the VMs are already up, e.g.:
#     sudo bash tests/vm/run.sh up --kernel 4.15
#     sudo bash tests/vm/validate-netns.sh
#     sudo bash tests/vm/run.sh down --kernel 4.15
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
[ -x "$BIN" ] || fail "missing binary $BIN (run 'run.sh up' or 'cargo build -p mymitm --release' first)"

info "netns firewall validation: kernel=$B_KERNEL left=$LEFT right=$RIGHT planes='$PLANES'"

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
  vm_ssh B "sudo mkdir -p /opt/mymitm/dumps && sudo chown -R ubuntu /opt/mymitm"
  vm_scp B "$BIN"                      /opt/mymitm/mymitm
  vm_scp B "$CERT_DIR/leaf.pem"        /opt/mymitm/leaf.pem
  vm_scp B "$CERT_DIR/leaf.key"        /opt/mymitm/leaf.key
  vm_scp B "$HERE/netns/b-testkit.sh"  /opt/mymitm/b-testkit.sh
  vm_scp B "$HERE/netns/netns-recipe.sh" /opt/mymitm/netns-recipe.sh
  # Files authored on a Windows checkout can arrive CRLF; /bin/sh then dies on
  # `set: pipefail: invalid option name`-style errors. Normalize in place.
  vm_ssh B "sudo sed -i 's/\r\$//' $TK $RECIPE && chmod +x /opt/mymitm/mymitm"
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

host_sysctl() { vm_ssh B "cat /proc/sys/net/ipv4/$1 2>/dev/null || echo NA"; }

setup_b

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
  pass "($PLANE/S) baseline OK without a firewall"
  tk mm-stop >/dev/null

  # --- firewall ON ----------------------------------------------------------
  info "=== ($PLANE) applying the testers' default-DROP firewall on B ==="
  tk fw-up "$C_IP" "$PORT" || fail "fw-up failed"
  FW_REF="$(tk fw-hash)"
  info "firewall digest: $FW_REF"
  ALL_RPF_REF="$(host_sysctl conf/all/rp_filter)"
  LEFT_RLN_REF="$(host_sysctl "conf/$LEFT/route_localnet")"
  info "host sysctl refs: all.rp_filter=$ALL_RPF_REF $LEFT.route_localnet=$LEFT_RLN_REF"

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
  pass "($PLANE/R) reproduced the report: firewall ON + host legs => blocked (proxy healthy, no traffic)"
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

  # The four classifiers share one interface here (tun_iface == egress_iface).
  # Surface the attach path so a partial attach is visible, not silent.
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

  # ANTI-FALSE-PASS GATE. An HTTP 200 alone proves nothing about interception:
  # the first version of this topology returned 200 with the flow routed straight
  # THROUGH the namespace to the server, never touching the proxy (one veth pair
  # => cls_eth_ingress won the tc pref order and ended the chain before
  # cls_tun_ingress could DNAT). Demand evidence that the proxy itself
  # terminated the connection.
  # NB: match the address on its own. tracing writes ANSI colour escapes between
  # the field name, the '=' and the value, so a literal "peer=<ip>" never matches.
  jP="$(vm_ssh B "sudo sh $TK mm-log")"
  echo "$jP" | grep -q "alpn negotiated" \
    || { echo "$jP"; die "($PLANE/P) HTTP 200 but the proxy logged NO connection -- the traffic BYPASSED the proxy"; }
  echo "$jP" | grep "alpn negotiated" | grep -q "$A_IP" \
    || { echo "$jP"; die "($PLANE/P) proxy handled a connection, but not one from $A_IP"; }
  pass "($PLANE/P) the proxy really terminated the connection (alpn negotiated, peer=$A_IP)"

  # source-IP preservation still intact end to end
  log="$(vm_ssh C "cat /var/log/tls_server.log")"
  echo "C tls_server.log: $log"
  echo "$log" | grep -q "^$A_IP "       || die "($PLANE/P) C did not log the preserved client IP $A_IP"
  echo "$log" | grep -q "^$B_RIGHT_IP " && die "($PLANE/P) C saw the box IP $B_RIGHT_IP (source not preserved)" || true
  vm_ssh B "sudo grep -rl '$MARK-netns' /opt/mymitm/dumps/" >/dev/null 2>&1 \
    || { vm_ssh B "sudo ls -la /opt/mymitm/dumps/"; die "($PLANE/P) decrypted marker not found in any B dump"; }
  pass "($PLANE/P) C saw preserved src=$A_IP; decrypted bytes in B's dump"

  # --- invariants ----------------------------------------------------------
  FW_NOW="$(tk fw-hash)"
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

  # --- teardown -----------------------------------------------------------
  tk mm-stop >/dev/null
  vm_ssh B "sudo sh $RECIPE down $C_IP $PORT $LEFT $RIGHT" >/dev/null \
    || fail "($PLANE) netns-recipe down failed"
  left_rules="$(vm_ssh B "ip rule show | grep -cE 'lookup (3|4)[0-9][0-9]' || true")"
  [ "${left_rules:-0}" = 0 ] || { vm_ssh B "ip rule show"; fail "($PLANE) netns ip rules left behind"; }
  for v in mmc0 mmu0; do
    vm_ssh B "ip link show $v >/dev/null 2>&1" && fail "($PLANE) veth $v left behind" || true
  done
  pass "($PLANE) netns plumbing fully removed (no ip rules, no veth, no namespace)"

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
  echo "$jX" | grep -q "alpn negotiated" \
    || { echo "$jX"; die "($PLANE/X) HTTP 200 but the proxy logged NO connection -- traffic BYPASSED the proxy"; }
  echo "$jX" | grep "alpn negotiated" | grep -q "$A_IP" \
    || { echo "$jX"; die "($PLANE/X) proxy handled a connection, but not one from $A_IP"; }
  log="$(vm_ssh C "cat /var/log/tls_server.log")"
  echo "C tls_server.log: $log"
  echo "$log" | grep -q "^$A_IP " || die "($PLANE/X) C did not log the preserved client IP $A_IP"
  vm_ssh B "sudo grep -rl '$MARK-product' /opt/mymitm/dumps/" >/dev/null 2>&1 \
    || { vm_ssh B "sudo ls -la /opt/mymitm/dumps/"; die "($PLANE/X) decrypted marker not found in any B dump"; }
  pass "($PLANE/X) --netns=true: intercepted end to end, src=$A_IP preserved, bytes dumped"

  FW_NOW="$(tk fw-hash)"
  [ "$FW_NOW" = "$FW_REF" ] \
    || { vm_ssh B "sudo sh $TK fw-show"; die "($PLANE/X) the firewall CHANGED under --netns=true ($FW_REF -> $FW_NOW)"; }
  pass "($PLANE/X) firewall ruleset unchanged by --netns=true"

  # RAII: the supervisor must remove every trace of its own plumbing on exit.
  tk mm-stop >/dev/null
  sleep 2
  vm_ssh B "sudo ip netns list | grep -qw mitm" && die "($PLANE/X) namespace left behind after stop" || true
  for v in mmc0 mmu0; do
    vm_ssh B "ip link show $v >/dev/null 2>&1" && die "($PLANE/X) veth $v left behind after stop" || true
  done
  x_rules="$(vm_ssh B "ip rule show | grep -cE 'lookup (3|4)[0-9][0-9]' || true")"
  [ "${x_rules:-0}" = 0 ] || { vm_ssh B "ip rule show"; die "($PLANE/X) netns ip rules left behind after stop"; }
  ALL_RPF_NOW="$(host_sysctl conf/all/rp_filter)"
  [ "$ALL_RPF_NOW" = "$ALL_RPF_REF" ] \
    || die "($PLANE/X) HOST conf.all.rp_filter changed ($ALL_RPF_REF -> $ALL_RPF_NOW)"
  pass "($PLANE/X) RAII teardown: namespace, veths, policy rules gone; host sysctls untouched"

  tk fw-down >/dev/null || fail "($PLANE) fw-down failed"
done

green "================================================================"
green " NETNS FIREWALL VALIDATION PASS (kernel=$B_KERNEL, planes: $PLANES)"
green "   (S) baseline flows with no firewall"
green "   (R) default-DROP firewall blocks the proxy on the host legs (report reproduced)"
green "   (P) same firewall, UNCHANGED: proxy in netns 'mitm' flows, src preserved,"
green "       host sysctls untouched, sysctl fix applied inside the namespace"
green "   (X) same firewall, UNCHANGED: mymitm --netns=true does its own plumbing,"
green "       intercepts end to end, and reverses everything on exit"
green "================================================================"
