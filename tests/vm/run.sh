#!/usr/bin/env bash
# VM test harness orchestrator. Run as root (needs ip/tap + /dev/kvm).
#   sudo bash tests/vm/run.sh {up|router|proxy|all|down} [--data-plane ebpf|iproute] [--keep]
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib.sh"

DATA_PLANE=ebpf
KEEP=0
CMD="${1:-}"; shift || true
while [ $# -gt 0 ]; do
  case "$1" in
    --data-plane) DATA_PLANE="$2"; shift 2;;
    --keep) KEEP=1; shift;;
    *) red "unknown arg: $1"; exit 2;;
  esac
done

[ "$(id -u)" -eq 0 ] || fail "must run as root (sudo)"

cmd_up() {
  ssh_keygen_once
  [ -x "$BIN" ] || { info "building release binary"; ( cd "$REPO_ROOT" && cargo build -p mymitm --release ) || fail "cargo build failed"; }
  img_fetch
  net_up
  vm_overlay A "$IMG_JAMMY";  vm_seed A; vm_launch A "$MAC_A_CTRL" "$SSH_PORT_A"
  vm_overlay B "$IMG_BIONIC"; vm_seed B; vm_launch B "$MAC_B_CTRL" "$SSH_PORT_B"
  vm_overlay C "$IMG_JAMMY";  vm_seed C; vm_launch C "$MAC_C_CTRL" "$SSH_PORT_C"
  wait_ssh A; wait_ssh B; wait_ssh C

  # B must be kernel 4.15.
  local kver; kver="$(vm_ssh B uname -r)"
  case "$kver" in 4.15*) pass "B kernel is $kver";; *) fail "B kernel is $kver (expected 4.15.*)";; esac

  # Bring up the server on C: copy script + cert, then start the unit.
  vm_ssh C "sudo mkdir -p /opt/tlssrv && sudo chown ubuntu /opt/tlssrv"
  vm_scp C "$HERE/server/tls_server.py" /opt/tlssrv/tls_server.py
  vm_scp C "$CERT_DIR/leaf.pem" /opt/tlssrv/leaf.pem
  vm_scp C "$CERT_DIR/leaf.key" /opt/tlssrv/leaf.key
  vm_ssh C "sudo systemctl enable --now tls-server && sleep 1 && systemctl is-active tls-server" \
    | grep -qx active || fail "tls-server did not start on C"
  pass "tls-server active on C"

  # CA onto A for curl validation (used by phases 1 and 2).
  vm_scp A "$CERT_DIR/ca.pem" /tmp/ca.pem

  # Routing sanity: A reaches C through B.
  vm_ssh A "ping -c1 -W3 $C_IP" >/dev/null 2>&1 && pass "A can reach C ($C_IP) via B" \
    || fail "A cannot reach C through B"
}

cmd_down() {
  vms_kill
  sleep 1
  net_down
  pass "torn down"
}

# Generate the CA + leaf once per up-cycle if absent.
ensure_certs() { [ -f "$CERT_DIR/leaf.pem" ] || { mkdir -p "$CERT_DIR"; bash "$HERE/certs/gen-certs.sh" "$CERT_DIR" >/dev/null; }; }

MARKER_ROUTER="/marker-router-$$"

cmd_router() {
  # Phase 1: no proxy on B.
  vm_ssh B "systemctl is-active mymitm 2>/dev/null" | grep -qx active \
    && fail "mymitm is running on B; phase 1 must be plain-router" || true
  vm_ssh C "sudo truncate -s0 /var/log/tls_server.log"

  local out
  out="$(vm_ssh A "curl -s -o - -w '\nHTTP:%{http_code}\n' --cacert /tmp/ca.pem https://$C_IP$MARKER_ROUTER" 2>&1)" \
    || true
  echo "$out"
  echo "$out" | grep -q "HTTP:200"          || fail "(router) curl A->C did not return 200"
  echo "$out" | grep -q "MITM-OK"            || fail "(router) unexpected body"
  pass "phase1: A->C HTTPS returned 200"

  local log; log="$(vm_ssh C "cat /var/log/tls_server.log")"
  echo "$log"
  echo "$log" | grep -q "^$A_IP "            || fail "(router) C did not log client IP $A_IP"
  echo "$log" | grep -q "$B_RIGHT_IP "       && fail "(router) C saw B's IP $B_RIGHT_IP (routing rewrote src?)" || true
  pass "phase1: C saw src=$A_IP (plain routing preserves client IP)"
}

MARKER_PROXY="/marker-proxy-$$"

write_b_toml() {  # writes mymitm.toml onto B for the selected data plane
  local local_addr; [ "$DATA_PLANE" = ebpf ] && local_addr="$B_LEFT_IP" || local_addr="127.0.0.1"
  vm_ssh B "sudo tee /opt/mymitm/mymitm.toml >/dev/null" <<EOF
target_server_ip = "$C_IP"
target_server_port = 443
box_ip = "$B_RIGHT_IP"
cert_path = "/opt/mymitm/leaf.pem"
key_path = "/opt/mymitm/leaf.key"
tun_iface = "left0"
egress_iface = "right0"
local_addr = "$local_addr"
local_port = 8443
fwmark = 0x1337
dump_path = "/opt/mymitm/dumps"
log_level = "info"
server_name = "server.test"
data_plane = "$DATA_PLANE"
EOF
}

cmd_proxy() {
  info "phase2: installing proxy on B (data_plane=$DATA_PLANE)"
  vm_ssh B "sudo mkdir -p /opt/mymitm/dumps && sudo chown -R ubuntu /opt/mymitm"
  vm_scp B "$BIN" /opt/mymitm/mymitm
  vm_scp B "$CERT_DIR/leaf.pem" /opt/mymitm/leaf.pem
  vm_scp B "$CERT_DIR/leaf.key" /opt/mymitm/leaf.key
  vm_ssh B "chmod +x /opt/mymitm/mymitm"
  write_b_toml
  # eBPF DNATs the client flow to a local listener address on the tun iface.
  [ "$DATA_PLANE" = ebpf ] && vm_ssh B "sudo sysctl -wq net.ipv4.conf.left0.route_localnet=1"
  vm_ssh C "sudo truncate -s0 /var/log/tls_server.log"
  vm_ssh B "sudo rm -f /opt/mymitm/dumps/*"

  vm_ssh B "sudo systemctl restart mymitm"
  # wait for readiness
  local i ok=0
  for i in $(seq 1 50); do
    vm_ssh B "sudo journalctl -u mymitm --no-pager -n50 2>/dev/null | grep -q 'proxy listening'" && { ok=1; break; }
    sleep 0.4
  done
  [ "$ok" = 1 ] || { vm_ssh B "sudo journalctl -u mymitm --no-pager -n80"; fail "(proxy) mymitm never logged 'proxy listening'"; }
  pass "phase2: mymitm attached + listening on B"

  local out
  out="$(vm_ssh A "curl -s -o - -w '\nHTTP:%{http_code}\n' --cacert /tmp/ca.pem https://$C_IP$MARKER_PROXY" 2>&1)" || true
  echo "$out"
  echo "$out" | grep -q "HTTP:200" || { vm_ssh B "sudo journalctl -u mymitm --no-pager -n80"; fail "(proxy) curl A->C did not return 200"; }
  pass "phase2: A->C HTTPS returned 200 through the proxy"

  sleep 0.5
  # (a) decrypted visibility on B: the marker request appears in a c2s dump.
  vm_ssh B "sudo grep -rl '$MARKER_PROXY' /opt/mymitm/dumps/" >/dev/null 2>&1 \
    && pass "phase2: decrypted request ($MARKER_PROXY) found in B's dump" \
    || { vm_ssh B "sudo ls -la /opt/mymitm/dumps/ && sudo cat /opt/mymitm/dumps/index.jsonl"; fail "(proxy) marker not found in any dump on B"; }

  # (b) src IP still preserved at C.
  local log; log="$(vm_ssh C "cat /var/log/tls_server.log")"
  echo "$log"
  echo "$log" | grep -q "^$A_IP "      || fail "(proxy) C did not log client IP $A_IP"
  echo "$log" | grep -q "$B_RIGHT_IP " && fail "(proxy) C saw B's IP $B_RIGHT_IP (src not preserved)" || true
  pass "phase2: C saw src=$A_IP (proxy preserved client IP, data_plane=$DATA_PLANE)"

  vm_ssh B "sudo systemctl stop mymitm" || true
}

cmd_all() {
  ensure_certs; cmd_up; cmd_router; cmd_proxy
  green "================================================================"
  green " ALL PHASES PASS (data_plane=$DATA_PLANE)"
  green " phase1 router + phase2 proxy both preserved src $A_IP at C"
  green "================================================================"
  [ "$KEEP" = 1 ] || cmd_down
}

case "$CMD" in
  up)     ensure_certs; cmd_up;;
  down)   cmd_down;;
  router) cmd_router;;
  proxy)  cmd_proxy;;
  all)    cmd_all;;
  *)      red "usage: run.sh {up|router|proxy|all|down} [--data-plane ebpf|iproute] [--keep]"; exit 2;;
esac
