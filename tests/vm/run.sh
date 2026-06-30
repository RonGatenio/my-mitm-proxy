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
    | grep -q active || fail "tls-server did not start on C"
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

case "$CMD" in
  up)    ensure_certs; cmd_up;;
  down)  cmd_down;;
  *)     red "usage: run.sh {up|router|proxy|all|down} [--data-plane ebpf|iproute] [--keep]"; exit 2;;
esac
