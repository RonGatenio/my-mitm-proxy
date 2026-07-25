#!/usr/bin/env bash
# Phase-4 validation for the eBPF sysctl preflight (--manage-sysctls).
#
# The main harness (run.sh) hides the very bug this feature fixes: for the eBPF
# plane it uses a NON-loopback local_addr (the box's own left-leg IP) AND pre-sets
# net.ipv4.conf.<tun>.route_localnet=1 itself. Either crutch alone masks the
# ingress martian-drop of a loopback DNAT target. This validator removes BOTH:
# it runs the eBPF plane with the PRODUCT DEFAULT local_addr = 127.0.0.1 and
# route_localnet = 0, and proves the proxy's own preflight is what makes it work.
#
# Assumes the VMs are already up on a chosen kernel, e.g.:
#     sudo bash tests/vm/run.sh up --kernel 4.15
# (that boots A/B/C, starts tls-server on C, and drops the CA on A at /tmp/ca.pem).
# Then:
#     sudo bash tests/vm/validate-sysctls.sh
#     sudo bash tests/vm/run.sh down --kernel 4.15
#
# Proves, on a real old kernel:
#   (N) --manage-sysctls=false with route_localnet=0 -> the proxy FAILS FAST with
#       an actionable error naming route_localnet and the --manage-sysctls=true
#       remedy, and never listens.
#   (P) default (manage_sysctls=true) with route_localnet=0 -> the proxy SETS
#       route_localnet 0 -> 1 itself, traffic flows end-to-end (C sees the client's
#       preserved source IP, decrypted bytes land in B's dump), and it RESTORES
#       route_localnet to 0 on clean stop (SysctlGuard Drop).
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib.sh"
[ "$(id -u)" -eq 0 ] || fail "must run as root (sudo)"

b_resolve_ifaces                    # no-op on 4.15/jammy (stays left0/right0)
IFACE="$B_LEFT_IFACE"              # the tun iface the DNAT target lands on
MARKER="/phase4-sysctl-$$"
[ -x "$BIN" ] || fail "missing binary $BIN (run 'run.sh up' or 'cargo build -p mymitm --release' first)"

info "Phase-4 sysctl validation: kernel=$B_KERNEL, tun_iface=$IFACE, local_addr=127.0.0.1 (loopback), data_plane=ebpf"

# --- helpers ---------------------------------------------------------------
setup_b() {  # push the freshly-built binary + leaf cert/key to B, once
  vm_ssh B "sudo mkdir -p /opt/mymitm/dumps && sudo chown -R ubuntu /opt/mymitm"
  vm_scp B "$BIN"                 /opt/mymitm/mymitm
  vm_scp B "$CERT_DIR/leaf.pem"   /opt/mymitm/leaf.pem
  vm_scp B "$CERT_DIR/leaf.key"   /opt/mymitm/leaf.key
  vm_ssh B "chmod +x /opt/mymitm/mymitm"
}

write_toml() {  # write_toml <true|false> : manage_sysctls value; loopback local_addr
  vm_ssh B "sudo tee /opt/mymitm/mymitm.toml >/dev/null" <<EOF
target_server_ip = "$C_IP"
target_server_port = 443
box_ip = "$B_RIGHT_IP"
cert_path = "/opt/mymitm/leaf.pem"
key_path = "/opt/mymitm/leaf.key"
tun_iface = "$IFACE"
egress_iface = "$B_RIGHT_IFACE"
local_addr = "127.0.0.1"
local_port = 8443
fwmark = 0x1337
dump_path = "/opt/mymitm/dumps"
stdout_log_level = "info"
server_name = "server.test"
data_plane = "ebpf"
preserve_src_ip = true
manage_sysctls = $1
alpn_protocols = ["h2", "http/1.1"]
EOF
}

rln()       { vm_ssh B "cat /proc/sys/net/ipv4/conf/$1/route_localnet 2>/dev/null || echo NA"; }
reset_rln0() {  # force effective route_localnet OFF (all AND iface) so the fix has real work to do
  vm_ssh B "sudo sysctl -wq net.ipv4.conf.all.route_localnet=0"
  vm_ssh B "sudo sysctl -wq net.ipv4.conf.$IFACE.route_localnet=0"
}
restart_mymitm() { vm_ssh B "sudo systemctl reset-failed mymitm 2>/dev/null; sudo systemctl restart mymitm"; }
listening()      { vm_ssh B "sudo journalctl -u mymitm --no-pager -n200 2>/dev/null | grep -q 'proxy listening'"; }

# Start from a clean unit + journal so assertions never match a prior run's lines.
vm_ssh B "sudo systemctl stop mymitm 2>/dev/null; sudo journalctl --rotate 2>/dev/null; sudo journalctl --vacuum-time=1s 2>/dev/null" >/dev/null 2>&1 || true
setup_b

# =========================== (N) fail-fast ==================================
info "=== (N) --manage-sysctls=false + route_localnet=0 MUST fail fast (no listen) ==="
reset_rln0
write_toml false
vm_ssh B "sudo rm -f /opt/mymitm/dumps/*"
restart_mymitm
sleep 3                             # preflight (probe on lo, then sysctl bail) is sub-second
if listening; then
  vm_ssh B "sudo journalctl -u mymitm --no-pager -n160"
  fail "(N) proxy logged 'proxy listening' but manage_sysctls=false with route_localnet=0 must fail fast"
fi
jN="$(vm_ssh B "sudo journalctl -u mymitm --no-pager -n200")"
echo "----- B: journalctl -u mymitm (N) -----"; echo "$jN"; echo "---------------------------------------"
echo "$jN" | grep -q "needs kernel sysctls that are not set" || fail "(N) missing the sysctl fail-fast error"
echo "$jN" | grep -q "route_localnet"                        || fail "(N) error did not name route_localnet"
echo "$jN" | grep -q -- "--manage-sysctls=true"              || fail "(N) error did not offer the --manage-sysctls=true remedy"
vm_ssh B "systemctl is-active mymitm" | grep -qx active && fail "(N) unit is still active; expected failed/inactive" || true
pass "(N) fail-fast: actionable route_localnet error, remedy names --manage-sysctls=true, never listened"

# =========================== (P) manage + flow ==============================
info "=== (P) default manage_sysctls=true + route_localnet=0: proxy sets it, traffic flows ==="
reset_rln0
before="$(rln "$IFACE")"; [ "$before" = 0 ] || fail "(P) precondition: $IFACE.route_localnet is '$before', want 0"
write_toml true
vm_ssh C "sudo truncate -s0 /var/log/tls_server.log"
vm_ssh B "sudo rm -f /opt/mymitm/dumps/*"
restart_mymitm
ok=0; for _ in $(seq 1 60); do listening && { ok=1; break; }; sleep 0.4; done
[ "$ok" = 1 ] || { vm_ssh B "sudo journalctl -u mymitm --no-pager -n200"; fail "(P) proxy never logged 'proxy listening'"; }

jP="$(vm_ssh B "sudo journalctl -u mymitm --no-pager -n200")"
echo "----- B: manage-sysctls / listen lines (P) -----"
echo "$jP" | grep -E "manage-sysctls|proxy listening" || true
echo "------------------------------------------------"
echo "$jP" | grep -Eq "manage-sysctls: set net\.ipv4\.conf\.$IFACE\.route_localnet 0 -> 1" \
  || { echo "$jP"; fail "(P) proxy did not log setting $IFACE.route_localnet 0 -> 1"; }
during="$(rln "$IFACE")"; [ "$during" = 1 ] || fail "(P) $IFACE.route_localnet is '$during' while running, want 1"
pass "(P) proxy set $IFACE.route_localnet 0 -> 1 (was 0, now 1) via SysctlGuard"

out="$(vm_ssh A "curl -s -o - -w '\nHTTP:%{http_code}\n' --cacert /tmp/ca.pem https://$C_IP$MARKER" 2>&1)" || true
echo "curl A->C: $out"
echo "$out" | grep -q "HTTP:200" || { vm_ssh B "sudo journalctl -u mymitm --no-pager -n200"; fail "(P) curl A->C did not return 200"; }

log="$(vm_ssh C "cat /var/log/tls_server.log")"
echo "C tls_server.log: $log"
echo "$log" | grep -q "^$A_IP "        || fail "(P) C did not log the client IP $A_IP"
echo "$log" | grep -q "^$B_RIGHT_IP "  && fail "(P) C saw the box IP $B_RIGHT_IP (source not preserved)" || true
vm_ssh B "sudo grep -rl '$MARKER' /opt/mymitm/dumps/" >/dev/null 2>&1 \
  || { vm_ssh B "sudo ls -la /opt/mymitm/dumps/"; fail "(P) decrypted marker $MARKER not found in any B dump"; }
pass "(P) traffic flows over loopback local_addr; C saw preserved client src=$A_IP; decrypted bytes in B dump"

vm_ssh B "sudo systemctl stop mymitm"; sleep 1
after="$(rln "$IFACE")"; [ "$after" = 0 ] || fail "(P) $IFACE.route_localnet is '$after' after stop, want 0 (RAII restore failed)"
pass "(P) route_localnet restored to 0 on clean stop (SysctlGuard Drop)"

green "================================================================"
green " PHASE-4 SYSCTL VALIDATION PASS (kernel=$B_KERNEL, ebpf, local_addr=127.0.0.1)"
green "   (N) --manage-sysctls=false -> actionable fail-fast, never listened"
green "   (P) default true -> set route_localnet 0->1, traffic flowed (src $A_IP), restored on exit"
green "================================================================"
