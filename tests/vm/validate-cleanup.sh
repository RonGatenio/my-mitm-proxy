#!/usr/bin/env bash
# Validate that `--cleanup` is a usable maintenance command: it reverses what an
# unclean exit left behind, says what it removed, and EXITS.
#
# The bug this covers: `--cleanup` used to reverse the leftovers and then fall
# through into normal startup. On a `netns = true` config that meant the very next
# thing it did was rebuild the plumbing it had just removed and run as a
# long-lived proxy -- so an operator cleaning up a box was left with one that was
# dirty again and intercepting traffic, with no clean-and-exit mode anywhere.
#
# Only a real box can show this. The failure is not a wrong value, it is a process
# that never returns and kernel state that comes back; a unit test sees neither.
#
# Assumes the VMs are already up, e.g.:
#     sudo bash tests/vm/run.sh up --kernel 4.15
#     sudo bash tests/vm/validate-cleanup.sh
#     sudo bash tests/vm/run.sh down --kernel 4.15
#
# Proves, on a real kernel, with real leftovers from a real SIGKILL:
#   (K) SIGKILL leaves runtime state installed        -- the precondition is real
#   (C) --cleanup EXITS (does not become a proxy), removes it all, reports what
#       it removed, and the forensic tool then reports the box CLEAN
#   (I) a second --cleanup on the clean box exits 0 and reports NOTHING to clean
#       -- the count is honest, not "route flush always succeeds"
#   (B) --cleanup REFUSES while an instance is running, names its pids, and
#       leaves that instance alive with its plumbing intact
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib.sh"
[ "$(id -u)" -eq 0 ] || fail "must run as root (sudo)"

b_resolve_ifaces
LEFT="$B_LEFT_IFACE"; RIGHT="$B_RIGHT_IFACE"
PORT=443
PLANE="${PLANE:-ebpf}"
# Derived from fwmark 0x1337 exactly as netns.rs derives them; the forensic tool
# derives the same numbers from its own --fwmark. Asserting on them here is what
# makes "the state is gone" mean the state, not just the namespace.
T_IN=355; T_BACK=455; P_IN=31055; P_BACK=32055
NS=mitm
CFG=/opt/mymitm/mymitm-cleanup.toml
TK="/opt/mymitm/b-testkit.sh"
FX="/opt/mymitm/mymitm-forensics.sh"
[ -x "$BIN" ] || fail "missing binary $BIN (run 'run.sh up' or 'cargo build -p mymitm --release' first)"

info "--cleanup validation: kernel=$B_KERNEL left=$LEFT right=$RIGHT plane=$PLANE"

tk() { vm_ssh B "sudo sh $TK $*"; }

diag() {
  echo "----- B: mymitm log -----";   vm_ssh B "sudo sh $TK mm-log" || true
  echo "----- B: ip rule -----";      vm_ssh B "ip rule show" || true
  echo "----- B: ip netns list -----"; vm_ssh B "ip netns list" || true
  echo "----- B: forensics -----";    vm_ssh B "sudo $FX" || true
  echo "-------------------------"
}
die() { diag; fail "$*"; }

# Never leave a killed proxy's plumbing (or a live proxy) on B for the next run.
CLEANED=0
cleanup_b() {
  [ "$CLEANED" = 1 ] && return 0
  CLEANED=1
  vm_ssh B "sudo sh $TK mm-kill"                                      >/dev/null 2>&1 || true
  vm_ssh B "sudo /opt/mymitm/mymitm --config $CFG --cleanup"          >/dev/null 2>&1 || true
}
trap cleanup_b EXIT

# --- one-time setup on B ---------------------------------------------------
vm_ssh B "sudo mkdir -p /opt/mymitm/dumps && sudo chown -R ubuntu /opt/mymitm" \
  || fail "B: could not prepare /opt/mymitm"
vm_scp B "$BIN"                      /opt/mymitm/mymitm             || fail "B: copying the binary failed"
vm_scp B "$CERT_DIR/leaf.pem"        /opt/mymitm/leaf.pem           || fail "B: copying leaf.pem failed"
vm_scp B "$CERT_DIR/leaf.key"        /opt/mymitm/leaf.key           || fail "B: copying leaf.key failed"
vm_scp B "$HERE/netns/b-testkit.sh"  /opt/mymitm/b-testkit.sh       || fail "B: copying the testkit failed"
vm_scp B "$REPO_ROOT/tools/mymitm-forensics.sh" "$FX"               || fail "B: copying the forensic tool failed"
# A Windows checkout hands these over CRLF; /bin/sh then dies opaquely.
vm_ssh B "sudo sed -i 's/\r\$//' $TK $FX && chmod +x /opt/mymitm/mymitm && sudo chmod +x $FX" \
  || fail "B: normalizing the guest scripts failed"
vm_ssh B "sudo sh $TK mm-log >/dev/null" || fail "B: the testkit is not executable ($TK)"
# Prove the forensic tool runs before any assertion depends on its output; a
# broken tool would otherwise "agree" with everything by printing nothing.
vm_ssh B "sudo $FX -h >/dev/null" || fail "B: the forensic tool is not executable ($FX)"

vm_ssh B "sudo tee $CFG >/dev/null" <<EOF || fail "B: writing $CFG failed"
netns = true
target_server_ip = "$C_IP"
target_server_port = $PORT
box_ip = "$B_RIGHT_IP"
cert_path = "/opt/mymitm/leaf.pem"
key_path = "/opt/mymitm/leaf.key"
tun_iface = "$LEFT"
egress_iface = "$RIGHT"
local_addr = "127.0.0.1"
local_port = 8443
fwmark = 0x1337
dump_path = "/opt/mymitm/dumps"
stdout_log_level = "info"
server_name = "server.test"
data_plane = "$PLANE"
preserve_src_ip = true
alpn_protocols = ["h2", "http/1.1"]
EOF

# --- helpers ---------------------------------------------------------------
listening()  { vm_ssh B "sudo sh $TK mm-log" 2>/dev/null | grep -q 'proxy listening'; }
wait_listen() { local i; for i in $(seq 1 60); do listening && return 0; sleep 0.4; done; return 1; }
alive()      { [ "$(vm_ssh B "sudo sh $TK mm-alive")" = yes ]; }
# How many of our runtime objects exist right now. Counted directly rather than
# through the forensic tool so the two are independent witnesses.
traces() {
  vm_ssh B "n=0
    ip netns list 2>/dev/null | grep -qw $NS && n=\$((n+1))
    ip link show mmc0 >/dev/null 2>&1 && n=\$((n+1))
    ip link show mmu0 >/dev/null 2>&1 && n=\$((n+1))
    ip rule show 2>/dev/null | grep -q '^$P_IN:'  && n=\$((n+1))
    ip rule show 2>/dev/null | grep -q '^$P_BACK:' && n=\$((n+1))
    [ -n \"\$(ip route show table $T_IN 2>/dev/null)\" ]   && n=\$((n+1))
    [ -n \"\$(ip route show table $T_BACK 2>/dev/null)\" ] && n=\$((n+1))
    echo \$n"
}
# `--cleanup` under a hard timeout. Echoes the output; returns 124 if it never
# exited, which IS the bug -- a proxy does not return.
run_cleanup() {
  vm_ssh B "sudo timeout 45 /opt/mymitm/mymitm --config $CFG --cleanup 2>&1"
}

start_proxy() {
  vm_ssh B "sudo sh $TK mm-start plain $CFG" >/dev/null || die "mm-start failed"
  wait_listen || die "the proxy never logged 'proxy listening' (netns mode, plane=$PLANE)"
}

# Start from a box with nothing of ours on it, so (K)'s count means something.
vm_ssh B "sudo sh $TK mm-kill" >/dev/null 2>&1 || true
vm_ssh B "sudo /opt/mymitm/mymitm --config $CFG --cleanup" >/dev/null 2>&1 || true
n0="$(traces)"
[ "$n0" = 0 ] || die "precondition: B already has $n0 of our objects installed before the test starts"

# ======================= (K) SIGKILL leaves state ===========================
info "=== (K) SIGKILL must leave the runtime state installed ==="
start_proxy
n_live="$(traces)"
[ "$n_live" -ge 6 ] || die "(K) only $n_live/7 objects present while running; the plumbing did not come up"
tk mm-kill >/dev/null || die "(K) mm-kill failed"
alive && die "(K) a mymitm survived SIGKILL"
n_kill="$(traces)"
[ "$n_kill" = "$n_live" ] \
  || die "(K) $n_kill objects remain after SIGKILL, expected all $n_live -- SIGKILL must run no teardown"
pass "(K) SIGKILL left all $n_kill runtime objects installed (netns, both veths, both rules, both tables)"

# The tool's own verdict, as an independent witness. Its exit status also counts
# on-disk artifacts (the testkit's /var/log/mm.log is always one), so assert on
# the runtime verdict it prints rather than on the status.
fxK="$(vm_ssh B "sudo $FX --dump-path /opt/mymitm/dumps" || true)"
echo "$fxK" | grep -q "runtime state is still installed" \
  || { echo "$fxK"; die "(K) the forensic tool does not report leftover runtime state after a SIGKILL; it and this validator disagree"; }
pass "(K) the forensic tool independently reports the leftovers as an unclean exit"

# ======================= (C) --cleanup is terminal ==========================
info "=== (C) --cleanup must remove it all, report it, and EXIT ==="
out="$(run_cleanup)"; rc=$?
echo "----- B: mymitm --cleanup -----"; echo "$out"; echo "-------------------------------"
[ $rc -ne 124 ] || die "(C) --cleanup did not exit within 45s -- it fell through into startup and is running as a proxy (THE BUG)"
[ $rc -eq 0 ]   || die "(C) --cleanup exited $rc; expected 0"
echo "$out" | grep -q "leftover state removed" \
  || die "(C) --cleanup did not report what it removed"
alive && die "(C) a mymitm is still running after --cleanup returned -- it started a proxy"

n_after="$(traces)"
[ "$n_after" = 0 ] || die "(C) $n_after of our objects survived --cleanup (expected 0)"
pass "(C) --cleanup exited 0, left no process behind, and removed all $n_kill objects"

fxC="$(vm_ssh B "sudo $FX --dump-path /opt/mymitm/dumps" || true)"
echo "$fxC" | grep -qE "No runtime state|^CLEAN|CLEAN: no mymitm traces" \
  || { echo "$fxC"; die "(C) the forensic tool still finds runtime state after --cleanup reported success"; }
pass "(C) the forensic tool independently reports no runtime state left"

# ======================= (I) honest on a clean box ==========================
info "=== (I) a second --cleanup must report NOTHING to clean ==="
out2="$(run_cleanup)"; rc2=$?
echo "----- B: mymitm --cleanup (again) -----"; echo "$out2"; echo "---------------------------------------"
[ $rc2 -eq 0 ] || die "(I) --cleanup on a clean box exited $rc2; expected 0"
echo "$out2" | grep -q "nothing to clean up" \
  || die "(I) --cleanup on a clean box did not report 'nothing to clean up' -- it is counting no-op commands as removals"
echo "$out2" | grep -q "leftover state removed" \
  && die "(I) --cleanup claimed it removed something on an already-clean box"
pass "(I) --cleanup is idempotent and its count is honest (empty tables are not counted as removals)"

# ======================= (B) refuses on a live instance =====================
info "=== (B) --cleanup must REFUSE while an instance is running ==="
start_proxy
n_run="$(traces)"
out3="$(run_cleanup)"; rc3=$?
echo "----- B: mymitm --cleanup (live instance) -----"; echo "$out3"; echo "----------------------------------------------"
[ $rc3 -ne 124 ] || die "(B) --cleanup hung instead of refusing"
[ $rc3 -ne 0 ]   || die "(B) --cleanup succeeded while an instance was running -- it just blackholed a live proxy"
echo "$out3" | grep -q "refusing to clean up" || die "(B) the refusal did not say it was refusing"
echo "$out3" | grep -q "pids"                 || die "(B) the refusal did not name the processes in the namespace"
alive || die "(B) the running instance died during the refused --cleanup"
n_still="$(traces)"
[ "$n_still" = "$n_run" ] \
  || die "(B) the refused --cleanup still removed state ($n_run -> $n_still); a refusal must touch nothing"
pass "(B) --cleanup refused, named the pids, and left the live instance and all $n_run objects intact"

vm_ssh B "sudo sh $TK mm-stop" >/dev/null || die "(B) mm-stop failed"
n_term="$(traces)"
[ "$n_term" = 0 ] || die "(B) $n_term objects survived a clean SIGTERM stop"
pass "(B) clean SIGTERM teardown still removes everything (RAII path unaffected)"

green "================================================================"
green " --cleanup VALIDATION PASS (kernel=$B_KERNEL, plane=$PLANE, netns mode)"
green "   (K) SIGKILL left $n_kill runtime objects installed"
green "   (C) --cleanup removed them all, reported them, and EXITED (no proxy)"
green "   (I) a second run reported nothing to clean -- the count is honest"
green "   (B) refused on a live instance, naming its pids, touching nothing"
green "================================================================"
