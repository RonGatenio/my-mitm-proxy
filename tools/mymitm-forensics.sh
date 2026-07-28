#!/bin/sh
# Show every trace mymitm leaves on a machine: the network namespace and veths,
# the policy-routing rules and tables, the eBPF programs and their attachments,
# the iptables rules of the iproute data plane, the managed sysctls, and the
# on-disk artifacts. Reports where each item lives and whether it is still there.
#
# STRICTLY READ-ONLY. This tool changes nothing, ever -- it is meant to be safe to
# run on a production box mid-incident, and to be believable afterwards. If you
# want the state removed, that is `mymitm --cleanup`, not this.
#
# Why it exists: mymitm's footprint is spread across five subsystems and two
# network namespaces, and nothing in the kernel records WHO created any of it.
# Names, addresses and rule priorities are the only attribution, and they are
# derived from config (`fwmark`) rather than fixed. Reconstructing that by hand
# during an incident is exactly when you do not want to be reading source.
#
# Usage:
#   mymitm-forensics.sh [options]
#     --fwmark <n>     fwmark the proxy runs with (default 0x1337). Everything
#                      else -- table ids, rule priorities -- derives from this, so
#                      pass it if you changed it or the tool will look in the
#                      wrong places.
#     --ns <name>      namespace name (default mitm)
#     --tun <iface>    tun_iface, if you know it. Omitted => every interface is
#     --egress <iface> egress_iface, likewise.        scanned for our classifiers.
#     --dump-path <p>  dump directory (default /var/tmp/mitm-dumps)
#     --local-addr <a> listener address (default 127.0.0.1)
#     --local-port <p> listener port (default 8443)
#     -q, --quiet      only print sections that found something
#     -h, --help       this text
#
# Exit status: 0 = nothing of ours found, 1 = traces found, 2 = usage error.
# So `mymitm-forensics.sh -q` is usable as a post-run cleanliness gate.
set -u

FWMARK=0x1337
NS=mitm
TUN=""
EGRESS=""
DUMP=/var/tmp/mitm-dumps
LOCAL_ADDR=127.0.0.1
LOCAL_PORT=8443
QUIET=0

usage() { sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-2}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --fwmark)     FWMARK="${2:?}"; shift 2 ;;
    --ns)         NS="${2:?}"; shift 2 ;;
    --tun)        TUN="${2:?}"; shift 2 ;;
    --egress)     EGRESS="${2:?}"; shift 2 ;;
    --dump-path)  DUMP="${2:?}"; shift 2 ;;
    --local-addr) LOCAL_ADDR="${2:?}"; shift 2 ;;
    --local-port) LOCAL_PORT="${2:?}"; shift 2 ;;
    -q|--quiet)   QUIET=1; shift ;;
    -h|--help)    usage 0 ;;
    *) echo "unknown option: $1" >&2; usage 2 ;;
  esac
done

# Everything below derives from fwmark exactly as the product does, so this tool
# and the proxy cannot disagree about where to look:
#   netns mode  (mymitm/src/netns.rs)   table 300+mask / 400+mask,
#                                       rule prio 31000+mask / 32000+mask
#   iproute     (mymitm/src/iproute.rs) table 100+mask, rule prio 30000+table
MASK=$(( FWMARK & 0xff ))
T_IN=$(( 300 + MASK ))
T_BACK=$(( 400 + MASK ))
P_IN=$(( 31000 + MASK ))
P_BACK=$(( 32000 + MASK ))
T_IPR=$(( 100 + MASK ))
P_IPR=$(( 30000 + T_IPR ))

# The four classifiers, by the names they are compiled under (mymitm-ebpf).
CLS="cls_tun_ingress cls_tun_egress cls_eth_ingress cls_eth_egress"

FOUND=0
RUNTIME=0   # kernel/runtime state: its presence without a process means unclean exit
DISK=0      # files: a clean exit leaves these too
SECTION=""
SECTION_HITS=0
BUF=""

if [ -t 1 ]; then B_="$(printf '\033[1m')"; R_="$(printf '\033[31m')"; G_="$(printf '\033[32m')"; D_="$(printf '\033[2m')"; Z_="$(printf '\033[0m')"
else B_=""; R_=""; G_=""; D_=""; Z_=""; fi

# Sections buffer their output so --quiet can drop the ones that found nothing.
sec() { flush; SECTION="$1"; SECTION_HITS=0; BUF=""; }
out() { BUF="$BUF$1
"; }
hit() { SECTION_HITS=$((SECTION_HITS + 1)); FOUND=$((FOUND + 1)); RUNTIME=$((RUNTIME + 1)); out "  ${R_}PRESENT${Z_}  $1"; }
# An artifact that survives a reboot and that a CLEAN exit also leaves behind.
# Counted separately: its presence says nothing about how the process exited.
disk_hit() { SECTION_HITS=$((SECTION_HITS + 1)); FOUND=$((FOUND + 1)); DISK=$((DISK + 1)); out "  ${R_}ON DISK${Z_}  $1"; }
# Present, but indistinguishable from a legitimate system value. Never counted.
unattributable() { SECTION_HITS=$((SECTION_HITS + 1)); out "  ${D_}UNKNOWN${Z_}  $1"; }
info() { out "  ${D_}·${Z_}       $1"; }
flush() {
  [ -n "$SECTION" ] || return 0
  if [ "$SECTION_HITS" -gt 0 ]; then
    printf '%s%s%s\n' "$B_" "$SECTION" "$Z_"
    printf '%s' "$BUF"
  elif [ "$QUIET" = 0 ]; then
    printf '%s%s%s  %s(nothing found)%s\n' "$B_" "$SECTION" "$Z_" "$D_" "$Z_"
    printf '%s' "$BUF"
  fi
  SECTION=""
}

have() { command -v "$1" >/dev/null 2>&1; }
# Append a multi-line block to the section buffer. A `while read` loop fed by a
# pipe runs in a SUBSHELL, so info() calls inside one update a copy of BUF and are
# silently lost; word-splitting a for-loop on newlines stays in this shell.
out_block() {
  _sifs="$IFS"; IFS='
'
  for _l in $1; do [ -n "$_l" ] && info "    $_l"; done
  IFS="$_sifs"
}
# Run a command inside the namespace, quietly failing if it does not exist.
inns() { ip netns exec "$NS" "$@" 2>/dev/null; }
ns_exists() { ip netns list 2>/dev/null | cut -d' ' -f1 | grep -qx "$NS"; }

[ "$(id -u)" -eq 0 ] || echo "${R_}warning${Z_}: not root -- bpftool, iptables and namespace inspection will be incomplete" >&2

echo "${B_}mymitm forensic report${Z_}  $(date -u '+%Y-%m-%dT%H:%M:%SZ')  host=$(uname -n)  kernel=$(uname -r)"
echo "${D_}read-only; derived from fwmark=$FWMARK -> netns tables $T_IN/$T_BACK prio $P_IN/$P_BACK, iproute table $T_IPR prio $P_IPR${Z_}"
echo

# ---------------------------------------------------------------------------
sec "1. PROCESSES"
# ---------------------------------------------------------------------------
# In namespace mode there are TWO: a supervisor in the host namespace (it owns the
# host plumbing and is the only thing that can remove it) and a child inside the
# namespace running the data plane.
# -x on the process NAME, not -f on the cmdline: a cmdline match hits the shell
# that invoked this tool from a path containing "mymitm", every editor with the
# source open, and any concurrent grep. Self-matching a forensic tool is worse than
# missing something, because it manufactures evidence.
pids="$(pgrep -x mymitm 2>/dev/null || true)"
if [ -n "$pids" ]; then
  for p in $pids; do
    [ -r "/proc/$p/cmdline" ] || continue
    cl="$(tr '\0' ' ' < "/proc/$p/cmdline")"
    netns="$(readlink "/proc/$p/ns/net" 2>/dev/null || echo '?')"
    where="host netns"
    if ns_exists; then
      ns_ino="net:[$(stat -Lc %i "/var/run/netns/$NS" 2>/dev/null || echo x)]"
      [ "$netns" = "$ns_ino" ] && where="INSIDE netns $NS"
    fi
    hit "pid $p ($where, $netns)"
    info "    $cl"
  done
else
  info "no mymitm process running (traces below, if any, are LEFTOVERS)"
fi

# ---------------------------------------------------------------------------
sec "2. NETWORK NAMESPACE"
# ---------------------------------------------------------------------------
if ns_exists; then
  f="/var/run/netns/$NS"
  hit "namespace '$NS' exists"
  info "    backing mount: $f"
  info "    inode:         net:[$(stat -Lc %i "$f" 2>/dev/null || echo '?')]"
  # No birth time on most filesystems; ctime is when `ip netns add` bind-mounted it.
  info "    created ~:     $(stat -c %z "$f" 2>/dev/null || echo '?')  (ctime of the mount)"
  np="$(ip netns pids "$NS" 2>/dev/null | tr '\n' ' ')"
  if [ -n "${np% }" ]; then info "    processes in it: ${np% }"
  else                      info "    processes in it: none (empty namespace -- a leftover)"; fi
else
  info "no namespace named '$NS'"
fi

# ---------------------------------------------------------------------------
sec "3. VIRTUAL INTERFACES (veth)"
# ---------------------------------------------------------------------------
# Two pairs: client leg and upstream leg. Only the host-side ends are visible in
# the host namespace; `ip -d link` names the peer's namespace, which is the single
# most direct piece of evidence that a device belongs to a namespace setup.
for d in mmc0 mmu0; do
  if ip link show "$d" >/dev/null 2>&1; then
    hit "host-side veth $d"
    info "    $(ip -o -d link show "$d" 2>/dev/null | tr -s ' ' | cut -c1-160)"
    a="$(ip -o -4 addr show "$d" 2>/dev/null | awk '{print $4}' | tr '\n' ' ')"
    [ -n "${a% }" ] && info "    address: ${a% }"
  fi
done
if ns_exists; then
  for d in mmc1 mmu1; do
    if inns ip link show "$d" >/dev/null 2>&1; then
      hit "namespace-side veth $d (inside $NS)"
      a="$(inns ip -o -4 addr show "$d" | awk '{print $4}' | tr '\n' ' ')"
      [ -n "${a% }" ] && info "    address: ${a% }"
    fi
  done
fi
# Anything else veth-shaped is worth showing, but is not necessarily ours.
others="$(ip -o -d link show type veth 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 \
          | grep -vxE 'mmc0|mmu0' | tr '\n' ' ' || true)"
[ -n "${others% }" ] && info "other veths on this box (not necessarily mymitm's): ${others% }"

# ---------------------------------------------------------------------------
sec "4. POLICY ROUTING (host)"
# ---------------------------------------------------------------------------
# The longest-lived trace by far. Deleting an interface does NOT delete a rule that
# references its table, so these outlive the veths and the namespace -- if you find
# exactly one category of leftover on a box, expect it to be this one.
rules="$(ip rule show 2>/dev/null || true)"
for pr in "$P_IN:netns steer, client leg" "$P_BACK:netns steer, reply leg" "$P_IPR:iproute plane, fwmark lookup"; do
  n="${pr%%:*}"; what="${pr#*:}"
  line="$(printf '%s\n' "$rules" | grep "^$n:" || true)"
  [ -n "$line" ] && { hit "ip rule priority $n  ($what)"; info "    $line"; }
done
for t in "$T_IN:netns, client leg" "$T_BACK:netns, reply leg" "$T_IPR:iproute plane"; do
  n="${t%%:*}"; what="${t#*:}"
  r="$(ip route show table "$n" 2>/dev/null || true)"
  if [ -n "$r" ]; then
    hit "routing table $n is populated  ($what)"
    out_block "$r"
  fi
done

# ---------------------------------------------------------------------------
sec "5. eBPF PROGRAMS AND ATTACHMENTS"
# ---------------------------------------------------------------------------
# Loaded programs are GLOBAL objects: a classifier attached to an interface inside
# the namespace still shows in a host-side `bpftool prog list`. Attachments are
# per-netdev and therefore per-namespace, so those must be queried in both.
if have bpftool; then
  pl="$(bpftool prog list 2>/dev/null || true)"
  for c in $CLS; do
    line="$(printf '%s\n' "$pl" | grep -- "$c" || true)"
    [ -n "$line" ] && { hit "loaded eBPF program $c"; info "    $(printf '%s\n' "$line" | head -1 | tr -s ' ')"; }
  done
  ml="$(bpftool map list 2>/dev/null | grep -i -- 'CONFIG' || true)"
  [ -n "$ml" ] && { hit "eBPF map CONFIG (the single-entry settings map)"; info "    $(printf '%s\n' "$ml" | head -1 | tr -s ' ')"; }
else
  info "bpftool not installed -- falling back to tc; install it for program-level detail"
fi
# mymitm pins nothing, so anything here belongs to something else. Worth saying so
# explicitly rather than leaving the reader to wonder.
if [ -d /sys/fs/bpf ]; then
  pins="$(ls -A /sys/fs/bpf 2>/dev/null | tr '\n' ' ' || true)"
  if [ -n "${pins% }" ]; then info "/sys/fs/bpf contains: ${pins% } ${D_}(mymitm pins nothing; not ours)${Z_}"
  else info "/sys/fs/bpf is empty (mymitm pins nothing, as expected)"; fi
fi

# Which interfaces to inspect: the ones named, else every interface in each
# namespace -- the point of a forensic tool is to not need to be told.
scan_ifaces() {  # scan_ifaces <"" for host | ns>
  if [ -n "$1" ]; then inns ip -o link show; else ip -o link show 2>/dev/null; fi \
    | awk -F': ' '{print $2}' | cut -d@ -f1
}
check_attach() {  # check_attach <ns-or-empty> <label>
  _ns="$1"; _label="$2"
  _list="${TUN:-} ${EGRESS:-}"
  [ -n "${_list# }" ] || _list="$(scan_ifaces "$_ns")"
  for d in $_list; do
    [ -n "$d" ] || continue
    if [ -n "$_ns" ]; then _q="inns"; else _q=""; fi
    _qd="$($_q tc qdisc show dev "$d" 2>/dev/null | grep -w clsact || true)"
    [ -n "$_qd" ] && { hit "clsact qdisc on $d ($_label)"; info "    $_qd"; }
    for dir in ingress egress; do
      _f="$($_q tc filter show dev "$d" "$dir" 2>/dev/null | grep -E 'bpf|cls_' || true)"
      if [ -n "$_f" ]; then
        hit "tc-bpf filter on $d $dir ($_label)"
        out_block "$(printf '%s\n' "$_f" | grep -v '^filter protocol all pref [0-9]* bpf chain 0 $' | head -2)"
      fi
    done
  done
}
check_attach "" "host namespace"
ns_exists && check_attach "$NS" "inside netns $NS"

# ---------------------------------------------------------------------------
sec "6. IPTABLES (the iproute data plane only)"
# ---------------------------------------------------------------------------
# The eBPF plane and namespace mode add NO iptables rules at all. Everything here
# belongs to `data_plane = iproute`, which DNATs in nat/PREROUTING and marks
# replies in mangle. Matched on the fwmark and on <local_addr>:<local_port>.
if have iptables; then
  for tbl in nat mangle; do
    d="$(iptables -t "$tbl" -S 2>/dev/null || true)"
    m="$(printf '%s\n' "$d" | grep -iE "$FWMARK|$MASK|$LOCAL_ADDR:$LOCAL_PORT|--to-destination $LOCAL_ADDR" || true)"
    if [ -n "$m" ]; then
      hit "iptables -t $tbl has mymitm rules"
      out_block "$m"
    fi
  done
  # Namespace mode's whole premise is that it needs no firewall change; if the
  # namespace exists, note that the filter table should be untouched by us.
  ns_exists && info "filter table: namespace mode adds nothing here by design"
else
  info "iptables not installed -- nothing to check (and the iproute plane could not have run)"
fi

# ---------------------------------------------------------------------------
sec "7. SYSCTLS"
# ---------------------------------------------------------------------------
# mymitm saves the prior value and restores it on a clean exit; a SIGKILL leaves
# these set. Shown with the value that would indicate our change, so a reader who
# does not know the box's baseline can still judge.
show_sysctl() {  # show_sysctl <proc-relative-path> <suspicious-value> <note>
  v="$(cat "/proc/sys/net/ipv4/$1" 2>/dev/null || true)"
  [ -n "$v" ] || return 0
  _name="net.ipv4.$(printf '%s' "$1" | tr '/' '.')"
  if [ "$v" = "$2" ]; then hit "$_name = $v  ($3)"
  else info "$_name = $v  ${D_}(ours would be $2)${Z_}"; fi
}
# Host side. route_localnet/rp_filter on OUR veths only exist while the veths do.
show_sysctl "conf/mmc0/rp_filter" 2 "netns mode loosens rp_filter on its own veth"
show_sysctl "conf/mmu0/rp_filter" 2 "netns mode loosens rp_filter on its own veth"
for i in ${TUN:-} ${EGRESS:-}; do
  show_sysctl "conf/$i/rp_filter" 0 "iproute plane / eBPF manage_sysctls"
  show_sysctl "conf/$i/route_localnet" 1 "needed for a loopback local_addr"
done
# NOT `show_sysctl`: 0 is what the iproute plane writes AND the kernel/Debian
# default (Debian ships no rp_filter setting at all), so a 0 here is not evidence
# of anything. Report it, attribute nothing.
_arp="$(cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || true)"
case "${_arp:-}" in
  0) unattributable "net.ipv4.conf.all.rp_filter = 0  (the iproute plane writes 0 here, but 0 is also the kernel/Debian default -- unattributable either way)" ;;
  "") ;;
  *) info "net.ipv4.conf.all.rp_filter = $_arp  ${D_}(not 0, so the iproute plane is not currently holding it down)${Z_}" ;;
esac
if ns_exists; then
  nf="$(inns cat /proc/sys/net/ipv4/ip_forward || true)"
  [ -n "$nf" ] && {
    if [ "$nf" = 0 ]; then info "in-netns ip_forward = 0  ${D_}(fail closed: eBPF plane)${Z_}"
    else hit "in-netns ip_forward = $nf  (fail OPEN -- the iproute plane sets this for itself)"; fi
  }
  for d in mmc1 mmu1; do
    v="$(inns cat "/proc/sys/net/ipv4/conf/$d/route_localnet" || true)"
    [ "${v:-0}" = 1 ] && hit "in-netns conf.$d.route_localnet = 1"
  done
fi

# ---------------------------------------------------------------------------
sec "8. ON-DISK ARTIFACTS"
# ---------------------------------------------------------------------------
# These are the only traces that survive a reboot. Everything above is runtime
# state: the namespace is a mount, the rules and tables are kernel state.
if [ -d "$DUMP" ]; then
  n="$(find "$DUMP" -type f 2>/dev/null | wc -l | tr -d ' ')"
  sz="$(du -sh "$DUMP" 2>/dev/null | cut -f1)"
  if [ "$n" -gt 0 ]; then
    disk_hit "decrypted-traffic dumps: $n file(s), $sz in $DUMP"
    info "    newest: $(find "$DUMP" -type f -printf '%T+ %p\n' 2>/dev/null | sort | tail -1)"
    info "    ${R_}these contain plaintext of intercepted sessions${Z_}"
  else
    info "$DUMP exists but is empty"
  fi
else
  info "no dump directory at $DUMP"
fi
for f in /var/log/mymitm.log /var/log/mm.log; do
  [ -f "$f" ] && { disk_hit "log file $f ($(wc -l < "$f" | tr -d ' ') lines)"; }
done

flush

# ---------------------------------------------------------------------------
echo
if [ "$FOUND" -eq 0 ]; then
  echo "${G_}CLEAN${Z_}: no mymitm traces found."
  exit 0
fi
echo "${B_}Summary${Z_}: $RUNTIME runtime trace(s), $DISK on-disk artifact(s)."
if [ -n "$(pgrep -x mymitm 2>/dev/null || true)" ]; then
  echo "A mymitm process is RUNNING, so the runtime state above is expected and live."
  echo "It is removed when the process exits cleanly (SIGTERM -- a SIGKILL skips the"
  echo "teardown entirely, since it is RAII in the supervisor process)."
elif [ "$RUNTIME" -gt 0 ]; then
  echo "${R_}No mymitm process is running, but runtime state is still installed.${Z_}"
  echo "That means the last exit was UNCLEAN -- almost always a SIGKILL, which gives"
  echo "the supervisor's teardown no chance to run. Expect the policy-routing rules to"
  echo "be the longest-lived part: deleting an interface does not delete a rule that"
  echo "references its table."
  echo
  echo "${B_}To remove it, run these (derived from fwmark=$FWMARK):${Z_}"
  echo "    ip rule del priority $P_IN"
  echo "    ip rule del priority $P_BACK"
  echo "    ip route flush table $T_IN"
  echo "    ip route flush table $T_BACK"
  echo "    ip netns del $NS            # takes mmc1/mmu1, and with them mmc0/mmu0"
  echo "    ip link del mmc0 ; ip link del mmu0    # only if the netns was already gone"
  echo "    ip rule del priority $P_IPR ; ip route flush table $T_IPR   # iproute plane only"
  echo
  echo "${D_}NOT \`mymitm --cleanup\`: that flag reverses leftovers and then CONTINUES${Z_}"
  echo "${D_}STARTUP (documented behaviour), so on a netns config it rebuilds everything${Z_}"
  echo "${D_}it just removed and runs as a proxy. There is no clean-and-exit mode today.${Z_}"
else
  echo "No runtime state: the last exit tore everything down correctly."
  echo "What remains is on disk only, which a clean exit also leaves. Note the dumps"
  echo "contain PLAINTEXT of intercepted sessions -- delete them when done."
fi
echo
echo "${D_}This tool changed nothing. Re-run it after removing state to confirm.${Z_}"
exit 1
