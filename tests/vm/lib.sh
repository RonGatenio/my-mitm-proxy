#!/usr/bin/env bash
# Shared constants + helpers for the VM test harness. Source, don't execute.

VM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$VM_DIR/../.." && pwd)"
WORK="$VM_DIR/.work"
IMG_DIR="$WORK/images"
CERT_DIR="$WORK/certs"

# The SSH private key MUST be mode 0600 or OpenSSH refuses it. On a Windows drvfs
# mount (repo under /mnt/c/... in WSL) every file is 0777 and chmod is ignored, so
# the key cannot live under $WORK there. Keep it on a native filesystem instead.
KEYDIR="${MYMITM_VM_KEYDIR:-/tmp/mymitm-vm}"
SSH_KEY="$KEYDIR/ssh_key"

BIN="$REPO_ROOT/target/x86_64-unknown-linux-musl/release/mymitm"

# --- kernel target for B (the router/proxy) --------------------------------
# 4.15     -> bionic cloud image's own distro kernel (default; original harness).
# 5.10     -> jammy rootfs booted with an external vanilla 5.10 kernel from the
#             Cilium lvh catalog, with its modules delivered to the guest over 9p.
# debian11 -> Debian 11 "bullseye" cloud image on its OWN native 5.10 kernel
#             (uname -r == 5.10.0-xx-amd64). Distro-exact proof; a full distro
#             kernel, so the iproute plane's netfilter tcp match works too.
B_KERNEL="${B_KERNEL:-4.15}"
LVH_DIR="$WORK/lvh"
KVER_510="5.10.260"
LVH_TAG_510="5.10-main"
VMLINUZ_510="$LVH_DIR/$LVH_TAG_510/boot/vmlinuz-$KVER_510"
MODS_PARENT_510="$LVH_DIR/$LVH_TAG_510/lib/modules"   # contains <KVER_510>/

# --- topology constants ----------------------------------------------------
# Host-global iface names are env-overridable so a second checkout can run
# concurrently on the same host without colliding (defaults unchanged).
BR_LEFT="${BR_LEFT:-br-left}"
BR_RIGHT="${BR_RIGHT:-br-right}"
TAP_AL="${TAP_AL:-tap-al}"      # A  data  -> br-left
TAP_BL="${TAP_BL:-tap-bl}"      # B  left  -> br-left
TAP_BR="${TAP_BR:-tap-br}"      # B  right -> br-right
TAP_CR="${TAP_CR:-tap-cr}"      # C  data  -> br-right

A_IP=10.10.1.10
B_LEFT_IP=10.10.1.1
B_RIGHT_IP=10.10.2.1
C_IP=10.10.2.10

# Data-leg iface names mymitm binds on B. Ubuntu's netplan renderer honors the
# cloud-init `set-name:` so these hold; Debian's renderer may not, so they are
# re-resolved by MAC at runtime (see b_resolve_ifaces).
B_LEFT_IFACE="${B_LEFT_IFACE:-left0}"
B_RIGHT_IFACE="${B_RIGHT_IFACE:-right0}"

# control NIC = user-mode; data NIC MACs bind the network-config.
MAC_A_CTRL=52:54:00:00:00:0a; MAC_A_DATA=52:54:00:00:01:0a
MAC_B_CTRL=52:54:00:00:00:0b; MAC_B_LEFT=52:54:00:00:01:0b; MAC_B_RIGHT=52:54:00:00:02:0b
MAC_C_CTRL=52:54:00:00:00:0c; MAC_C_DATA=52:54:00:00:02:0c

SSH_PORT_A="${SSH_PORT_A:-2201}"; SSH_PORT_B="${SSH_PORT_B:-2202}"; SSH_PORT_C="${SSH_PORT_C:-2203}"

# Maintained "current" cloud images (bionic kernel == 4.15).
URL_BIONIC="https://cloud-images.ubuntu.com/bionic/current/bionic-server-cloudimg-amd64.img"
URL_JAMMY="https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
IMG_BIONIC="$IMG_DIR/bionic-server-cloudimg-amd64.img"
IMG_JAMMY="$IMG_DIR/jammy-server-cloudimg-amd64.img"

# Debian 11 "bullseye" genericcloud image ships a native 5.10 kernel. Debian
# publishes SHA512SUMS (not Ubuntu's SHA256SUMS); _fetch_one takes the sums
# file + checksum tool as optional args to cope with both.
URL_DEB11="https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-genericcloud-amd64.qcow2"
IMG_DEB11="$IMG_DIR/debian-11-genericcloud-amd64.qcow2"

# --- output helpers --------------------------------------------------------
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m[vm]\033[0m %s\n' "$*"; }
pass()  { green "PASS: $*"; }
fail()  { red "FAIL: $*"; exit 1; }

ssh_port_for() { case "$1" in A) echo "$SSH_PORT_A";; B) echo "$SSH_PORT_B";; C) echo "$SSH_PORT_C";; esac; }

# --- ssh key ---------------------------------------------------------------
ssh_keygen_once() {
  mkdir -p "$WORK" "$KEYDIR"
  chmod 700 "$KEYDIR" 2>/dev/null || true
  [ -f "$SSH_KEY" ] || ssh-keygen -t ed25519 -N "" -f "$SSH_KEY" -q
  chmod 600 "$SSH_KEY" 2>/dev/null || true
  export SSH_PUBKEY="$(cat "$SSH_KEY.pub")"
}

SSH_OPTS=(-i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o ConnectTimeout=5 -o LogLevel=ERROR)

vm_ssh() { local vm="$1"; shift; ssh "${SSH_OPTS[@]}" -p "$(ssh_port_for "$vm")" ubuntu@127.0.0.1 "$@"; }
vm_scp() { local vm="$1" src="$2" dst="$3"; scp "${SSH_OPTS[@]}" -P "$(ssh_port_for "$vm")" "$src" "ubuntu@127.0.0.1:$dst"; }

# Resolve the current kernel iface name carrying a given MAC on a VM.
vm_iface_by_mac() {  # vm_iface_by_mac <vm> <mac>
  vm_ssh "$1" "for d in /sys/class/net/*; do read -r m < \"\$d/address\" 2>/dev/null; \
    [ \"\$m\" = \"$2\" ] && { basename \"\$d\"; break; }; done"
}

# Debian's cloud-init may use the eni/ifupdown renderer, which ignores netplan's
# `set-name:` — so B's data legs may NOT be named left0/right0 even though their
# addresses (matched by MAC) land correctly. Re-resolve the real names by MAC and
# feed them to mymitm; correct whether or not set-name took effect. No-op on the
# Ubuntu targets (left0/right0), so those paths stay byte-for-byte unchanged.
b_resolve_ifaces() {
  [ "$B_KERNEL" = debian11 ] || return 0
  B_LEFT_IFACE="$(vm_iface_by_mac B "$MAC_B_LEFT")"
  B_RIGHT_IFACE="$(vm_iface_by_mac B "$MAC_B_RIGHT")"
  [ -n "$B_LEFT_IFACE" ] && [ -n "$B_RIGHT_IFACE" ] \
    || fail "B: could not resolve data-leg ifaces by MAC (left=$MAC_B_LEFT right=$MAC_B_RIGHT)"
  info "B data legs (Debian): left=$B_LEFT_IFACE right=$B_RIGHT_IFACE"
}

wait_ssh() {
  local vm="$1" i
  for i in $(seq 1 120); do
    vm_ssh "$vm" true 2>/dev/null && { info "$vm SSH up"; return 0; }
    sleep 2
  done
  fail "$vm did not become SSH-reachable"
}

# --- host networking -------------------------------------------------------
_br_add()  { ip link show "$1" >/dev/null 2>&1 || ip link add "$1" type bridge; ip link set "$1" up; }
_tap_add() { ip link show "$2" >/dev/null 2>&1 || ip tuntap add "$2" mode tap; ip link set "$2" master "$1"; ip link set "$2" up; }

net_up() {
  info "creating bridges + taps"
  _br_add "$BR_LEFT"; _br_add "$BR_RIGHT"
  _tap_add "$BR_LEFT"  "$TAP_AL"
  _tap_add "$BR_LEFT"  "$TAP_BL"
  _tap_add "$BR_RIGHT" "$TAP_BR"
  _tap_add "$BR_RIGHT" "$TAP_CR"
  # Allow forwarding through the test bridges.
  # When bridge-nf-call-iptables=1 the kernel runs bridged frames through
  # the iptables FORWARD chain with both IN and OUT set to the bridge device.
  for br in "$BR_LEFT" "$BR_RIGHT"; do
    iptables -C FORWARD -i "$br" -o "$br" -j ACCEPT 2>/dev/null \
      || iptables -I FORWARD 1 -i "$br" -o "$br" -j ACCEPT
  done
}

net_down() {
  info "removing taps + bridges"
  for t in "$TAP_AL" "$TAP_BL" "$TAP_BR" "$TAP_CR"; do ip link del "$t" 2>/dev/null || true; done
  for b in "$BR_LEFT" "$BR_RIGHT"; do ip link del "$b" 2>/dev/null || true; done
  for br in "$BR_LEFT" "$BR_RIGHT"; do
    iptables -D FORWARD -i "$br" -o "$br" -j ACCEPT 2>/dev/null || true
  done
}

# --- images ----------------------------------------------------------------
_fetch_one() {  # _fetch_one <url> <dest> [sums_file] [sum_cmd]
  local url="$1" dest="$2" sums="${3:-SHA256SUMS}" sumcmd="${4:-sha256sum}" base
  base="$(basename "$dest")"
  if [ -f "$dest" ]; then info "image cached: $base"; return 0; fi
  info "downloading $base"
  curl -fSL "$url" -o "$dest.part"
  curl -fsSL "$(dirname "$url")/$sums" -o "$IMG_DIR/$sums.$base"
  ( cd "$IMG_DIR" && grep "[* ]$base\$" "$sums.$base" | sed "s|[* ].*|  $dest.part|" | "$sumcmd" -c - ) \
    || fail "checksum mismatch for $base"
  mv "$dest.part" "$dest"
}

img_fetch() {
  mkdir -p "$IMG_DIR"
  _fetch_one "$URL_JAMMY" "$IMG_JAMMY"                              # A and C always
  case "$B_KERNEL" in
    5.10)     kernel_fetch_510 ;;                                  # B: jammy rootfs + external kernel
    debian11) _fetch_one "$URL_DEB11" "$IMG_DEB11" SHA512SUMS sha512sum ;;  # B: Debian 11 native 5.10
    *)        _fetch_one "$URL_BIONIC" "$IMG_BIONIC" ;;            # B: 4.15 distro kernel
  esac
}

# Pull the vanilla 5.10 kernel + its modules from the Cilium lvh catalog (cached).
kernel_fetch_510() {
  if [ -f "$VMLINUZ_510" ] && [ -d "$MODS_PARENT_510/$KVER_510" ]; then
    info "lvh 5.10 kernel cached ($KVER_510)"; return 0
  fi
  command -v lvh >/dev/null 2>&1 || fail "lvh not on PATH; needed to fetch the 5.10 kernel (see tests/vm/README.md)"
  info "pulling lvh $LVH_TAG_510 kernel (vmlinuz + modules)"
  mkdir -p "$LVH_DIR"
  ( cd "$LVH_DIR" && lvh kernels pull "$LVH_TAG_510" --dir . ) || fail "lvh kernels pull $LVH_TAG_510 failed"
  [ -f "$VMLINUZ_510" ] || fail "expected $VMLINUZ_510 after lvh pull"
}

# B (5.10) boots an external kernel whose modules are not in the jammy rootfs.
# The launcher exports them over 9p (tag mmmods); copy them into place so the
# modular clsact (sch_ingress) and iptables mangle/mark targets are loadable.
b_install_modules_510() {
  vm_ssh B "sudo mkdir -p /mnt/mmmods \
    && sudo mount -t 9p -o trans=virtio,ro mmmods /mnt/mmmods \
    && sudo cp -a /mnt/mmmods/$KVER_510 /lib/modules/ \
    && sudo depmod $KVER_510 \
    && sudo umount /mnt/mmmods" \
    || fail "B: installing 5.10 modules from the 9p share failed"
  vm_ssh B "sudo modprobe sch_ingress" \
    || fail "B: clsact module (sch_ingress) failed to load on $KVER_510"
}

# --- per-VM seed + overlay -------------------------------------------------
vm_seed() {  # vm_seed <A|B|C>
  local vm="$1" lc; lc="$(echo "$vm" | tr 'A-Z' 'a-z')"
  local ud="$WORK/$vm.user-data" nc="$VM_DIR/cloud-init/$lc-network-config" md="$WORK/$vm.meta-data"
  HOSTNAME="vm-$lc" envsubst '${HOSTNAME} ${SSH_PUBKEY}' < "$VM_DIR/cloud-init/$lc-user-data" > "$ud"
  HOSTNAME="vm-$lc" envsubst '${HOSTNAME}'              < "$VM_DIR/cloud-init/meta-data.tmpl" > "$md"
  cloud-localds --network-config="$nc" "$WORK/$vm.seed.iso" "$ud" "$md"
}

vm_overlay() {  # vm_overlay <vm> <base_img>
  local vm="$1" base="$2"
  qemu-img create -f qcow2 -F qcow2 -b "$base" "$WORK/$vm.overlay.qcow2" 8G >/dev/null
}

# --- launch ----------------------------------------------------------------
_accel() { [ -w /dev/kvm ] && echo "-enable-kvm -cpu host" || { info "no /dev/kvm: TCG fallback (slow)"; echo "-cpu max"; }; }

_data_args() {  # echoes -netdev/-device pairs for a VM's data NIC(s)
  case "$1" in
    A) echo "-netdev tap,id=d0,ifname=$TAP_AL,script=no,downscript=no -device virtio-net-pci,netdev=d0,mac=$MAC_A_DATA";;
    B) echo "-netdev tap,id=d0,ifname=$TAP_BL,script=no,downscript=no -device virtio-net-pci,netdev=d0,mac=$MAC_B_LEFT" \
            "-netdev tap,id=d1,ifname=$TAP_BR,script=no,downscript=no -device virtio-net-pci,netdev=d1,mac=$MAC_B_RIGHT";;
    C) echo "-netdev tap,id=d0,ifname=$TAP_CR,script=no,downscript=no -device virtio-net-pci,netdev=d0,mac=$MAC_C_DATA";;
  esac
}

vm_launch() {  # vm_launch <A|B|C> <ctrl_mac> <ssh_port>
  local vm="$1" cmac="$2" port="$3"
  # For B on the 5.10 target: boot jammy with the external lvh kernel (no initrd —
  # the lvh kernel has virtio/ext4 built in) and expose its modules over 9p. An
  # empty array otherwise, so the 4.15 path is byte-for-byte unchanged.
  local -a kargs=()
  if [ "$B_KERNEL" = 5.10 ] && [ "$vm" = B ]; then
    kargs=( -kernel "$VMLINUZ_510"
            -append "root=/dev/vda1 ro console=ttyS0"
            -virtfs "local,path=$MODS_PARENT_510,mount_tag=mmmods,security_model=none,readonly=on" )
  fi
  # shellcheck disable=SC2046
  qemu-system-x86_64 $(_accel) -m 1024 -smp 2 -display none \
    -drive file="$WORK/$vm.overlay.qcow2",if=virtio \
    -cdrom "$WORK/$vm.seed.iso" \
    -netdev user,id=mgmt,hostfwd=tcp:127.0.0.1:$port-:22 \
    -device virtio-net-pci,netdev=mgmt,mac=$cmac \
    $(_data_args "$vm") \
    "${kargs[@]}" \
    -serial file:"$WORK/$vm.serial.log" \
    -pidfile "$WORK/$vm.pid" -daemonize
  info "$vm launched (ssh port $port${kargs:+, kernel $KVER_510})"
}

vms_kill() {
  for vm in A B C; do
    [ -f "$WORK/$vm.pid" ] && kill "$(cat "$WORK/$vm.pid")" 2>/dev/null || true
    rm -f "$WORK/$vm.pid"
  done
}
