#!/usr/bin/env bash
# Shared constants + helpers for the VM test harness. Source, don't execute.

VM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$VM_DIR/../.." && pwd)"
WORK="$VM_DIR/.work"
IMG_DIR="$WORK/images"
CERT_DIR="$WORK/certs"
SSH_KEY="$WORK/ssh_key"

BIN="$REPO_ROOT/target/x86_64-unknown-linux-musl/release/mymitm"

# --- topology constants ----------------------------------------------------
BR_LEFT=br-left
BR_RIGHT=br-right
TAP_AL=tap-al      # A  data  -> br-left
TAP_BL=tap-bl      # B  left  -> br-left
TAP_BR=tap-br      # B  right -> br-right
TAP_CR=tap-cr      # C  data  -> br-right

A_IP=10.10.1.10
B_LEFT_IP=10.10.1.1
B_RIGHT_IP=10.10.2.1
C_IP=10.10.2.10

# control NIC = user-mode; data NIC MACs bind the network-config.
MAC_A_CTRL=52:54:00:00:00:0a; MAC_A_DATA=52:54:00:00:01:0a
MAC_B_CTRL=52:54:00:00:00:0b; MAC_B_LEFT=52:54:00:00:01:0b; MAC_B_RIGHT=52:54:00:00:02:0b
MAC_C_CTRL=52:54:00:00:00:0c; MAC_C_DATA=52:54:00:00:02:0c

SSH_PORT_A=2201; SSH_PORT_B=2202; SSH_PORT_C=2203

# Maintained "current" cloud images (bionic kernel == 4.15).
URL_BIONIC="https://cloud-images.ubuntu.com/bionic/current/bionic-server-cloudimg-amd64.img"
URL_JAMMY="https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
IMG_BIONIC="$IMG_DIR/bionic-server-cloudimg-amd64.img"
IMG_JAMMY="$IMG_DIR/jammy-server-cloudimg-amd64.img"

# --- output helpers --------------------------------------------------------
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m[vm]\033[0m %s\n' "$*"; }
pass()  { green "PASS: $*"; }
fail()  { red "FAIL: $*"; exit 1; }

ssh_port_for() { case "$1" in A) echo "$SSH_PORT_A";; B) echo "$SSH_PORT_B";; C) echo "$SSH_PORT_C";; esac; }

# --- ssh key ---------------------------------------------------------------
ssh_keygen_once() {
  mkdir -p "$WORK"
  [ -f "$SSH_KEY" ] || ssh-keygen -t ed25519 -N "" -f "$SSH_KEY" -q
  export SSH_PUBKEY="$(cat "$SSH_KEY.pub")"
}

SSH_OPTS=(-i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o ConnectTimeout=5 -o LogLevel=ERROR)

vm_ssh() { local vm="$1"; shift; ssh "${SSH_OPTS[@]}" -p "$(ssh_port_for "$vm")" ubuntu@127.0.0.1 "$@"; }
vm_scp() { local vm="$1" src="$2" dst="$3"; scp "${SSH_OPTS[@]}" -P "$(ssh_port_for "$vm")" "$src" "ubuntu@127.0.0.1:$dst"; }

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
}

net_down() {
  info "removing taps + bridges"
  for t in "$TAP_AL" "$TAP_BL" "$TAP_BR" "$TAP_CR"; do ip link del "$t" 2>/dev/null || true; done
  for b in "$BR_LEFT" "$BR_RIGHT"; do ip link del "$b" 2>/dev/null || true; done
}

# --- images ----------------------------------------------------------------
_fetch_one() {
  local url="$1" dest="$2" base; base="$(basename "$dest")"
  if [ -f "$dest" ]; then info "image cached: $base"; return 0; fi
  info "downloading $base"
  curl -fSL "$url" -o "$dest.part"
  curl -fsSL "$(dirname "$url")/SHA256SUMS" -o "$IMG_DIR/SHA256SUMS.$base"
  ( cd "$IMG_DIR" && grep "[* ]$base\$" "SHA256SUMS.$base" | sed "s|[* ].*|  $dest.part|" | sha256sum -c - ) \
    || fail "checksum mismatch for $base"
  mv "$dest.part" "$dest"
}

img_fetch() {
  mkdir -p "$IMG_DIR"
  _fetch_one "$URL_BIONIC" "$IMG_BIONIC"
  _fetch_one "$URL_JAMMY"  "$IMG_JAMMY"
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
  # shellcheck disable=SC2046
  qemu-system-x86_64 $(_accel) -m 1024 -smp 2 -nographic -display none \
    -drive file="$WORK/$vm.overlay.qcow2",if=virtio \
    -cdrom "$WORK/$vm.seed.iso" \
    -netdev user,id=mgmt,hostfwd=tcp:127.0.0.1:$port-:22 \
    -device virtio-net-pci,netdev=mgmt,mac=$cmac \
    $(_data_args "$vm") \
    -serial file:"$WORK/$vm.serial.log" \
    -pidfile "$WORK/$vm.pid" -daemonize
  info "$vm launched (ssh port $port)"
}

vms_kill() {
  for vm in A B C; do
    [ -f "$WORK/$vm.pid" ] && kill "$(cat "$WORK/$vm.pid")" 2>/dev/null || true
    rm -f "$WORK/$vm.pid"
  done
}
