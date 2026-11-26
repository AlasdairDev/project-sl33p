#!/usr/bin/env bash
#
# Create the sl33p Windows 11 lab VM under session libvirt.
#
#   ISO=/path/to/Win11.iso VIRTIO_ISO=/path/to/virtio-win.iso ./lab/create-vm.sh
#   DRY_RUN=1 ... ./lab/create-vm.sh          # print, do not create
#
# Session libvirt means: no root, no svirt labels, and the qcow2 is owned by
# you. That matches the existing owasp-bwa VM on this host.

set -euo pipefail

VM_NAME="${VM_NAME:-sl33p-win11}"
VM_DIR="${VM_DIR:-$HOME/lab/vms}"
ISO="${ISO:-}"
VIRTIO_ISO="${VIRTIO_ISO:-}"
REPO_DIR="${REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
DISK_GIB="${DISK_GIB:-64}"
RAM_MB="${RAM_MB:-4096}"
VCPUS="${VCPUS:-4}"
NETWORK="${NETWORK:-user}" # 'none' for an offline build from the first boot
DRY_RUN="${DRY_RUN:-0}"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '  %s\n' "$*"; }

[ -n "$ISO" ] || die "set ISO=/path/to/Win11.iso"
[ -f "$ISO" ] || die "ISO not found: $ISO"
[ -d "$REPO_DIR" ] || die "repo not found: $REPO_DIR"

command -v virt-install >/dev/null 2>&1 || die "virt-install is not installed"
command -v virsh >/dev/null 2>&1 || die "virsh is not installed"

if virsh -c qemu:///session dominfo "$VM_NAME" >/dev/null 2>&1; then
  die "domain '$VM_NAME' already exists (virsh -c qemu:///session list --all)"
fi

DISK="$VM_DIR/$VM_NAME.qcow2"
[ -e "$DISK" ] && die "disk already exists: $DISK"

# 4 GiB RAM + a 64 GiB disk is the practical floor for Windows 11 + tooling.
if [ "$(id -u)" -eq 0 ]; then
  die "run as your user, not root (session libvirt, no sudo)"
fi

mkdir -p "$VM_DIR"

args=(
  --connect qemu:///session
  --name "$VM_NAME"
  --memory "$RAM_MB"
  --vcpus "$VCPUS"
  --machine q35
  --cpu host-passthrough
  --osinfo win11
  --boot uefi
  --tpm backend.type=emulator,backend.version=2.0,model=tpm-crb
  --disk "path=$DISK,size=$DISK_GIB,format=qcow2,bus=virtio,cache=writeback"
  --cdrom "$ISO"
  --graphics spice
  --video virtio
  --filesystem "$REPO_DIR,sl33p,driver.type=virtiofs"
  --noautoconsole
)

if [ -n "$VIRTIO_ISO" ]; then
  [ -f "$VIRTIO_ISO" ] || die "virtio ISO not found: $VIRTIO_ISO"
  args+=(--disk "path=$VIRTIO_ISO,device=cdrom,bus=sata")
fi

case "$NETWORK" in
  none) args+=(--network none) ;;
  user) args+=(--network user) ;;
  *) die "NETWORK must be 'user' or 'none'" ;;
esac

printf 'Creating %s\n' "$VM_NAME"
note "disk     $DISK (${DISK_GIB} GiB)"
note "memory   ${RAM_MB} MiB, ${VCPUS} vCPU"
note "share    $REPO_DIR -> Z: (virtiofs, needs WinFsp in the guest)"
note "network  $NETWORK"
note "uri      qemu:///session"

if [ "$DRY_RUN" != "0" ]; then
  printf '\nvirt-install'
  printf ' %q' "${args[@]}"
  printf '\n'
  exit 0
fi

virt-install "${args[@]}"

cat <<EOF

Next:
  1. virt-manager -> QEMU/KVM User session -> $VM_NAME
  2. Install Windows 11 (local account: Shift+F10, start ms-cxh:localonly)
  3. Install virtio drivers + guest agent (+ WinFsp/virtiofs for the Z: share)
  4. Install .NET 10 SDK and Python 3.13, build src/core
  5. Remove the NIC, then snapshot baseline-offline:
       virsh -c qemu:///session snapshot-create-as $VM_NAME baseline-offline --atomic
  6. Read lab/vm-setup.md before the first hunt
EOF
