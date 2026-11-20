#!/usr/bin/env bash
set -euo pipefail

# Safely installs Serenity Linux rootfs + kernel/initrd onto a dedicated ext4 partition
# and optionally registers a dual-boot GRUB menu entry alongside Ubuntu.
#
# Usage:
#   make disk   # first build rootfs-stage as your regular user
#   sudo ./scripts/install-to-partition.sh /dev/nvme0n1pX [--grub]

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE_DIR="${ROOT_DIR}/build/rootfs-stage"
CUSTOM_KERNEL="${ROOT_DIR}/build/bzImage"
HOST_KERNEL="/boot/vmlinuz"
HOST_INITRD="/boot/initrd.img"

if [ "${EUID}" -ne 0 ]; then
    echo "ERROR: Please run with sudo: sudo $0 /dev/<ext4-partition> [--grub]"
    exit 1
fi

if [ $# -lt 1 ]; then
    echo "Usage: sudo $0 /dev/<ext4-partition> [--grub]"
    echo "Tip: Run 'lsblk -f' to check your ext4 partition name."
    exit 1
fi

PART="$1"
INSTALL_GRUB=0
if [ "${2:-}" = "--grub" ]; then
    INSTALL_GRUB=1
fi

if [ ! -b "${PART}" ]; then
    echo "ERROR: ${PART} is not a block device."
    exit 1
fi

if [ ! -d "${STAGE_DIR}" ] || [ ! -x "${STAGE_DIR}/init" ]; then
    echo "ERROR: Missing ${STAGE_DIR}. Run 'make disk' (as normal user) first."
    exit 1
fi

# Safety guard: never touch mounted system partitions
MOUNTPOINT="$(findmnt -n -o TARGET "${PART}" 2>/dev/null || true)"
if [ -n "${MOUNTPOINT}" ]; then
    case "${MOUNTPOINT}" in
        /|/boot|/boot/efi|/home|/var|/usr)
            echo "ABORT: Refusing to touch active system mount '${MOUNTPOINT}' (${PART})!"
            exit 1
            ;;
    esac
fi

FSTYPE="$(blkid -o value -s TYPE "${PART}" 2>/dev/null || true)"
if [ "${FSTYPE}" != "ext4" ]; then
    echo "ERROR: ${PART} filesystem is '${FSTYPE:-unknown}', expected 'ext4'."
    echo "Format it first if it's a new empty partition: sudo mkfs.ext4 -L SERENITY ${PART}"
    exit 1
fi

UUID="$(blkid -o value -s UUID "${PART}")"
SIZE="$(lsblk -no SIZE "${PART}")"

echo "============================================================"
echo "  Serenity Linux Partition Installer"
echo "  Target partition : ${PART} (${SIZE}, ext4)"
echo "  Partition UUID   : ${UUID}"
echo "  RootFS source    : ${STAGE_DIR}"
echo "============================================================"
read -r -p "Type YES to install Serenity Linux onto ${PART}: " CONFIRM
if [ "${CONFIRM}" != "YES" ]; then
    echo "Aborted."
    exit 1
fi

MNT="$(mktemp -d /tmp/serenity-mnt.XXXXXX)"
cleanup() {
    sync
    if mountpoint -q "${MNT}"; then
        umount "${MNT}"
    fi
    rmdir "${MNT}" 2>/dev/null || true
}
trap cleanup EXIT

mount "${PART}" "${MNT}"

echo "[install] Copying Serenity rootfs..."
cp -a "${STAGE_DIR}/." "${MNT}/"

mkdir -p "${MNT}/boot"
USE_INITRD=0
if [ -r "${CUSTOM_KERNEL}" ]; then
    echo "[install] Using custom Serenity kernel: ${CUSTOM_KERNEL}"
    cp -L "${CUSTOM_KERNEL}" "${MNT}/boot/vmlinuz-serenity"
else
    echo "[install] Using host kernel + initrd (for NVMe/USB-HID drivers on bare metal)..."
    cp -L "${HOST_KERNEL}" "${MNT}/boot/vmlinuz-serenity"
    if [ -r "${HOST_INITRD}" ]; then
        cp -L "${HOST_INITRD}" "${MNT}/boot/initrd-serenity.img"
        USE_INITRD=1
    fi
fi

# Ensure root ownership
chown -R 0:0 "${MNT}"
sync

GRUB_ENTRY=$(cat <<EOF
menuentry "Serenity Linux 0.1.0 (Rust + Nushell)" {
    insmod part_gpt
    insmod ext2
    search --no-floppy --fs-uuid --set=root ${UUID}
    linux /boot/vmlinuz-serenity root=UUID=${UUID} rw init=/init
$( [ "${USE_INITRD}" -eq 1 ] && echo "    initrd /boot/initrd-serenity.img" )
}
EOF
)

echo ""
echo "[install] Serenity Linux installed cleanly to ${PART}!"
echo ""
if [ "${INSTALL_GRUB}" -eq 1 ]; then
    GRUB_FILE="/etc/grub.d/40_serenity"
    printf '#!/bin/sh\nexec tail -n +3 $0\n%s\n' "${GRUB_ENTRY}" > "${GRUB_FILE}"
    chmod +x "${GRUB_FILE}"
    echo "[install] Wrote ${GRUB_FILE}, running update-grub..."
    update-grub
    echo "[install] Done! Reboot and choose 'Serenity Linux 0.1.0' in GRUB."
else
    echo "Next step — add this entry to /etc/grub.d/40_custom and run 'sudo update-grub'"
    echo "(or re-run this script with --grub to do it automatically):"
    echo ""
    echo "${GRUB_ENTRY}"
fi
