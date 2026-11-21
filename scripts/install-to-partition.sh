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
PARTUUID="$(blkid -o value -s PARTUUID "${PART}" 2>/dev/null || true)"
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

# Remove any legacy broken symlinks on the target partition (e.g. /usr/share/X11/xkb)
# before copying real directories from STAGE_DIR so 'cp -a' does not fail with
# "cannot overwrite non-directory ... with directory".
if [ -L "${MNT}/usr/share/X11/xkb" ]; then
    rm -f "${MNT}/usr/share/X11/xkb"
fi

echo "[install] Copying Serenity rootfs..."
cp -a "${STAGE_DIR}/." "${MNT}/"

# Automatically bundle Smithay compositor + Serenity Shell GUI if release binaries are built
if [ -x "${ROOT_DIR}/target/release/serenity-compositor" ]; then
    echo "[install] Detected release compositor build; bundling Smithay + GUI libraries..."
    "${ROOT_DIR}/scripts/bundle-compositor.sh" "${MNT}"
fi

mkdir -p "${MNT}/boot"
USE_INITRD=0
if [ -e "${STAGE_DIR}/boot/vmlinuz-serenity" ]; then
    # Serenity's own kernel package (linux): drivers are built-in or loaded by
    # serenity-init through kmod, firmware comes from the linux-firmware package.
    echo "[install] Using Serenity kernel $(readlink "${STAGE_DIR}/boot/vmlinuz-serenity") (no initrd, no host modules)"
    SERENITY_KERNEL=1
else
SERENITY_KERNEL=0
echo "[install] Copying host kernel + initrd (for NVMe/USB-HID/DRM/Wi-Fi drivers on bare metal)..."
cp -L "${HOST_KERNEL}" "${MNT}/boot/vmlinuz-serenity"
if [ -r "${HOST_INITRD}" ]; then
    cp -L "${HOST_INITRD}" "${MNT}/boot/initrd-serenity.img"
    USE_INITRD=1
fi

# Bundle hardware kernel modules (decompressed .ko) + Intel firmware for bare-metal Wi-Fi, GPU & touchpad
KVER="$(readlink -f "${HOST_KERNEL}" | sed -E 's|^.*/vmlinuz-||')"
echo "[install] Bundling bare-metal drivers for kernel ${KVER} (iwlwifi, iwlmvm, i915, hid, psmouse)..."
MOD_OUT="${MNT}/lib/modules/serenity"
MOD_LIST="${MNT}/etc/serenity/modules.load"
mkdir -p "${MOD_OUT}" "${MNT}/etc/serenity" "${MNT}/lib/firmware"
: > "${MOD_LIST}"

declare -A SEEN_MODS=()
TARGET_MODS=(
    ccm cmac aesni_intel libarc4 iwlwifi iwlmvm i915
    usbhid hid_generic hid_multitouch i2c_hid_acpi psmouse
    snd snd_pcm snd_rawmidi snd_ctl_led snd_seq snd_hrtimer
    snd_hda_intel snd_hda_codec_realtek snd_hda_codec_alc269 snd_hda_codec_alc662 snd_hda_codec_alc882
    snd_hda_codec_conexant snd_hda_codec_cirrus snd_hda_codec_cs8409
    snd_hda_codec_intelhdmi snd_hda_codec_nvhdmi snd_hda_codec_atihdmi
    snd_hda_codec_generic snd_hda_codec_hdmi
    snd_soc_skl_hda_dsp snd_soc_dmic snd_soc_hdac_hdmi snd_soc_sof_sdw
    snd_sof_pci_intel_tgl snd_sof_pci_intel_adl snd_sof_pci_intel_mtl snd_sof_pci_intel_cnl
    snd_usb_audio
)
for mod in "${TARGET_MODS[@]}"; do
    while read -r kind modpath _; do
        [ "${kind}" = "insmod" ] || continue
        [ -f "${modpath}" ] || continue
        base="$(basename "${modpath}")"
        base_ko="${base%.zst}"
        base_ko="${base_ko%.xz}"
        base_ko="${base_ko%.gz}"
        if [ -n "${SEEN_MODS[${base_ko}]:-}" ]; then
            continue
        fi
        SEEN_MODS["${base_ko}"]=1
        dest_ko="${MOD_OUT}/${base_ko}"
        case "${modpath}" in
            *.ko.zst) zstd -dq -c "${modpath}" > "${dest_ko}" ;;
            *.ko.xz)  xz -dc "${modpath}" > "${dest_ko}" ;;
            *.ko.gz)  gzip -dc "${modpath}" > "${dest_ko}" ;;
            *.ko)     cp "${modpath}" "${dest_ko}" ;;
        esac
        echo "/lib/modules/serenity/${base_ko}" >> "${MOD_LIST}"
    done < <(modprobe -C /dev/null -S "${KVER}" --show-depends "${mod}" 2>/dev/null || true)
done
echo "[install] Bundled $(wc -l < "${MOD_LIST}") kernel module(s) into /lib/modules/serenity."

echo "[install] Copying Intel Wi-Fi & GPU firmware into /lib/firmware..."
if [ -d /lib/firmware/i915 ]; then
    cp -a /lib/firmware/i915 "${MNT}/lib/firmware/"
fi
if [ -d /lib/firmware/intel/iwlwifi ]; then
    mkdir -p "${MNT}/lib/firmware/intel"
    cp -a /lib/firmware/intel/iwlwifi "${MNT}/lib/firmware/intel/"
fi
# Intel Smart Sound Technology (SOF) firmware & topologies for bare-metal laptop audio
for sof_dir in /lib/firmware/intel/sof*; do
    if [ -d "${sof_dir}" ]; then
        mkdir -p "${MNT}/lib/firmware/intel"
        cp -a "${sof_dir}" "${MNT}/lib/firmware/intel/"
    fi
done
cp -a /lib/firmware/iwlwifi* "${MNT}/lib/firmware/" 2>/dev/null || true
cp -a /lib/firmware/regulatory.db* "${MNT}/lib/firmware/" 2>/dev/null || true
fi

# Ensure root ownership and setuid bit on /init so non-root UID 1000 can invoke poweroff/reboot/cosmic-osd
chown -R 0:0 "${MNT}"
chmod 4755 "${MNT}/init"
chown -R 1000:1000 "${MNT}/home/serenity" 2>/dev/null || true
sync

# Without an initrd the kernel can only resolve root=PARTUUID=, not root=UUID=.
if [ "${USE_INITRD}" -eq 0 ] && [ -n "${PARTUUID}" ]; then
    ROOT_ARG="root=PARTUUID=${PARTUUID} rootwait"
else
    ROOT_ARG="root=UUID=${UUID}"
fi

GRUB_ENTRY=$(cat <<EOF
menuentry "Serenity Linux 0.1.0 (Rust + Nushell)" {
    insmod part_gpt
    insmod ext2
    search --no-floppy --fs-uuid --set=root ${UUID}
    linux /boot/vmlinuz-serenity ${ROOT_ARG} rw init=/init
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
