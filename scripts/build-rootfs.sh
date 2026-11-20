#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
STAGE_DIR="${BUILD_DIR}/rootfs-stage"
INIT_BIN="${ROOT_DIR}/target/x86_64-unknown-linux-musl/release/init"
SPKG_BIN="${ROOT_DIR}/target/x86_64-unknown-linux-musl/release/spkg"
NU_BIN="${BUILD_DIR}/userland/bin/nu"
COREUTILS_BIN="${BUILD_DIR}/userland/bin/coreutils"
OUT_INITRAMFS="${BUILD_DIR}/initramfs.cpio.gz"
OUT_DISK="${BUILD_DIR}/disk.img"
DISK_SIZE_MB="${DISK_SIZE_MB:-256}"
MODE="${1:-all}"

for bin in "${INIT_BIN}" "${SPKG_BIN}" "${NU_BIN}" "${COREUTILS_BIN}"; do
    if [ ! -x "${bin}" ]; then
        echo "[rootfs] ERROR: Missing ${bin}. Run 'make init spkg nushell coreutils' first."
        exit 1
    fi
done

rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}"/{bin,usr/bin,usr/local/bin,usr/share/applications,usr/share/icons/hicolor/scalable/apps,sbin,etc,proc,sys,dev,tmp,run,root,home/serenity,var/db/spkg}

# Copy static overlay files (includes /etc/os-release, /etc/hosts, /etc/resolv.conf,
# TLS CA certs, Fontconfig, D-Bus session.conf, GLVND 50_mesa.json, XKB, locale, and DejaVu fonts)
cp -a "${ROOT_DIR}/rootfs/overlay/." "${STAGE_DIR}/"

# Install PID 1 + poweroff/reboot/cosmic-osd/start-desktop multicall symlinks
# Note: keep 0755 during rootless staging so mke2fs -d (owned by UID 1000) never
# creates a setuid-1000 /init! Use -E root_owner=0:0 and setuid via debugfs/chmod.
install -m 0755 "${INIT_BIN}" "${STAGE_DIR}/init"
ln -sf /init "${STAGE_DIR}/sbin/poweroff"
ln -sf /init "${STAGE_DIR}/sbin/reboot"
ln -sf /init "${STAGE_DIR}/sbin/halt"
ln -sf /init "${STAGE_DIR}/usr/bin/poweroff"
ln -sf /init "${STAGE_DIR}/usr/bin/reboot"
ln -sf /init "${STAGE_DIR}/usr/bin/suspend"
ln -sf /init "${STAGE_DIR}/usr/bin/cosmic-osd"
ln -sf /init "${STAGE_DIR}/usr/bin/start-desktop"

# Install Nushell, spkg & uutils/coreutils
install -m 0755 "${NU_BIN}" "${STAGE_DIR}/bin/nu"
install -m 0755 "${SPKG_BIN}" "${STAGE_DIR}/usr/bin/spkg"
install -m 0755 "${COREUTILS_BIN}" "${STAGE_DIR}/bin/coreutils"

# Generate symlinks for all uutils/coreutils applets
applet_count=0
for applet in $("${COREUTILS_BIN}" --list); do
    case "${applet}" in
        "["|"nu"|"init"|"coreutils") continue ;;
    esac
    ln -sf coreutils "${STAGE_DIR}/bin/${applet}"
    applet_count=$((applet_count + 1))
done
echo "[rootfs] Staged /init, /bin/nu, and ${applet_count} uutils/coreutils applets."

if [ "${MODE}" = "initramfs" ] || [ "${MODE}" = "all" ]; then
    (
        cd "${STAGE_DIR}"
        find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > "${OUT_INITRAMFS}"
    )
    echo "[rootfs] Built initramfs: ${OUT_INITRAMFS} ($(du -h "${OUT_INITRAMFS}" | cut -f1))"
fi

if [ "${MODE}" = "disk" ] || [ "${MODE}" = "all" ]; then
    rm -f "${OUT_DISK}"
    truncate -s "${DISK_SIZE_MB}M" "${OUT_DISK}"
    /usr/sbin/mke2fs -q -t ext4 -d "${STAGE_DIR}" -L SERENITY -F "${OUT_DISK}"
    printf 'sif init uid 0\nsif init gid 0\nsif init mode 0104755\n' | /usr/sbin/debugfs -w "${OUT_DISK}" >/dev/null 2>&1
    echo "[rootfs] Built persistent ext4 disk: ${OUT_DISK} (${DISK_SIZE_MB}M)"
fi
