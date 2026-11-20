#!/usr/bin/env bash
set -euo pipefail

# Bundles `serenity-compositor` + its required shared libraries, Mesa EGL/DRI drivers,
# and XKB keymaps into a target Serenity rootfs mountpoint (or build/rootfs-stage).
#
# Usage:
#   cargo build --release -p serenity-compositor
#   sudo ./scripts/bundle-compositor.sh /mnt/serenity

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMP_BIN="${ROOT_DIR}/target/release/serenity-compositor"
LOGIN_BIN="${ROOT_DIR}/target/release/serenity-login"
SHELL_BIN="${ROOT_DIR}/target/release/serenity-shell"
ALACRITTY_BIN=""
if [ -x "${ROOT_DIR}/build/userland/bin/alacritty" ]; then
    ALACRITTY_BIN="${ROOT_DIR}/build/userland/bin/alacritty"
elif command -v alacritty >/dev/null 2>&1; then
    ALACRITTY_BIN="$(command -v alacritty)"
fi
TARGET_ROOT="${1:-${ROOT_DIR}/build/rootfs-stage}"

if [ ! -x "${COMP_BIN}" ]; then
    echo "[bundle-compositor] ERROR: Missing ${COMP_BIN}."
    echo "Build it first: cargo build --release -p serenity-compositor -p serenity-shell"
    exit 1
fi

echo "[bundle-compositor] Installing desktop binaries into ${TARGET_ROOT}/usr/bin..."
mkdir -p "${TARGET_ROOT}/usr/bin"
install -m 0755 "${COMP_BIN}" "${TARGET_ROOT}/usr/bin/serenity-compositor"
[ -x "${LOGIN_BIN}" ] && install -m 0755 "${LOGIN_BIN}" "${TARGET_ROOT}/usr/bin/serenity-login"
[ -x "${SHELL_BIN}" ] && install -m 0755 "${SHELL_BIN}" "${TARGET_ROOT}/usr/bin/serenity-shell"
if [ -n "${ALACRITTY_BIN}" ] && [ -x "${ALACRITTY_BIN}" ]; then
    echo "[bundle-compositor] Bundling Alacritty terminal (${ALACRITTY_BIN})..."
    install -m 0755 "${ALACRITTY_BIN}" "${TARGET_ROOT}/usr/bin/alacritty"
else
    echo "[bundle-compositor] WARN: 'alacritty' not installed on host. Run: sudo apt install -y alacritty"
fi

copy_lib_and_deps() {
    local bin="$1"
    ldd "${bin}" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ /^\//) print $i}' | sort -u | while read -r lib; do
        [ -f "${lib}" ] || continue
        local dest="${TARGET_ROOT}${lib}"
        mkdir -p "$(dirname "${dest}")"
        cp -nL "${lib}" "${dest}" 2>/dev/null || true
    done
}

echo "[bundle-compositor] Copying shared libraries via ldd..."
for b in "${COMP_BIN}" "${LOGIN_BIN}" "${SHELL_BIN}" "${ALACRITTY_BIN}"; do
    [ -n "${b}" ] && [ -x "${b}" ] && copy_lib_and_deps "${b}"
done

# Also bundle EGL/GLES2/GBM/Mesa DRI + COSMIC/Alacritty runtime shared libraries
for libdir in /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu; do
    [ -d "${libdir}" ] || continue
    for pat in \
        "libEGL*.so*" "libGLESv2*.so*" "libGLdispatch*.so*" "libgbm*.so*" "libgallium*.so*" "libLLVM*.so*" \
        "libwayland-*.so*" "libxkb*.so*" \
        "libdisplay-info*.so*" "libseat*.so*" "libpixman-1*.so*" "libdav1d*.so*" \
        "libfontconfig*.so*" "libfreetype*.so*" "libsystemd*.so*" \
        "libpipewire-0.3*.so*" "libpulse*.so*"; do
        for f in ${libdir}/${pat}; do
            [ -e "$f" ] || continue
            mkdir -p "${TARGET_ROOT}${libdir}"
            cp -an "$f" "${TARGET_ROOT}${libdir}/" 2>/dev/null || true
            [ -f "$f" ] && copy_lib_and_deps "$f"
        done
    done
    # Mesa 25+ GBM backend (dri_gbm.so)
    if [ -d "${libdir}/gbm" ]; then
        mkdir -p "${TARGET_ROOT}${libdir}/gbm"
        for f in "${libdir}/gbm/"*.so*; do
            [ -e "$f" ] || continue
            cp -an "$f" "${TARGET_ROOT}${libdir}/gbm/" 2>/dev/null || true
            [ -f "$f" ] && copy_lib_and_deps "$f"
        done
    fi
    # Mesa DRI drivers (copy libdril_dri.so + all *_dri.so symlinks including swrast_dri.so, kms_swrast_dri.so, iris_dri.so, virtio_gpu_dri.so)
    if [ -d "${libdir}/dri" ]; then
        mkdir -p "${TARGET_ROOT}${libdir}/dri"
        for f in "${libdir}/dri/"*_dri.so*; do
            [ -e "$f" ] || continue
            cp -a "$f" "${TARGET_ROOT}${libdir}/dri/" 2>/dev/null || true
        done
        [ -f "${libdir}/dri/libdril_dri.so" ] && copy_lib_and_deps "${libdir}/dri/libdril_dri.so"
    fi
done

# Ensure /lib64 dynamic linker exists
if [ -e /lib64/ld-linux-x86-64.so.2 ]; then
    mkdir -p "${TARGET_ROOT}/lib64"
    cp -nL /lib64/ld-linux-x86-64.so.2 "${TARGET_ROOT}/lib64/"
fi

# Bundle D-Bus daemon, seatd, NetworkManager, wpa_supplicant, nmcli, cosmic-settings & cosmic-randr
for sys_bin in \
    /usr/bin/dbus-daemon /usr/bin/dbus-run-session \
    /usr/sbin/seatd /usr/bin/seatd \
    /usr/sbin/NetworkManager /usr/sbin/wpa_supplicant /usr/bin/nmcli \
    /usr/bin/cosmic-settings /usr/bin/cosmic-randr; do
    if [ -x "${sys_bin}" ]; then
        install -m 0755 "${sys_bin}" "${TARGET_ROOT}/usr/bin/$(basename "${sys_bin}")"
        copy_lib_and_deps "${sys_bin}"
    fi
done

# Bundle NetworkManager Wi-Fi device plugin so NetworkManager can scan & connect wlan0
for nm_ver_dir in /usr/lib/x86_64-linux-gnu/NetworkManager/*; do
    if [ -d "${nm_ver_dir}" ] && [ -f "${nm_ver_dir}/libnm-device-plugin-wifi.so" ]; then
        mkdir -p "${TARGET_ROOT}${nm_ver_dir}"
        cp -nL "${nm_ver_dir}/libnm-device-plugin-wifi.so" "${TARGET_ROOT}${nm_ver_dir}/" 2>/dev/null || true
        copy_lib_and_deps "${nm_ver_dir}/libnm-device-plugin-wifi.so"
    fi
done

# Bundle serenity-sysd (Rust System D-Bus daemon for login1 SetBrightness/PowerOff + UPower)
SYSD_BIN="${ROOT_DIR}/target/x86_64-unknown-linux-musl/release/serenity-sysd"
if [ -x "${SYSD_BIN}" ]; then
    install -m 0755 "${SYSD_BIN}" "${TARGET_ROOT}/usr/bin/serenity-sysd"
fi

echo "[bundle-compositor] Done! Inside Serenity, run 'start-desktop' to launch Desktop as UID 1000."
