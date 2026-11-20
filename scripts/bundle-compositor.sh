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
SHELL_BIN="${ROOT_DIR}/target/release/serenity-shell"
TARGET_ROOT="${1:-${ROOT_DIR}/build/rootfs-stage}"

if [ ! -x "${COMP_BIN}" ]; then
    echo "[bundle-compositor] ERROR: Missing ${COMP_BIN}."
    echo "Build it first: cargo build --release -p serenity-compositor -p serenity-shell"
    exit 1
fi

echo "[bundle-compositor] Installing serenity-compositor into ${TARGET_ROOT}..."
mkdir -p "${TARGET_ROOT}/usr/bin"
install -m 0755 "${COMP_BIN}" "${TARGET_ROOT}/usr/bin/serenity-compositor"
if [ -x "${SHELL_BIN}" ]; then
    echo "[bundle-compositor] Installing serenity-shell into ${TARGET_ROOT}..."
    install -m 0755 "${SHELL_BIN}" "${TARGET_ROOT}/usr/bin/serenity-shell"
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
copy_lib_and_deps "${COMP_BIN}"
if [ -x "${SHELL_BIN}" ]; then
    copy_lib_and_deps "${SHELL_BIN}"
fi

# Also bundle EGL/GLES2/GBM/Mesa DRI drivers dynamically loaded via dlopen()
for libdir in /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu; do
    [ -d "${libdir}" ] || continue
    for pat in "libEGL*.so*" "libGLESv2*.so*" "libGLdispatch*.so*" "libgbm*.so*" "libgallium*.so*" "libLLVM*.so*"; do
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
    # Mesa DRI drivers (Intel iris + QEMU virtio_gpu + libdril)
    if [ -d "${libdir}/dri" ]; then
        mkdir -p "${TARGET_ROOT}${libdir}/dri"
        for drv in iris_dri.so virtio_gpu_dri.so libdril_dri.so; do
            f="${libdir}/dri/${drv}"
            [ -e "$f" ] || continue
            cp -an "$f" "${TARGET_ROOT}${libdir}/dri/" 2>/dev/null || true
            [ -f "$f" ] && copy_lib_and_deps "$f"
        done
    fi
done

# Bundle GLVND EGL vendor config (50_mesa.json) so libEGL discovers libEGL_mesa.so.0
if [ -d /usr/share/glvnd/egl_vendor.d ]; then
    mkdir -p "${TARGET_ROOT}/usr/share/glvnd"
    cp -a /usr/share/glvnd/egl_vendor.d "${TARGET_ROOT}/usr/share/glvnd/"
fi

# Ensure /lib64 dynamic linker exists
if [ -e /lib64/ld-linux-x86-64.so.2 ]; then
    mkdir -p "${TARGET_ROOT}/lib64"
    cp -nL /lib64/ld-linux-x86-64.so.2 "${TARGET_ROOT}/lib64/"
fi

# Bundle XKB keymaps (dereferencing /usr/share/X11/xkb -> ../xkeyboard-config-2) & locale
if [ -d /usr/share/X11/xkb ]; then
    mkdir -p "${TARGET_ROOT}/usr/share/X11"
    rm -rf "${TARGET_ROOT}/usr/share/X11/xkb"
    cp -aL /usr/share/X11/xkb "${TARGET_ROOT}/usr/share/X11/xkb"
fi
if [ -d /usr/share/X11/locale ]; then
    mkdir -p "${TARGET_ROOT}/usr/share/X11"
    cp -aL /usr/share/X11/locale "${TARGET_ROOT}/usr/share/X11/locale"
fi

# Bundle DejaVu fallback fonts so all Wayland GUI apps render crisp text
if [ -d /usr/share/fonts/truetype/dejavu ]; then
    mkdir -p "${TARGET_ROOT}/usr/share/fonts/truetype"
    cp -aL /usr/share/fonts/truetype/dejavu "${TARGET_ROOT}/usr/share/fonts/truetype/"
fi

echo "[bundle-compositor] Done! Inside Serenity, run 'start-desktop' to launch Smithay as UID 1000."
