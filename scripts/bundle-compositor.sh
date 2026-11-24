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
        # Normalize /lib/x86_64-linux-gnu/* into /usr/lib/x86_64-linux-gnu/* so SONAMEs
        # (like libcap.so.2, libcap-ng.so.0, libc.so.6) always live in one canonical dir.
        local canon="${lib}"
        case "${lib}" in
            /lib/x86_64-linux-gnu/*) canon="/usr${lib}" ;;
        esac
        local dest="${TARGET_ROOT}${canon}"
        mkdir -p "$(dirname "${dest}")"
        cp -nL "${lib}" "${dest}" 2>/dev/null || true
    done
}

echo "[bundle-compositor] Copying shared libraries via ldd..."
for b in "${COMP_BIN}" "${LOGIN_BIN}" "${SHELL_BIN}" "${ALACRITTY_BIN}"; do
    [ -n "${b}" ] && [ -x "${b}" ] && copy_lib_and_deps "${b}"
done

# Also bundle EGL/GLES2/GBM/Mesa DRI + COSMIC/Alacritty runtime shared libraries
# Use only /usr/lib/x86_64-linux-gnu (on usr-merged Ubuntu /lib is a symlink to /usr/lib,
# looping both duplicates everything and bloats the archive).
libdir="/usr/lib/x86_64-linux-gnu"
if [ -d "${libdir}" ]; then
    for pat in \
        "libdl.so*" "libpthread.so*" "librt.so*" "libutil.so*" "libcrypt.so*" "libmvec.so*" "libresolv.so*" "libnss_files.so*" "libnss_dns.so*" \
        "libcap.so*" "libcap-ng.so*" \
        "libEGL*.so*" "libGLESv2*.so*" "libGL.so*" "libGLX*.so*" "libGLdispatch*.so*" "libgbm*.so*" "libgallium*.so*" \
        "libxcb-glx*.so*" "libXxf86vm*.so*" \
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
        for dri_real in "${libdir}/dri/libdril_dri.so" "${libdir}/dri/swrast_dri.so" "${libdir}/dri/iris_dri.so"; do
            [ -f "${dri_real}" ] && copy_lib_and_deps "${dri_real}"
        done
    fi
    # Vulkan loader + Intel/Lavapipe/VirtIO ICD drivers (required by Zed IDE GPUI & modern Vulkan apps)
    for vk in libvulkan.so.1 libvulkan_intel.so libvulkan_lvp.so libvulkan_virtio.so; do
        if [ -e "${libdir}/${vk}" ]; then
            mkdir -p "${TARGET_ROOT}${libdir}"
            cp -an "${libdir}/${vk}"* "${TARGET_ROOT}${libdir}/" 2>/dev/null || true
            [ -f "${libdir}/${vk}" ] && copy_lib_and_deps "${libdir}/${vk}"
        fi
    done
fi

if [ -d /usr/share/vulkan/icd.d ]; then
    mkdir -p "${TARGET_ROOT}/usr/share/vulkan/icd.d"
    for icd in intel_icd.json lvp_icd.json virtio_icd.json; do
        [ -f "/usr/share/vulkan/icd.d/${icd}" ] && cp -a "/usr/share/vulkan/icd.d/${icd}" "${TARGET_ROOT}/usr/share/vulkan/icd.d/"
    done
fi

# Ensure /lib64 dynamic linker exists
if [ -e /lib64/ld-linux-x86-64.so.2 ]; then
    mkdir -p "${TARGET_ROOT}/lib64"
    cp -nL /lib64/ld-linux-x86-64.so.2 "${TARGET_ROOT}/lib64/"
fi

# Bundle POSIX /bin/sh (dash, 127 KiB, only libc) so COSMIC panel buttons,
# pop-launcher, Cargo build scripts, and desktop apps calling `sh -c ...` work cleanly
if [ -x /usr/bin/dash ]; then
    mkdir -p "${TARGET_ROOT}/bin"
    install -m 0755 /usr/bin/dash "${TARGET_ROOT}/bin/sh"
    ln -sf /bin/sh "${TARGET_ROOT}/usr/bin/sh"
fi

# Bundle GNU Bash (/bin/bash + /usr/bin/bash) for IDEs (Antigravity, VS Code),
# build scripts, and developer tools that invoke `bash`
BASH_BIN="$(command -v bash || true)"
if [ -n "${BASH_BIN}" ] && [ -x "${BASH_BIN}" ]; then
    mkdir -p "${TARGET_ROOT}/bin" "${TARGET_ROOT}/usr/bin"
    install -m 0755 "${BASH_BIN}" "${TARGET_ROOT}/bin/bash"
    ln -sf /bin/bash "${TARGET_ROOT}/usr/bin/bash"
    copy_lib_and_deps "${BASH_BIN}"
fi

# Bundle D-Bus daemon, seatd, NetworkManager, wpa_supplicant, nmcli, cosmic-settings, cosmic-randr & pop-launcher
for sys_bin in \
    /usr/bin/dbus-daemon /usr/bin/dbus-run-session \
    /usr/sbin/seatd /usr/bin/seatd \
    /usr/sbin/NetworkManager /usr/sbin/wpa_supplicant /usr/bin/nmcli \
    /usr/bin/cosmic-settings /usr/bin/cosmic-randr /usr/bin/pop-launcher; do
    if [ -x "${sys_bin}" ]; then
        install -m 0755 "${sys_bin}" "${TARGET_ROOT}/usr/bin/$(basename "${sys_bin}")"
        copy_lib_and_deps "${sys_bin}"
    fi
done

# Bundle pop-launcher plugins (/usr/lib/pop-launcher) so cosmic-launcher & cosmic-app-library
# can search and launch desktop apps, files, and calculator
if [ -d /usr/lib/pop-launcher ]; then
    mkdir -p "${TARGET_ROOT}/usr/lib/pop-launcher"
    cp -a /usr/lib/pop-launcher/. "${TARGET_ROOT}/usr/lib/pop-launcher/" 2>/dev/null || true
fi

# Bundle NetworkManager Wi-Fi device plugin so NetworkManager can scan & connect wlan0
for nm_ver_dir in /usr/lib/x86_64-linux-gnu/NetworkManager/*; do
    if [ -d "${nm_ver_dir}" ] && [ -f "${nm_ver_dir}/libnm-device-plugin-wifi.so" ]; then
        mkdir -p "${TARGET_ROOT}${nm_ver_dir}"
        cp -nL "${nm_ver_dir}/libnm-device-plugin-wifi.so" "${TARGET_ROOT}${nm_ver_dir}/" 2>/dev/null || true
        copy_lib_and_deps "${nm_ver_dir}/libnm-device-plugin-wifi.so"
    fi
done

# Bundle netplan generate/configure C helpers + a tiny POSIX sh wrapper at /usr/sbin/netplan
# and /usr/bin/netplan (Ubuntu 24.04's NetworkManager 1.46 invokes `netplan generate` via PATH,
# whereas Ubuntu 26.04 invokes /usr/libexec/netplan/configure directly).
if [ -d /usr/libexec/netplan ]; then
    mkdir -p "${TARGET_ROOT}/usr/libexec/netplan" "${TARGET_ROOT}/usr/sbin" "${TARGET_ROOT}/usr/bin"
    for np_bin in /usr/libexec/netplan/generate /usr/libexec/netplan/configure; do
        if [ -x "${np_bin}" ]; then
            install -m 0755 "${np_bin}" "${TARGET_ROOT}${np_bin}"
            copy_lib_and_deps "${np_bin}"
        fi
    done
    if [ -x "${TARGET_ROOT}/usr/libexec/netplan/generate" ]; then
        cat > "${TARGET_ROOT}/usr/sbin/netplan" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "generate" ]; then
    shift
    exec /usr/libexec/netplan/generate "$@"
fi
exit 0
EOF
        chmod 0755 "${TARGET_ROOT}/usr/sbin/netplan"
        ln -sf /usr/sbin/netplan "${TARGET_ROOT}/usr/bin/netplan"
    fi
fi

# Bundle OpenSSL provider modules (legacy.so) for WPA/EAP crypto in wpa_supplicant
if [ -d /usr/lib/x86_64-linux-gnu/ossl-modules ]; then
    mkdir -p "${TARGET_ROOT}/usr/lib/x86_64-linux-gnu/ossl-modules"
    cp -a /usr/lib/x86_64-linux-gnu/ossl-modules/. "${TARGET_ROOT}/usr/lib/x86_64-linux-gnu/ossl-modules/" 2>/dev/null || true
fi

# Bundle IANA timezone database (/usr/share/zoneinfo) for timedate1 & COSMIC Settings
if [ -d /usr/share/zoneinfo ]; then
    mkdir -p "${TARGET_ROOT}/usr/share"
    cp -a /usr/share/zoneinfo "${TARGET_ROOT}/usr/share/" 2>/dev/null || true
fi

# Bundle compiled UTF-8 glibc locales + gconv modules so Chromium/Electron/GTK/Steam/coreutils
# never fall back to 7-bit ASCII "C" locale (which causes SIGTRAP on non-ASCII drag-and-drop).
for loc in C.utf8 en_US.utf8 vi_VN.utf8; do
    if [ -d "/usr/lib/locale/${loc}" ]; then
        mkdir -p "${TARGET_ROOT}/usr/lib/locale"
        cp -a "/usr/lib/locale/${loc}" "${TARGET_ROOT}/usr/lib/locale/"
    fi
done
for loc_bin in /usr/bin/locale /usr/bin/localedef; do
    if [ -x "${loc_bin}" ]; then
        install -m 0755 "${loc_bin}" "${TARGET_ROOT}/usr/bin/$(basename "${loc_bin}")"
        copy_lib_and_deps "${loc_bin}"
    fi
done
if [ -d /usr/lib/x86_64-linux-gnu/gconv ]; then
    mkdir -p "${TARGET_ROOT}/usr/lib/x86_64-linux-gnu"
    cp -a /usr/lib/x86_64-linux-gnu/gconv "${TARGET_ROOT}/usr/lib/x86_64-linux-gnu/"
fi

# Bundle serenity-sysd (Rust System D-Bus daemon for login1 SetBrightness/PowerOff + UPower)
SYSD_BIN="${ROOT_DIR}/target/x86_64-unknown-linux-musl/release/serenity-sysd"
if [ -x "${SYSD_BIN}" ]; then
    install -m 0755 "${SYSD_BIN}" "${TARGET_ROOT}/usr/bin/serenity-sysd"
fi

echo "[bundle-compositor] Done! Inside Serenity, run 'start-desktop' to launch Desktop as UID 1000."
