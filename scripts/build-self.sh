#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
DL_DIR="${BUILD_DIR}/downloads"
TOOLCHAIN_DIR="${BUILD_DIR}/toolchain"
STAGE_DIR="${BUILD_DIR}/rootfs-stage"
USERLAND_BIN="${BUILD_DIR}/userland/bin"
MUSL_TARGET="x86_64-unknown-linux-musl"
ZIG_VERSION="${ZIG_VERSION:-0.14.1}"

SKIP_PACKAGES=0
NO_INSTALL=0

usage() {
    cat <<'EOF'
Usage: scripts/build-self.sh [OPTIONS]

Build Serenity Linux directly inside Serenity (equivalent to 'make disk-gui')
and install updated system binaries, overlay configs, DNS, and packages into /.

Options:
  --skip-packages  Skip 'spkg update' and remote package installs/upgrades
  --no-install     Build and stage into build/rootfs-stage without modifying /
  -h, --help       Show this help message
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --skip-packages) SKIP_PACKAGES=1 ;;
        --no-install)    NO_INSTALL=1 ;;
        -h|--help)       usage; exit 0 ;;
        *)
            echo "[self-build] ERROR: Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

atomic_install() {
    local mode="$1"
    local src="$2"
    local dst="$3"
    as_root mkdir -p "$(dirname "${dst}")"
    as_root install -o 0 -g 0 -m "${mode}" "${src}" "${dst}.serenity-new"
    as_root mv -f "${dst}.serenity-new" "${dst}"
}

ensure_nm_dns_none() {
    local src="$1"
    local dst="$2"
    if grep -q '^dns=' "${src}"; then
        sed 's/^dns=.*/dns=none/' "${src}" > "${dst}"
    elif grep -q '^\[main\]$' "${src}"; then
        awk '{print} /^\[main\]$/ && !done {print "dns=none"; done=1}' "${src}" > "${dst}"
    else
        cp "${src}" "${dst}"
        printf '\n[main]\ndns=none\n' >> "${dst}"
    fi
}

write_dns_files_stage() {
    local stage="$1"
    mkdir -p "${stage}/etc" "${stage}/etc/NetworkManager"
    printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > "${stage}/etc/resolv.conf"
    chmod 0644 "${stage}/etc/resolv.conf"

    local nm_conf="${stage}/etc/NetworkManager/NetworkManager.conf"
    if [ -f "${nm_conf}" ]; then
        ensure_nm_dns_none "${nm_conf}" "${nm_conf}.tmp"
        mv -f "${nm_conf}.tmp" "${nm_conf}"
        chmod 0644 "${nm_conf}"
    fi
}

write_dns_files_live() {
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > "${tmp_dir}/resolv.conf"
    atomic_install 0644 "${tmp_dir}/resolv.conf" /etc/resolv.conf

    local nm_dst="/etc/NetworkManager/NetworkManager.conf"
    local nm_overlay="${ROOT_DIR}/rootfs/overlay/etc/NetworkManager/NetworkManager.conf"
    if [ -f "${nm_dst}" ]; then
        ensure_nm_dns_none "${nm_dst}" "${tmp_dir}/NetworkManager.conf"
        atomic_install 0644 "${tmp_dir}/NetworkManager.conf" "${nm_dst}"
    elif [ -f "${nm_overlay}" ]; then
        ensure_nm_dns_none "${nm_overlay}" "${tmp_dir}/NetworkManager.conf"
        atomic_install 0644 "${tmp_dir}/NetworkManager.conf" "${nm_dst}"
    fi
    rm -rf "${tmp_dir}"
}

write_wireplumber_config_live() {
    local wp_src="${ROOT_DIR}/rootfs/overlay/etc/wireplumber/bluetooth.lua.d/51-disable-logind.lua"
    local wp_dst="/etc/wireplumber/bluetooth.lua.d/51-disable-logind.lua"
    if [ -f "${wp_src}" ]; then
        atomic_install 0644 "${wp_src}" "${wp_dst}"
    fi
}

fix_glibc_linker_scripts() {
    local libdir="/usr/lib/x86_64-linux-gnu"
    local tmp_dir
    tmp_dir="$(mktemp -d)"

    local expected_libc_group="GROUP ( /usr/lib/x86_64-linux-gnu/libc.so.6 /usr/lib/x86_64-linux-gnu/libc_nonshared.a AS_NEEDED ( /lib64/ld-linux-x86-64.so.2 ) )"
    if [ -f "${libdir}/libc.so" ] && ! grep -Fqx "${expected_libc_group}" "${libdir}/libc.so"; then
        echo "[self-build] Writing canonical GNU ld script at ${libdir}/libc.so..."
        cat > "${tmp_dir}/libc.so" <<EOF
/* GNU ld script */
OUTPUT_FORMAT(elf64-x86-64)
${expected_libc_group}
EOF
        atomic_install 0644 "${tmp_dir}/libc.so" "${libdir}/libc.so"
    fi

    if [ -f "${libdir}/libm.so" ]; then
        local expected_libm_group
        if [ -e "${libdir}/libmvec.so.1" ]; then
            expected_libm_group="GROUP ( /usr/lib/x86_64-linux-gnu/libm.so.6 AS_NEEDED ( /usr/lib/x86_64-linux-gnu/libmvec.so.1 ) )"
        else
            expected_libm_group="GROUP ( /usr/lib/x86_64-linux-gnu/libm.so.6 )"
        fi
        if ! grep -Fqx "${expected_libm_group}" "${libdir}/libm.so"; then
            echo "[self-build] Writing canonical GNU ld script at ${libdir}/libm.so..."
            cat > "${tmp_dir}/libm.so" <<EOF
/* GNU ld script */
OUTPUT_FORMAT(elf64-x86-64)
${expected_libm_group}
EOF
            atomic_install 0644 "${tmp_dir}/libm.so" "${libdir}/libm.so"
        fi
    fi

    rm -rf "${tmp_dir}"
}

fix_clang_resource_headers() {
    command -v clang >/dev/null 2>&1 || return 0
    local clang_res clang_major src_inc
    clang_res="$(clang -print-resource-dir 2>/dev/null || true)"
    [ -n "${clang_res}" ] || return 0
    if [ -f "${clang_res}/include/immintrin.h" ]; then
        return 0
    fi
    clang_major="$(basename "${clang_res}")"
    for src_inc in \
        "/usr/lib/llvm-${clang_major}/lib/clang/${clang_major}/include" \
        "/usr/include/clang/${clang_major}/include"; do
        if [ -f "${src_inc}/immintrin.h" ]; then
            echo "[self-build] Linking Clang resource headers into ${clang_res}/include..."
            as_root mkdir -p "${clang_res}"
            as_root ln -sfn "${src_inc}" "${clang_res}/include"
            return 0
        fi
    done
}

check_host_tools() {
    local missing=()
    for cmd in cargo rustc curl tar xz gzip install cp ln mv awk sed grep find mktemp; do
        command -v "${cmd}" >/dev/null 2>&1 || missing+=("${cmd}")
    done
    if [ "${NO_INSTALL}" -eq 0 ] && [ "$(id -u)" -ne 0 ] && ! command -v sudo >/dev/null 2>&1; then
        missing+=("sudo")
    fi
    if [ "${#missing[@]}" -gt 0 ]; then
        echo "[self-build] ERROR: Missing required command(s): ${missing[*]}" >&2
        exit 1
    fi
}

ensure_musl_toolchain() {
    mkdir -p "${DL_DIR}" "${TOOLCHAIN_DIR}"

    if [ "${SKIP_PACKAGES}" -eq 0 ] && [ "${NO_INSTALL}" -eq 0 ] && [ -x /usr/bin/spkg ]; then
        if [ ! -d "/usr/lib/rustlib/${MUSL_TARGET}/lib" ] || [ ! -x /usr/bin/musl-cc ]; then
            echo "[self-build] Checking spkg for updated 'rust' package with musl support..."
            as_root /usr/bin/spkg update || true
            if [ -f /var/db/spkg/installed/rust.json ]; then
                as_root /usr/bin/spkg install rust || true
            fi
        fi
    fi

    if [ "${NO_INSTALL}" -eq 0 ]; then
        fix_glibc_linker_scripts
        fix_clang_resource_headers
    fi

    if [ ! -d "/usr/lib/rustlib/${MUSL_TARGET}/lib" ]; then
        local rust_ver std_tar std_url tmp_std std_src
        rust_ver="$(rustc --version | awk '{print $2}')"
        std_tar="rust-std-${rust_ver}-${MUSL_TARGET}.tar.xz"
        std_url="https://static.rust-lang.org/dist/${std_tar}"
        if [ ! -f "${DL_DIR}/${std_tar}" ]; then
            echo "[self-build] Downloading ${std_tar}..."
            curl -fL --progress-bar "${std_url}" -o "${DL_DIR}/${std_tar}.tmp"
            mv -f "${DL_DIR}/${std_tar}.tmp" "${DL_DIR}/${std_tar}"
        fi
        tmp_std="$(mktemp -d)"
        tar -xJf "${DL_DIR}/${std_tar}" -C "${tmp_std}"
        std_src="$(find "${tmp_std}" -maxdepth 5 -type d -path "*/lib/rustlib/${MUSL_TARGET}" | head -n 1)"
        if [ -z "${std_src}" ] || [ ! -d "${std_src}/lib" ]; then
            rm -rf "${tmp_std}"
            echo "[self-build] ERROR: Could not locate ${MUSL_TARGET} stdlib inside ${std_tar}" >&2
            exit 1
        fi
        if [ "${NO_INSTALL}" -eq 0 ]; then
            echo "[self-build] Installing ${MUSL_TARGET} target into /usr/lib/rustlib..."
            as_root mkdir -p /usr/lib/rustlib
            as_root cp -rP --preserve=mode,timestamps --no-preserve=ownership "${std_src}" /usr/lib/rustlib/
        else
            local local_sysroot="${TOOLCHAIN_DIR}/sysroot"
            local host_triple
            host_triple="$(rustc -vV | awk '/^host:/ {print $2}')"
            mkdir -p "${local_sysroot}/lib/rustlib"
            rm -rf "${local_sysroot}/lib/rustlib/${MUSL_TARGET}"
            cp -a "${std_src}" "${local_sysroot}/lib/rustlib/"
            if [ -n "${host_triple}" ] && [ -d "/usr/lib/rustlib/${host_triple}" ]; then
                ln -sfn "/usr/lib/rustlib/${host_triple}" "${local_sysroot}/lib/rustlib/${host_triple}"
            fi
            export RUSTFLAGS="--sysroot=${local_sysroot} ${RUSTFLAGS:-}"
        fi
        rm -rf "${tmp_std}"
    fi

    if [ -x /usr/bin/musl-cc ] && [ -x /usr/bin/llvm-ar ]; then
        export CC_x86_64_unknown_linux_musl="/usr/bin/musl-cc"
        export AR_x86_64_unknown_linux_musl="/usr/bin/llvm-ar"
    elif command -v x86_64-linux-musl-gcc >/dev/null 2>&1 && command -v x86_64-linux-musl-ar >/dev/null 2>&1; then
        export CC_x86_64_unknown_linux_musl="$(command -v x86_64-linux-musl-gcc)"
        export AR_x86_64_unknown_linux_musl="$(command -v x86_64-linux-musl-ar)"
    else
        local zig_dir="${TOOLCHAIN_DIR}/zig-x86_64-linux-${ZIG_VERSION}"
        local zig_bin="${zig_dir}/zig"
        if [ ! -x "${zig_bin}" ]; then
            local zig_tar="zig-x86_64-linux-${ZIG_VERSION}.tar.xz"
            local zig_url="https://ziglang.org/download/${ZIG_VERSION}/${zig_tar}"
            if [ ! -f "${DL_DIR}/${zig_tar}" ]; then
                echo "[self-build] Downloading Zig ${ZIG_VERSION} (for musl C/ASM build of spkg)..."
                curl -fL --progress-bar "${zig_url}" -o "${DL_DIR}/${zig_tar}.tmp"
                mv -f "${DL_DIR}/${zig_tar}.tmp" "${DL_DIR}/${zig_tar}"
            fi
            echo "[self-build] Extracting Zig ${ZIG_VERSION} into ${TOOLCHAIN_DIR}..."
            tar -xJf "${DL_DIR}/${zig_tar}" -C "${TOOLCHAIN_DIR}"
        fi
        if [ ! -x "${zig_bin}" ]; then
            echo "[self-build] ERROR: Zig binary not found at ${zig_bin}" >&2
            exit 1
        fi
        cat > "${TOOLCHAIN_DIR}/zig-musl-cc" <<EOF
#!/bin/sh
exec "${zig_bin}" cc -target x86_64-linux-musl -fno-sanitize=undefined "\$@"
EOF
        cat > "${TOOLCHAIN_DIR}/zig-ar" <<EOF
#!/bin/sh
exec "${zig_bin}" ar "\$@"
EOF
        chmod 0755 "${TOOLCHAIN_DIR}/zig-musl-cc" "${TOOLCHAIN_DIR}/zig-ar"
        export CC_x86_64_unknown_linux_musl="${TOOLCHAIN_DIR}/zig-musl-cc"
        export AR_x86_64_unknown_linux_musl="${TOOLCHAIN_DIR}/zig-ar"
        export ZIG_GLOBAL_CACHE_DIR="${TOOLCHAIN_DIR}/zig-cache"
        export ZIG_LOCAL_CACHE_DIR="${TOOLCHAIN_DIR}/zig-local-cache"
        mkdir -p "${ZIG_GLOBAL_CACHE_DIR}" "${ZIG_LOCAL_CACHE_DIR}"
    fi
}

stage_rootfs() {
    local init_bin="${ROOT_DIR}/target/${MUSL_TARGET}/release/init"
    local spkg_bin="${ROOT_DIR}/target/${MUSL_TARGET}/release/spkg"
    local guard_bin="${ROOT_DIR}/target/${MUSL_TARGET}/release/serenity-guard"
    local nu_bin="${USERLAND_BIN}/nu"
    local coreutils_bin="${USERLAND_BIN}/coreutils"

    for bin in "${init_bin}" "${spkg_bin}" "${guard_bin}" "${nu_bin}" "${coreutils_bin}"; do
        if [ ! -x "${bin}" ]; then
            echo "[self-build] ERROR: Missing built binary: ${bin}" >&2
            exit 1
        fi
    done

    rm -rf "${STAGE_DIR}"
    mkdir -p "${STAGE_DIR}"/{bin,usr/bin,usr/local/bin,usr/share/applications,usr/share/icons/hicolor/scalable/apps,sbin,etc,proc,sys,dev,tmp,run,root,home/serenity,var/db/spkg}

    cp -a "${ROOT_DIR}/rootfs/overlay/." "${STAGE_DIR}/"
    write_dns_files_stage "${STAGE_DIR}"

    install -m 0755 "${init_bin}" "${STAGE_DIR}/init"
    ln -sf /init "${STAGE_DIR}/sbin/poweroff"
    ln -sf /init "${STAGE_DIR}/sbin/reboot"
    ln -sf /init "${STAGE_DIR}/sbin/halt"
    ln -sf /init "${STAGE_DIR}/usr/bin/poweroff"
    ln -sf /init "${STAGE_DIR}/usr/bin/reboot"
    ln -sf /init "${STAGE_DIR}/usr/bin/suspend"
    ln -sf /init "${STAGE_DIR}/usr/bin/sudo"
    ln -sf /init "${STAGE_DIR}/usr/bin/passwd"
    ln -sf /init "${STAGE_DIR}/usr/bin/serenity-fw"
    ln -sf /init "${STAGE_DIR}/usr/bin/cosmic-osd"
    ln -sf /init "${STAGE_DIR}/usr/bin/start-desktop"

    install -m 0755 "${nu_bin}" "${STAGE_DIR}/bin/nu"
    install -m 0755 "${spkg_bin}" "${STAGE_DIR}/usr/bin/spkg"
    install -m 0755 "${guard_bin}" "${STAGE_DIR}/usr/bin/serenity-guard"
    install -m 0755 "${coreutils_bin}" "${STAGE_DIR}/bin/coreutils"

    local applet_count=0
    for applet in $("${coreutils_bin}" --list); do
        case "${applet}" in
            "["|"nu"|"init"|"coreutils") continue ;;
        esac
        ln -sf coreutils "${STAGE_DIR}/bin/${applet}"
        applet_count=$((applet_count + 1))
    done
    ln -sf /bin/env "${STAGE_DIR}/usr/bin/env"
    echo "[self-build] Staged /init, /bin/nu, /usr/bin/spkg, and ${applet_count} coreutils applets into ${STAGE_DIR}."
}

install_staged_to_root() {
    local init_bin="${STAGE_DIR}/init"
    local spkg_bin="${STAGE_DIR}/usr/bin/spkg"
    local guard_bin="${STAGE_DIR}/usr/bin/serenity-guard"
    local nu_bin="${STAGE_DIR}/bin/nu"
    local coreutils_bin="${STAGE_DIR}/bin/coreutils"

    echo "[self-build] Installing static musl binaries atomically into /..."
    atomic_install 04755 "${init_bin}" /init
    atomic_install 0755 "${spkg_bin}" /usr/bin/spkg
    atomic_install 0755 "${guard_bin}" /usr/bin/serenity-guard
    atomic_install 0755 "${nu_bin}" /bin/nu
    atomic_install 0755 "${coreutils_bin}" /bin/coreutils

    as_root mkdir -p /sbin /usr/bin /bin
    as_root ln -sfn /init /sbin/poweroff
    as_root ln -sfn /init /sbin/reboot
    as_root ln -sfn /init /sbin/halt
    as_root ln -sfn /init /usr/bin/poweroff
    as_root ln -sfn /init /usr/bin/reboot
    as_root ln -sfn /init /usr/bin/suspend
    as_root ln -sfn /init /usr/bin/sudo
    as_root ln -sfn /init /usr/bin/passwd
    as_root ln -sfn /init /usr/bin/serenity-fw
    as_root ln -sfn /init /usr/bin/cosmic-osd
    as_root ln -sfn /init /usr/bin/start-desktop

    for applet in $("${coreutils_bin}" --list); do
        case "${applet}" in
            "["|"nu"|"init"|"coreutils") continue ;;
        esac
        as_root ln -sfn coreutils "/bin/${applet}"
    done
    as_root ln -sfn /bin/env /usr/bin/env

    echo "[self-build] Syncing system overlay configs into /etc and /usr/share..."
    for item in "${STAGE_DIR}/etc/"*; do
        [ -e "${item}" ] || continue
        local base
        base="$(basename "${item}")"
        if { [ "${base}" = "passwd" ] || [ "${base}" = "group" ] || [ "${base}" = "shadow" ]; } && [ -e "/etc/${base}" ]; then
            continue
        fi
        as_root cp -rP --preserve=mode,timestamps --no-preserve=ownership "${item}" /etc/
    done
    as_root mkdir -p /usr/share
    as_root cp -rP --preserve=mode,timestamps --no-preserve=ownership "${STAGE_DIR}/usr/share/." /usr/share/

    write_dns_files_live
    write_wireplumber_config_live
}

install_remote_packages() {
    local fav_file="/usr/share/cosmic/com.system76.CosmicAppList/v1/favorites"
    local fav_backup=""
    if [ -f "${fav_file}" ]; then
        fav_backup="$(mktemp)"
        cp "${fav_file}" "${fav_backup}"
    fi

    echo "[self-build] Updating spkg package index..."
    as_root /usr/bin/spkg update

    echo "[self-build] Installing/updating disk-gui package set..."
    as_root /usr/bin/spkg install serenity-base alacritty cosmic-desktop
    as_root /usr/bin/spkg install cosmic-settings cosmic-randr pop-launcher || \
        echo "[self-build] WARN: optional COSMIC packages (cosmic-settings/cosmic-randr/pop-launcher) not available yet"
    as_root /usr/bin/spkg install kmod linux linux-firmware || \
        echo "[self-build] WARN: kmod/linux/linux-firmware not available yet"

    local disk_gui_pkgs="serenity-base alacritty cosmic-desktop cosmic-settings cosmic-randr pop-launcher kmod linux linux-firmware"
    if [ -d /var/db/spkg/installed ]; then
        local extra_pkgs=()
        for meta in /var/db/spkg/installed/*.json; do
            [ -f "${meta}" ] || continue
            local pkg
            pkg="$(basename "${meta}" .json)"
            case " ${disk_gui_pkgs} " in
                *" ${pkg} "*) continue ;;
            esac
            extra_pkgs+=("${pkg}")
        done
        if [ "${#extra_pkgs[@]}" -gt 0 ]; then
            local sorted_extra=()
            local pkg_line
            while IFS= read -r pkg_line; do
                [ -n "${pkg_line}" ] && sorted_extra+=("${pkg_line}")
            done <<EOF
$(printf '%s\n' "${extra_pkgs[@]}" | sort -u)
EOF
            echo "[self-build] Checking updates for additional installed package(s): ${sorted_extra[*]}"
            for pkg in "${sorted_extra[@]}"; do
                as_root /usr/bin/spkg install "${pkg}" || \
                    echo "[self-build] WARN: failed to upgrade ${pkg}"
            done
        fi
    fi

    if [ -n "${fav_backup}" ]; then
        atomic_install 0644 "${fav_backup}" "${fav_file}"
        rm -f "${fav_backup}"
    fi

    if [ -x /usr/bin/cosmic-applets ]; then
        for applet in \
            cosmic-app-list \
            cosmic-applet-audio \
            cosmic-applet-battery \
            cosmic-applet-time \
            cosmic-applet-power \
            cosmic-applet-network \
            cosmic-applet-notifications \
            cosmic-applet-minimize \
            cosmic-panel-button; do
            as_root ln -sfn cosmic-applets "/usr/bin/${applet}"
        done
    fi

    if [ -e /boot/vmlinuz-serenity ]; then
        as_root mkdir -p /etc/serenity
        local mod_tmp
        mod_tmp="$(mktemp)"
        : > "${mod_tmp}"
        atomic_install 0644 "${mod_tmp}" /etc/serenity/modules.load
        rm -f "${mod_tmp}"
    fi

    fix_glibc_linker_scripts
    fix_clang_resource_headers
}

main() {
    cd "${ROOT_DIR}"
    check_host_tools

    if [ "${NO_INSTALL}" -eq 0 ]; then
        echo "[self-build] Configuring DNS (1.1.1.1, 8.8.8.8) in /etc/resolv.conf..."
        write_dns_files_live
    fi

    ensure_musl_toolchain

    echo "[self-build] Building serenity-init (${MUSL_TARGET})..."
    cargo build --release --target "${MUSL_TARGET}" -p serenity-init

    echo "[self-build] Building spkg (${MUSL_TARGET})..."
    cargo build --release --target "${MUSL_TARGET}" -p spkg

    echo "[self-build] Building serenity-guard (${MUSL_TARGET})..."
    cargo build --release --target "${MUSL_TARGET}" -p serenity-guard

    echo "[self-build] Fetching static musl userland tools (nu, coreutils)..."
    bash "${ROOT_DIR}/scripts/fetch-nushell.sh"
    bash "${ROOT_DIR}/scripts/fetch-coreutils.sh"

    stage_rootfs

    if [ "${NO_INSTALL}" -eq 1 ]; then
        echo "[self-build] --no-install set; staging complete at ${STAGE_DIR}."
        exit 0
    fi

    install_staged_to_root

    if [ "${SKIP_PACKAGES}" -eq 0 ]; then
        install_remote_packages
    else
        echo "[self-build] --skip-packages set; skipped remote package updates."
    fi

    # Re-apply DNS & WirePlumber config in case an installed package touched /etc
    write_dns_files_live
    write_wireplumber_config_live
    if [ -x /usr/bin/serenity-guard ]; then
        as_root /usr/bin/serenity-guard stop >/dev/null 2>&1 || true
        as_root /usr/bin/serenity-guard start || true
    fi
    as_root sync

    echo ""
    echo "[self-build] Done! System binaries, overlay configs, DNS (1.1.1.1 / 8.8.8.8), and packages updated in /."
    echo "[self-build] Run 'reboot' to boot with the newly built /init and updated packages."
}

main "$@"
