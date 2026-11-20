#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
STAGE_DIR="${BUILD_DIR}/initramfs-stage"
INIT_BIN="${ROOT_DIR}/target/x86_64-unknown-linux-musl/release/init"
NU_BIN="${BUILD_DIR}/userland/bin/nu"
OUT_INITRAMFS="${BUILD_DIR}/initramfs.cpio.gz"

if [ ! -x "${INIT_BIN}" ]; then
    echo "[initramfs] ERROR: Missing ${INIT_BIN}. Run 'make init' first."
    exit 1
fi

if [ ! -x "${NU_BIN}" ]; then
    echo "[initramfs] ERROR: Missing ${NU_BIN}. Run 'make nushell' first."
    exit 1
fi

rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}"/{bin,usr/bin,sbin,etc,proc,sys,dev,tmp,run,root,var/db/spkg}

# Copy static overlay files
cp -a "${ROOT_DIR}/rootfs/overlay/." "${STAGE_DIR}/"

# Install PID 1 and Nushell
install -m 0755 "${INIT_BIN}" "${STAGE_DIR}/init"
install -m 0755 "${NU_BIN}" "${STAGE_DIR}/bin/nu"

# Pack initramfs (newc cpio + gzip)
(
    cd "${STAGE_DIR}"
    find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > "${OUT_INITRAMFS}"
)

echo "[initramfs] Built: ${OUT_INITRAMFS} ($(du -h "${OUT_INITRAMFS}" | cut -f1))"
