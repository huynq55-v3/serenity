#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
DL_DIR="${BUILD_DIR}/downloads"
KERNEL_VERSION="${KERNEL_VERSION:-6.12.28}"
KERNEL_MAJOR="${KERNEL_VERSION%%.*}"
TARBALL="linux-${KERNEL_VERSION}.tar.xz"
TARBALL_URL="https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_MAJOR}.x/${TARBALL}"
SRC_DIR="${BUILD_DIR}/linux-${KERNEL_VERSION}"
FRAGMENT="${ROOT_DIR}/kernel/config/serenity_x86_64.fragment"
OUT_IMAGE="${BUILD_DIR}/bzImage"

# Check required host build dependencies before downloading.
missing=()
for cmd in gcc make flex bison bc xz tar; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
done
if ! dpkg -s libelf-dev >/dev/null 2>&1 && [ ! -f /usr/include/gelf.h ]; then
    missing+=("libelf-dev")
fi
if [ "${#missing[@]}" -gt 0 ]; then
    echo "[kernel] ERROR: Missing host dependencies: ${missing[*]}"
    echo "[kernel] Run: sudo apt update && sudo apt install -y flex bison libelf-dev libssl-dev bc"
    exit 1
fi

mkdir -p "${DL_DIR}"

if [ ! -f "${DL_DIR}/${TARBALL}" ]; then
    echo "[kernel] Downloading Linux ${KERNEL_VERSION}..."
    curl -fL --progress-bar "${TARBALL_URL}" -o "${DL_DIR}/${TARBALL}.tmp"
    mv "${DL_DIR}/${TARBALL}.tmp" "${DL_DIR}/${TARBALL}"
fi

if [ ! -d "${SRC_DIR}" ]; then
    echo "[kernel] Extracting ${TARBALL}..."
    tar -xf "${DL_DIR}/${TARBALL}" -C "${BUILD_DIR}"
fi

echo "[kernel] Configuring Linux ${KERNEL_VERSION} (x86_64_defconfig + serenity fragment)..."
make -C "${SRC_DIR}" ARCH=x86_64 x86_64_defconfig
(
    cd "${SRC_DIR}"
    ARCH=x86_64 ./scripts/kconfig/merge_config.sh -m .config "${FRAGMENT}"
    make ARCH=x86_64 olddefconfig
)

JOBS="$(nproc)"
echo "[kernel] Compiling bzImage with ${JOBS} jobs..."
make -C "${SRC_DIR}" ARCH=x86_64 -j"${JOBS}" bzImage

cp "${SRC_DIR}/arch/x86/boot/bzImage" "${OUT_IMAGE}"
echo "[kernel] Built: ${OUT_IMAGE} ($(du -h "${OUT_IMAGE}" | cut -f1))"
