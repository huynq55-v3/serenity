#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
DL_DIR="${BUILD_DIR}/downloads"
USERLAND_BIN="${BUILD_DIR}/userland/bin"
COREUTILS_VERSION="${COREUTILS_VERSION:-0.12.0}"
ARCH="x86_64-unknown-linux-musl"
TARBALL="coreutils-${COREUTILS_VERSION}-${ARCH}.tar.gz"
URL="https://github.com/uutils/coreutils/releases/download/${COREUTILS_VERSION}/${TARBALL}"

mkdir -p "${DL_DIR}" "${USERLAND_BIN}"

if [ -x "${USERLAND_BIN}/coreutils" ]; then
    echo "[coreutils] Already present: ${USERLAND_BIN}/coreutils"
    exit 0
fi

if [ ! -f "${DL_DIR}/${TARBALL}" ]; then
    echo "[coreutils] Downloading uutils/coreutils ${COREUTILS_VERSION} (${ARCH})..."
    curl -fL --progress-bar "${URL}" -o "${DL_DIR}/${TARBALL}.tmp"
    mv "${DL_DIR}/${TARBALL}.tmp" "${DL_DIR}/${TARBALL}"
fi

echo "[coreutils] Extracting coreutils multicall binary..."
TMP_EXTRACT="$(mktemp -d)"
trap 'rm -rf "${TMP_EXTRACT}"' EXIT
tar -xzf "${DL_DIR}/${TARBALL}" -C "${TMP_EXTRACT}"
BIN="$(find "${TMP_EXTRACT}" -maxdepth 2 -type f -name coreutils | head -n1)"
if [ -z "${BIN}" ]; then
    echo "[coreutils] ERROR: Could not find 'coreutils' binary inside ${TARBALL}"
    exit 1
fi

install -m 0755 "${BIN}" "${USERLAND_BIN}/coreutils"
echo "[coreutils] Ready: ${USERLAND_BIN}/coreutils ($(du -h "${USERLAND_BIN}/coreutils" | cut -f1))"
