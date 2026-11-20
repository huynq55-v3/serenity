#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
DL_DIR="${BUILD_DIR}/downloads"
USERLAND_BIN="${BUILD_DIR}/userland/bin"
NU_VERSION="${NU_VERSION:-0.104.0}"
NU_ARCH="x86_64-unknown-linux-musl"
TARBALL="nu-${NU_VERSION}-${NU_ARCH}.tar.gz"
URL="https://github.com/nushell/nushell/releases/download/${NU_VERSION}/${TARBALL}"

mkdir -p "${DL_DIR}" "${USERLAND_BIN}"

if [ -x "${USERLAND_BIN}/nu" ]; then
    echo "[nushell] Already present: ${USERLAND_BIN}/nu"
    exit 0
fi

if [ ! -f "${DL_DIR}/${TARBALL}" ]; then
    echo "[nushell] Downloading Nushell ${NU_VERSION} (${NU_ARCH})..."
    curl -fL --progress-bar "${URL}" -o "${DL_DIR}/${TARBALL}.tmp"
    mv "${DL_DIR}/${TARBALL}.tmp" "${DL_DIR}/${TARBALL}"
fi

echo "[nushell] Extracting nu binary..."
TMP_EXTRACT="$(mktemp -d)"
trap 'rm -rf "${TMP_EXTRACT}"' EXIT
tar -xzf "${DL_DIR}/${TARBALL}" -C "${TMP_EXTRACT}"
NU_BIN="$(find "${TMP_EXTRACT}" -maxdepth 2 -type f -name nu | head -n1)"
if [ -z "${NU_BIN}" ]; then
    echo "[nushell] ERROR: Could not find 'nu' binary inside ${TARBALL}"
    exit 1
fi

install -m 0755 "${NU_BIN}" "${USERLAND_BIN}/nu"
echo "[nushell] Ready: ${USERLAND_BIN}/nu ($(du -h "${USERLAND_BIN}/nu" | cut -f1))"
