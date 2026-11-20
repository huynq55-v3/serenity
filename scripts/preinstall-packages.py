#!/usr/bin/env python3
"""Pre-install spkg packages (e.g. alacritty, cosmic-desktop) directly into a rootfs staging dir.

Downloads index.json + .tar.zst archives from GitHub Releases (with local cache in
build/pkg-cache/), verifies SHA-256 checksums, extracts into <target_dir>, and records
them in <target_dir>/var/db/spkg/installed.json so 'spkg list' inside Serenity sees them.
"""
import hashlib
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

INDEX_URL = "https://github.com/huynq55-v3/serenity/releases/download/pkgs-v1/index.json"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "serenity-preinstall/0.1"})
    with urllib.request.urlopen(req, timeout=60) as resp, tmp.open("wb") as out:
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            out.write(chunk)
    tmp.replace(dest)


def resolve_order(index: dict, requested: list[str]) -> list[str]:
    order: list[str] = []
    visiting: set[str] = set()
    visited: set[str] = set()

    def dfs(name: str) -> None:
        if name in visited:
            return
        if name in visiting:
            raise RuntimeError(f"Dependency cycle involving {name}")
        if name not in index:
            raise KeyError(f"Package '{name}' not found in index.json")
        visiting.add(name)
        for dep in index[name].get("deps", []):
            dfs(dep)
        visiting.remove(name)
        visited.add(name)
        order.append(name)

    for pkg in requested:
        dfs(pkg)
    return order


def main() -> int:
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <rootfs_dir> <pkg1> [pkg2 ...]", file=sys.stderr)
        return 1

    rootfs = Path(sys.argv[1]).resolve()
    requested = sys.argv[2:]
    repo_root = Path(__file__).resolve().parent.parent
    cache_dir = repo_root / "build" / "pkg-cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    index_path = cache_dir / "index.json"
    print(f"[preinstall] Fetching package index from {INDEX_URL}...")
    download(INDEX_URL, index_path)
    raw_index = json.loads(index_path.read_text(encoding="utf-8"))
    packages = raw_index["packages"]

    order = resolve_order(packages, requested)
    print(f"[preinstall] Resolving {len(order)} package(s): {', '.join(order)}")

    db_dir = rootfs / "var" / "db" / "spkg"
    db_dir.mkdir(parents=True, exist_ok=True)
    # Also save cached index.json into rootfs so 'spkg search' works offline immediately
    (db_dir / "index.json").write_text(index_path.read_text(encoding="utf-8"), encoding="utf-8")

    installed_path = db_dir / "installed.json"
    if installed_path.exists():
        installed = json.loads(installed_path.read_text(encoding="utf-8"))
    else:
        installed = {"packages": {}}

    for name in order:
        entry = packages[name]
        url = entry["url"]
        filename = entry.get("filename") or url.rsplit("/", 1)[-1]
        expected_sha = entry["sha256"]
        archive = cache_dir / filename

        if archive.exists() and sha256_file(archive) == expected_sha:
            print(f"[preinstall] Using cached {filename}")
        else:
            print(f"[preinstall] Downloading {filename}...")
            download(url, archive)
            actual_sha = sha256_file(archive)
            if actual_sha != expected_sha:
                archive.unlink(missing_ok=True)
                raise RuntimeError(f"SHA-256 mismatch for {filename}: {actual_sha} != {expected_sha}")

        # List files in archive and extract into rootfs
        list_proc = subprocess.run(
            ["tar", "--zstd", "-tf", str(archive)],
            check=True,
            capture_output=True,
            text=True,
        )
        files = []
        for line in list_proc.stdout.splitlines():
            p = line.strip().lstrip("./")
            if p and not p.endswith("/"):
                files.append("/" + p)

        # Keep Serenity's curated favorites file (Alacritty + CosmicSettings) intact
        fav_path = rootfs / "usr/share/cosmic/com.system76.CosmicAppList/v1/favorites"
        saved_fav = fav_path.read_text(encoding="utf-8") if fav_path.exists() else None

        subprocess.run(
            ["tar", "--zstd", "-xf", str(archive), "-C", str(rootfs)],
            check=True,
        )

        if saved_fav is not None:
            fav_path.write_text(saved_fav, encoding="utf-8")

        installed["packages"][name] = {
            "version": entry["version"],
            "arch": entry["arch"],
            "sha256": expected_sha,
            "files": files,
        }
        print(f"[preinstall] Installed {name} {entry['version']} ({len(files)} file(s))")

    # Create cosmic-applets multicall symlinks ahead of time
    usr_bin = rootfs / "usr" / "bin"
    if (usr_bin / "cosmic-applets").exists():
        for applet in [
            "cosmic-app-list",
            "cosmic-applet-battery",
            "cosmic-applet-time",
            "cosmic-applet-power",
            "cosmic-applet-network",
            "cosmic-applet-notifications",
            "cosmic-applet-minimize",
            "cosmic-panel-button",
        ]:
            link = usr_bin / applet
            if not link.exists() and not link.is_symlink():
                link.symlink_to("cosmic-applets")

    installed_path.write_text(json.dumps(installed, indent=2) + "\n", encoding="utf-8")
    print(f"[preinstall] Done! Pre-installed {len(order)} package(s) into {rootfs}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
