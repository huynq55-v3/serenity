#!/usr/bin/env python3
"""Serenity Linux Package Factory.

Reads packages/*/recipe.toml, builds/repacks static x86_64-musl binaries into
native Serenity `.tar.zst` archives, computes SHA-256 checksums, and emits
`index.json` ready for GitHub Releases + `spkg`.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.request
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
PACKAGES_DIR = ROOT_DIR / "packages"
OUT_DIR = ROOT_DIR / "build" / "packages"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path) -> None:
    print(f"  -> Downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "serenity-pkg-factory/0.1"})
    with urllib.request.urlopen(req) as resp, dest.open("wb") as out:
        shutil.copyfileobj(resp, out)


def stage_prebuilt(recipe: dict, stage_dir: Path, work_dir: Path) -> None:
    src = recipe["source"]
    url = src["url"]
    expected_sha = src.get("sha256", "").strip().lower()
    archive_path = work_dir / Path(url).name
    download(url, archive_path)

    if expected_sha:
        actual = sha256_file(archive_path)
        if actual != expected_sha:
            raise RuntimeError(
                f"Source SHA-256 mismatch for {url}:\n  expected: {expected_sha}\n  actual  : {actual}"
            )

    extract_dir = work_dir / "extracted"
    extract_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r:*") as tf:
        tf.extractall(extract_dir, filter="data")

    file_map: dict[str, str] = recipe["install"]["files"]
    installed = 0
    for root, _, files in os.walk(extract_dir):
        for fname in files:
            if fname in file_map:
                src_file = Path(root) / fname
                dst_rel = file_map[fname].lstrip("/")
                dst_file = stage_dir / dst_rel
                dst_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_file, dst_file)
                os.chmod(dst_file, 0o755)
                installed += 1

    if installed != len(file_map):
        raise RuntimeError(
            f"Expected {len(file_map)} file(s) from {url}, found {installed}"
        )


def stage_cargo(recipe: dict, stage_dir: Path, work_dir: Path) -> None:
    src = recipe["source"]
    repo_url = src["git"]
    rev = src.get("rev") or src.get("tag")
    src_dir = work_dir / "src"

    cmd = ["git", "clone", "--depth", "1"]
    if rev:
        cmd += ["--branch", rev]
    cmd += [repo_url, str(src_dir)]
    subprocess.run(cmd, check=True)

    env = os.environ.copy()
    env.setdefault("CC_x86_64_unknown_linux_musl", "clang")
    build_cmd = ["cargo", "build", "--release", "--target", "x86_64-unknown-linux-musl"]
    if src.get("features"):
        build_cmd += ["--features", ",".join(src["features"])]
    subprocess.run(build_cmd, cwd=src_dir, env=env, check=True)

    target_dir = src_dir / "target" / "x86_64-unknown-linux-musl" / "release"
    for bin_name, dst_rel in recipe["install"]["files"].items():
        bin_path = target_dir / bin_name
        if not bin_path.is_file():
            raise RuntimeError(f"Built binary not found: {bin_path}")
        dst_file = stage_dir / dst_rel.lstrip("/")
        dst_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(bin_path, dst_file)
        os.chmod(dst_file, 0o755)


def pack_tar_zst(stage_dir: Path, out_file: Path) -> None:
    tar_tmp = out_file.with_suffix("")  # .tar
    subprocess.run(
        ["tar", "--sort=name", "--owner=0", "--group=0", "--numeric-owner", "-cf", str(tar_tmp), "-C", str(stage_dir), "."],
        check=True,
    )
    subprocess.run(["zstd", "-19", "--force", "--rm", str(tar_tmp), "-o", str(out_file)], check=True)


def build_recipe(recipe_path: Path, out_dir: Path, base_url: str) -> tuple[str, dict]:
    with recipe_path.open("rb") as f:
        recipe = tomllib.load(f)

    pkg = recipe["package"]
    name = pkg["name"]
    version = pkg["version"]
    arch = pkg.get("arch", "x86_64-musl")
    archive_name = f"{name}-{version}-{arch}.tar.zst"
    out_file = out_dir / archive_name

    print(f"[factory] Building {name} {version} ({arch})...")
    with tempfile.TemporaryDirectory(prefix=f"spkg-{name}-") as tmp:
        work_dir = Path(tmp)
        stage_dir = work_dir / "stage"
        stage_dir.mkdir()

        src_type = recipe["source"]["type"]
        if src_type == "prebuilt":
            stage_prebuilt(recipe, stage_dir, work_dir)
        elif src_type == "cargo":
            stage_cargo(recipe, stage_dir, work_dir)
        else:
            raise RuntimeError(f"Unsupported source type: {src_type}")

        pack_tar_zst(stage_dir, out_file)

    checksum = sha256_file(out_file)
    size_kib = out_file.stat().st_size // 1024
    print(f"[factory] Packed {archive_name} ({size_kib} KiB, sha256={checksum[:12]}...)")

    meta = {
        "version": version,
        "arch": arch,
        "description": pkg.get("description", ""),
        "url": f"{base_url.rstrip('/')}/{archive_name}",
        "sha256": checksum,
        "deps": pkg.get("deps", []),
    }
    return name, meta


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Serenity .tar.zst packages and index.json")
    parser.add_argument(
        "--base-url",
        default=f"file://{OUT_DIR}",
        help="Base URL where built .tar.zst files will be hosted (e.g. GitHub Releases download URL)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=OUT_DIR,
        help="Output directory for .tar.zst files and index.json",
    )
    parser.add_argument(
        "packages",
        nargs="*",
        help="Optional specific package names to build (default: all in packages/)",
    )
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    if args.packages:
        recipes = [PACKAGES_DIR / p / "recipe.toml" for p in args.packages]
    else:
        recipes = sorted(PACKAGES_DIR.glob("*/recipe.toml"))

    if not recipes:
        print("[factory] No recipe.toml files found in packages/", file=sys.stderr)
        return 1

    index = {"version": 1, "packages": {}}
    for recipe_path in recipes:
        if not recipe_path.is_file():
            print(f"[factory] Recipe not found: {recipe_path}", file=sys.stderr)
            return 1
        name, meta = build_recipe(recipe_path, args.out_dir, args.base_url)
        index["packages"][name] = meta

    index_path = args.out_dir / "index.json"
    index_path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    print(f"[factory] Generated {index_path} ({len(index['packages'])} package(s)).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
