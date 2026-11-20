#!/usr/bin/env python3
"""Serenity Linux Package Factory.

Reads packages/*/recipe.toml, builds/repacks binaries + XDG desktop entries & icons
into native Serenity `.tar.zst` archives, computes SHA-256 checksums, and emits
`index.json` ready for GitHub Releases + `spkg`.

Supported source types:
  - prebuilt  : downloads an upstream musl tarball and repacks selected files
  - cargo     : clones a Rust repo and builds static x86_64-unknown-linux-musl
  - cargo-gnu : clones a Rust GUI/Wayland repo (e.g. COSMIC, Alacritty) and builds native x86_64-gnu
  - meta      : dependency-only / config-only meta-package (e.g. cosmic-desktop)
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
    req = urllib.request.Request(url, headers={"User-Agent": "serenity-pkg-factory/0.2"})
    with urllib.request.urlopen(req) as resp, dest.open("wb") as out:
        shutil.copyfileobj(resp, out)


def install_assets_and_inline(recipe: dict, src_dir: Path | None, stage_dir: Path) -> None:
    install_cfg = recipe.get("install", {})

    # Copy extra assets from source repo (e.g. .desktop files, SVG icons, configs)
    if src_dir is not None:
        for rel_src, dst_rel in install_cfg.get("assets", {}).items():
            src_path = src_dir / rel_src
            dst_path = stage_dir / dst_rel.lstrip("/")
            if src_path.is_dir():
                dst_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(src_path, dst_path, dirs_exist_ok=True)
            elif src_path.is_file():
                dst_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_path, dst_path)
            else:
                print(f"  -> WARN: optional asset not found in repo: {rel_src}")

    # Write inline text files declared in [install.inline] (e.g. default COSMIC Dock favorites)
    for dst_rel, content in install_cfg.get("inline", {}).items():
        dst_path = stage_dir / dst_rel.lstrip("/")
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        dst_path.write_text(content, encoding="utf-8")


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

    file_map: dict[str, str] = recipe.get("install", {}).get("files", {})
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

    install_assets_and_inline(recipe, extract_dir, stage_dir)


def stage_cargo(recipe: dict, stage_dir: Path, work_dir: Path, musl: bool) -> None:
    src = recipe["source"]
    repo_url = src["git"]
    rev = src.get("rev") or src.get("tag") or src.get("branch")
    src_dir = work_dir / "src"

    cmd = ["git", "clone", "--depth", "1"]
    if rev:
        cmd += ["--branch", rev]
    cmd += [repo_url, str(src_dir)]
    subprocess.run(cmd, check=True)

    env = os.environ.copy()
    if musl:
        env.setdefault("CC_x86_64_unknown_linux_musl", "clang")

    # Allow custom build command (e.g. `just build-release`) or standard cargo build
    custom_build = src.get("build_cmd")
    if custom_build:
        subprocess.run(custom_build, shell=True, cwd=src_dir, env=env, check=True)
        target_dir = src_dir / "target" / "release"
    else:
        build_cmd = ["cargo", "build", "--release"]
        if musl:
            build_cmd += ["--target", "x86_64-unknown-linux-musl"]
        if src.get("package"):
            build_cmd += ["-p", src["package"]]
        if src.get("features"):
            build_cmd += ["--features", ",".join(src["features"])]
        subprocess.run(build_cmd, cwd=src_dir, env=env, check=True)
        target_dir = (
            src_dir / "target" / "x86_64-unknown-linux-musl" / "release"
            if musl
            else src_dir / "target" / "release"
        )

    for bin_name, dst_rel in recipe.get("install", {}).get("files", {}).items():
        bin_path = target_dir / bin_name
        if not bin_path.is_file():
            raise RuntimeError(f"Built binary not found: {bin_path}")
        dst_file = stage_dir / dst_rel.lstrip("/")
        dst_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(bin_path, dst_file)
        os.chmod(dst_file, 0o755)

    install_assets_and_inline(recipe, src_dir, stage_dir)


def pack_tar_zst(stage_dir: Path, out_file: Path) -> None:
    tar_tmp = out_file.with_suffix("")  # .tar
    subprocess.run(
        [
            "tar",
            "--sort=name",
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "-cf",
            str(tar_tmp),
            "-C",
            str(stage_dir),
            ".",
        ],
        check=True,
    )
    subprocess.run(
        ["zstd", "-19", "--force", "--rm", str(tar_tmp), "-o", str(out_file)],
        check=True,
    )


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
            stage_cargo(recipe, stage_dir, work_dir, musl=True)
        elif src_type == "cargo-gnu":
            stage_cargo(recipe, stage_dir, work_dir, musl=False)
        elif src_type == "meta":
            install_assets_and_inline(recipe, None, stage_dir)
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


def merge_meta_files(meta_dir: Path, out_index: Path, base_index: Path | None = None) -> None:
    index = {"version": 1, "packages": {}}
    if base_index is not None and base_index.is_file():
        try:
            existing = json.loads(base_index.read_text(encoding="utf-8"))
            if isinstance(existing.get("packages"), dict):
                index["packages"].update(existing["packages"])
                print(
                    f"[factory] Loaded {len(index['packages'])} existing package(s) from {base_index}."
                )
        except Exception as e:
            print(f"[factory] WARN: Could not read base index {base_index}: {e}")

    updated = 0
    for meta_file in sorted(meta_dir.glob("*.meta.json")):
        data = json.loads(meta_file.read_text(encoding="utf-8"))
        index["packages"][data["name"]] = data["meta"]
        updated += 1
    out_index.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    print(
        f"[factory] Merged {updated} updated package(s) -> {out_index} (total: {len(index['packages'])})."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Serenity .tar.zst packages and index.json")
    parser.add_argument(
        "--base-url",
        default=f"file://{OUT_DIR}",
        help="Base URL where built .tar.zst files will be hosted (e.g. GitHub Releases URL)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=OUT_DIR,
        help="Output directory for .tar.zst files and index.json",
    )
    parser.add_argument(
        "--write-meta",
        action="store_true",
        help="Write per-package <name>.meta.json files (for parallel CI matrix merge)",
    )
    parser.add_argument(
        "--merge-meta-dir",
        type=Path,
        default=None,
        help="Merge all *.meta.json in this directory into <out-dir>/index.json and exit",
    )
    parser.add_argument(
        "--base-index",
        type=Path,
        default=None,
        help="Optional existing index.json to preserve previously published packages when merging",
    )
    parser.add_argument(
        "packages",
        nargs="*",
        help="Optional specific package names to build (default: all in packages/)",
    )
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    if args.merge_meta_dir is not None:
        merge_meta_files(args.merge_meta_dir, args.out_dir / "index.json", args.base_index)
        return 0

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
        if args.write_meta:
            meta_out = args.out_dir / f"{name}.meta.json"
            meta_out.write_text(
                json.dumps({"name": name, "meta": meta}, indent=2) + "\n",
                encoding="utf-8",
            )

    if not args.write_meta:
        index_path = args.out_dir / "index.json"
        index_path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
        print(f"[factory] Generated {index_path} ({len(index['packages'])} package(s)).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
