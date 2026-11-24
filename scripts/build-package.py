#!/usr/bin/env python3
"""Serenity Linux Package Factory.

Reads packages/*/recipe.toml, builds/repacks binaries + XDG desktop entries & icons
into native Serenity `.tar.zst` archives, computes SHA-256 checksums, and emits
`index.json` ready for GitHub Releases + `spkg`.

Supported source types:
  - prebuilt  : downloads an upstream musl tarball and repacks selected files
  - cargo     : clones a Rust repo and builds static x86_64-unknown-linux-musl
  - cargo-gnu : clones a Rust GUI/Wayland repo (e.g. COSMIC, Alacritty) and builds native x86_64-gnu
  - deb       : downloads an upstream .deb package, extracts data.tar.*, and repacks into .tar.zst
  - syslibs   : collects common C/C++ shared libraries from the build host (e.g. clibrary for Chrome)
  - custom    : runs a custom staging shell script declared in [source] script = "..."
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
        if dst_path.is_symlink():
            dst_path.unlink()
        dst_path.write_text(content, encoding="utf-8")

    # Write executable inline scripts declared in [install.scripts]
    for dst_rel, content in install_cfg.get("scripts", {}).items():
        dst_path = stage_dir / dst_rel.lstrip("/")
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        if dst_path.is_symlink():
            dst_path.unlink()
        dst_path.write_text(content, encoding="utf-8")
        os.chmod(dst_path, 0o755)


def stage_deb(recipe: dict, stage_dir: Path, work_dir: Path) -> None:
    """Download an upstream .deb archive, extract data.tar.*, and apply optional overrides."""
    src = recipe["source"]
    url = src["url"]
    expected_sha = src.get("sha256", "").strip().lower()
    deb_path = work_dir / Path(url).name
    download(url, deb_path)

    if expected_sha:
        actual = sha256_file(deb_path)
        if actual != expected_sha:
            raise RuntimeError(
                f"Source SHA-256 mismatch for {url}:\n  expected: {expected_sha}\n  actual  : {actual}"
            )

    deb_extract = work_dir / "deb"
    deb_extract.mkdir(parents=True, exist_ok=True)
    subprocess.run(["ar", "x", str(deb_path)], cwd=deb_extract, check=True)

    data_tars = sorted(deb_extract.glob("data.tar.*"))
    if not data_tars:
        raise RuntimeError(f"No data.tar.* found inside {deb_path}")
    data_tar = data_tars[0]
    print(f"  -> Extracting {data_tar.name} into staging rootfs...")
    subprocess.run(["tar", "-xf", str(data_tar), "-C", str(stage_dir)], check=True)

    # Remove unneeded paths (e.g. cron/apt hooks) if specified
    for rm_rel in recipe.get("install", {}).get("remove", []):
        target = stage_dir / rm_rel.lstrip("/")
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        elif target.exists() or target.is_symlink():
            target.unlink()

    install_assets_and_inline(recipe, stage_dir, stage_dir)

    # Auto-ensure every .desktop entry inside a repacked .deb has StartupWMClass so
    # COSMIC Dock pinning matches the running Wayland app_id cleanly.
    apps_dir = stage_dir / "usr" / "share" / "applications"
    if apps_dir.is_dir():
        for desktop_file in apps_dir.glob("*.desktop"):
            text = desktop_file.read_text(encoding="utf-8", errors="ignore")
            if "StartupWMClass=" not in text and "[Desktop Entry]" in text:
                text = text.replace(
                    "[Desktop Entry]\n",
                    f"[Desktop Entry]\nStartupWMClass={desktop_file.stem}\n",
                    1,
                )
                desktop_file.write_text(text, encoding="utf-8")


def stage_syslibs(recipe: dict, stage_dir: Path, _work_dir: Path) -> None:
    """Collect common C/C++ shared libraries + transitive ldd deps into a portable spkg archive."""
    src = recipe["source"]
    patterns = src.get("patterns", [])
    search_dirs = [Path("/usr/lib/x86_64-linux-gnu")]
    seen: set[Path] = set()

    # Never package core glibc / dynamic loader into app or syslibs packages:
    # the Serenity base rootfs already ships matching ld-linux + libc/libm/libpthread/libdl/librt (+ libutil/libcrypt/libmvec).
    # Overwriting them with a different Ubuntu runner's glibc or symlink breaks ELF exec!
    skip_prefixes = (
        "ld-linux-",
        "libc.so",
        "libm.so",
        "libdl.so",
        "libpthread.so",
        "librt.so",
        "libutil.so",
        "libcrypt.so",
        "libmvec.so",
    )

    def is_elf(p: Path) -> bool:
        try:
            with p.open("rb") as f:
                return f.read(4) == b"\x7fELF"
        except OSError:
            return False

    def collect_ldd_deps(p: Path) -> None:
        proc = subprocess.run(["ldd", str(p)], capture_output=True, text=True)
        for line in proc.stdout.splitlines():
            for tok in line.split():
                if tok.startswith("/") and (tok.startswith("/usr/lib") or tok.startswith("/lib")):
                    dep = Path(tok)
                    if dep.exists():
                        copy_one(dep)

    def canonical_lib_path(p: Path) -> Path:
        # On usr-merged Ubuntu 24.04, ldd reports /lib/x86_64-linux-gnu/foo.so.0 while
        # p.resolve() returns /usr/lib/x86_64-linux-gnu/foo.so.0.x.y. Normalize both to
        # /usr/lib/x86_64-linux-gnu/... so SONAME symlinks and real files stay together!
        s = str(p)
        if s.startswith("/lib/x86_64-linux-gnu/"):
            return Path("/usr" + s)
        return p

    def copy_one(p: Path) -> None:
        if not p.exists() and not p.is_symlink():
            return
        if p.name.startswith(skip_prefixes):
            return
        canon = canonical_lib_path(p)
        if canon in seen:
            return
        seen.add(canon)
        dst = stage_dir / str(canon).lstrip("/")
        dst.parent.mkdir(parents=True, exist_ok=True)
        if p.is_symlink():
            target = os.readlink(p)
            if dst.exists() or dst.is_symlink():
                dst.unlink()
            dst.symlink_to(target)
            resolved = p.resolve()
            if resolved.is_file():
                copy_one(resolved)
        elif p.is_file():
            if not dst.exists():
                shutil.copy2(p, dst)
            # Recursively collect transitive shared library dependencies via ldd
            collect_ldd_deps(p)

    matched = 0
    for libdir in search_dirs:
        if not libdir.is_dir():
            continue
        for pat in patterns:
            for match in sorted(libdir.glob(pat)):
                copy_one(match)
                matched += 1

    # Optional extra host data files/dirs/helpers declared in [source] extra_paths = [...]
    # (e.g. GSettings schemas, MIME database, glycin-loaders, gdk-pixbuf loaders, bwrap).
    # Any ELF binary or .so inside extra_paths also gets its transitive ldd deps collected.
    extra_elfs = 0
    for raw_path in src.get("extra_paths", []):
        p = Path(raw_path)
        if not p.exists():
            print(f"  -> WARN: optional extra_path not found: {p}")
            continue
        dst = stage_dir / str(p).lstrip("/")
        if p.is_dir():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(p, dst, symlinks=True, dirs_exist_ok=True)
            for root, _, files in os.walk(p):
                for fname in files:
                    item = Path(root) / fname
                    if not item.is_symlink() and item.is_file() and is_elf(item):
                        collect_ldd_deps(item)
                        extra_elfs += 1
        elif p.is_file():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, dst)
            resolved = p.resolve()
            if resolved.is_file() and is_elf(resolved):
                collect_ldd_deps(resolved)
                extra_elfs += 1

    print(
        f"  -> Collected {len(seen)} shared library file(s)/symlink(s) from {matched} pattern matches"
        f" (+ ldd deps for {extra_elfs} extra ELF file(s))."
    )

    install_assets_and_inline(recipe, None, stage_dir)


def stage_custom(recipe: dict, stage_dir: Path, work_dir: Path) -> None:
    """Run a custom bash script with STAGE_DIR and WORK_DIR env vars to assemble complex packages."""
    script = recipe["source"]["script"]
    env = os.environ.copy()
    env["STAGE_DIR"] = str(stage_dir)
    env["WORK_DIR"] = str(work_dir)
    env["PKG_VERSION"] = str(recipe["package"]["version"])
    env["REPO_DIR"] = str(ROOT_DIR)
    subprocess.run(["bash", "-euo", "pipefail", "-c", script], env=env, check=True)
    install_assets_and_inline(recipe, None, stage_dir)


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
        elif src_type == "deb":
            stage_deb(recipe, stage_dir, work_dir)
        elif src_type == "syslibs":
            stage_syslibs(recipe, stage_dir, work_dir)
        elif src_type == "custom":
            stage_custom(recipe, stage_dir, work_dir)
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
