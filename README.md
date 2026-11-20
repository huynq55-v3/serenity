# Serenity Linux

Minimal, modern Linux OS powered by **Linux Kernel + Rust Userland (`x86_64-unknown-linux-musl`) + Nushell + `spkg` Package Manager**.

## Highlights
- **PID 1 (`serenity-init`)**: Pure-Rust static `musl` init process — mounts virtual filesystems (`/proc`, `/sys`, `/dev`, `/tmp`, `/run`), configures `eth0` via Linux `ioctl`, manages controlling terminal + `TIOCSWINSZ`, reaps zombies, and provides `poweroff` / `reboot`.
- **Default Shell & Coreutils**: Static `nushell` + `uutils/coreutils` (105 applets) on a persistent `ext4` disk image (`build/disk.img`).
- **Package Manager (`spkg`)**: Pure-Rust static binary (`ureq` + `rustls`, `ruzstd`, `flate2`, `tar`, `sha2`) supporting `.tar.zst`, `.tar.gz`, and `.apk` with SHA-256 verification and dependency resolution.
- **GitHub Actions Package Factory**: Add `packages/<name>/recipe.toml` and push to automatically build `.tar.zst` archives + `index.json` onto GitHub Releases (`pkgs-v1`).

## Quick Start
```bash
# Verify host tools
make check-deps

# Boot Serenity Linux in QEMU (persistent ext4 disk + networking)
make run

# Run automated end-to-end QEMU smoke test (boot + net + spkg install/remove + poweroff)
make smoke-test

# Build .tar.zst packages + index.json locally
make packages
```

Inside Serenity Linux (`root@serenity:~ >`):
```nu
spkg update
spkg search
spkg install ripgrep
rg --version
spkg list
spkg remove ripgrep
poweroff
```

## Connecting `spkg` to your GitHub Releases
After pushing to GitHub and letting `.github/workflows/build-packages.yml` publish tag `pkgs-v1`, update `rootfs/overlay/etc/spkg/repo.json`:
```json
{
  "index_url": "https://github.com/<owner>/<repo>/releases/download/pkgs-v1/index.json"
}
```
