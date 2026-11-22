mod archive;
mod db;
mod manifest;

use crate::manifest::InstalledPackage;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;
use std::process::ExitCode;

fn print_usage() {
    println!("spkg 0.1.0 — Serenity Linux Package Manager");
    println!();
    println!("Usage:");
    println!("  spkg update                   Fetch latest package index");
    println!("  spkg search [query]           Search available packages");
    println!("  spkg info <pkg>               Show package details");
    println!("  spkg install [--reinstall] <pkg...>  Install, repair, or reinstall package(s)");
    println!("  spkg remove [--force] <pkg..> Remove installed package(s)");
    println!("  spkg list                     List installed packages");
    println!("  spkg unzstd [file]            Decompress zstd stream or file to stdout");
}

fn cmd_update() -> Result<(), String> {
    let url = db::load_repo_url();
    println!("[spkg] Fetching index from {}...", url);
    let raw = archive::fetch_bytes(&url)?;
    let index = db::save_index(&raw)?;
    println!(
        "[spkg] Updated index (schema v{}): {} package(s) available.",
        index.version,
        index.packages.len()
    );
    Ok(())
}

fn cmd_search(query: Option<&str>) -> Result<(), String> {
    let index = db::load_index()?;
    let installed = db::list_installed()?;
    let q = query.unwrap_or("").to_ascii_lowercase();

    let mut found = 0;
    for (name, meta) in &index.packages {
        if q.is_empty()
            || name.to_ascii_lowercase().contains(&q)
            || meta.description.to_ascii_lowercase().contains(&q)
        {
            let tag = if installed.contains_key(name) {
                " [installed]"
            } else {
                ""
            };
            println!(
                "{:<16} {:<10} {}{}",
                name, meta.version, meta.description, tag
            );
            found += 1;
        }
    }
    if found == 0 {
        println!("No packages matching '{}'.", q);
    }
    Ok(())
}

fn cmd_info(name: &str) -> Result<(), String> {
    let index = db::load_index()?;
    let meta = index
        .packages
        .get(name)
        .ok_or_else(|| format!("package '{}' not found in index", name))?;

    println!("Name        : {}", name);
    println!("Version     : {}", meta.version);
    println!("Arch        : {}", meta.arch);
    println!("Description : {}", meta.description);
    println!(
        "Depends     : {}",
        if meta.deps.is_empty() {
            "(none)".to_string()
        } else {
            meta.deps.join(", ")
        }
    );
    println!("URL         : {}", meta.url);
    println!(
        "SHA-256     : {}",
        if meta.sha256.is_empty() {
            "(none)"
        } else {
            &meta.sha256
        }
    );
    if let Some(inst) = db::load_installed(name) {
        println!("Status      : installed ({}, {} file(s))", inst.version, inst.files.len());
    } else {
        println!("Status      : not installed");
    }
    Ok(())
}

fn cmd_install(args: &[String]) -> Result<(), String> {
    let mut reinstall = false;
    let mut targets = Vec::new();
    for a in args {
        if a == "--reinstall" || a == "--force" || a == "-f" {
            reinstall = true;
        } else {
            targets.push(a.clone());
        }
    }
    if targets.is_empty() {
        return Err("Usage: spkg install [--reinstall] <pkg...>".to_string());
    }
    let index = db::load_index()?;
    let order = db::resolve_install_order(&index, &targets)?;

    for name in order {
        let meta = &index.packages[&name];
        if let Some(existing) = db::load_installed(&name) {
            if existing.version == meta.version {
                let missing_count = existing
                    .files
                    .iter()
                    .filter(|f| {
                        let p = Path::new(f);
                        !p.exists() && p.symlink_metadata().is_err()
                    })
                    .count();
                if !reinstall && missing_count == 0 {
                    println!("[spkg] {} {} is already installed.", name, existing.version);
                    continue;
                }
                if missing_count > 0 {
                    println!(
                        "[spkg] Repairing {} {} ({} missing file(s))...",
                        name, existing.version, missing_count
                    );
                } else {
                    println!("[spkg] Reinstalling {} {}...", name, existing.version);
                }
            } else {
                println!(
                    "[spkg] Upgrading {} ({} -> {})...",
                    name, existing.version, meta.version
                );
            }
        } else {
            println!("[spkg] Installing {} {}...", name, meta.version);
        }

        println!("  -> Downloading {}", meta.url);
        let bytes = archive::fetch_bytes(&meta.url)?;
        println!("  -> Downloaded {} KiB, verifying SHA-256...", bytes.len() / 1024);
        archive::verify_checksum(&bytes, &meta.sha256)?;

        let files = archive::extract_package(&bytes, &name, meta)?;
        let record = InstalledPackage {
            name: name.clone(),
            version: meta.version.clone(),
            deps: meta.deps.clone(),
            files: files.clone(),
        };
        db::save_installed(&record)?;
        println!(
            "[spkg] Installed {} {} ({} file(s)).",
            name,
            meta.version,
            files.len()
        );
    }
    refresh_ldconfig_cache();
    let _ = std::process::Command::new("/bin/sync").status();
    Ok(())
}

fn refresh_ldconfig_cache() {
    let ldconfig = Path::new("/sbin/ldconfig");
    if !ldconfig.exists() {
        return;
    }
    let has_real = Path::new("/sbin/ldconfig.real").exists();
    let is_elf = fs::read(ldconfig)
        .map(|b| b.starts_with(b"\x7fELF"))
        .unwrap_or(false);
    if !has_real && !is_elf {
        return;
    }
    let _ = std::process::Command::new(ldconfig)
        .arg("-X")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    if Path::new("/etc/ld.so.cache").exists() {
        let _ = fs::create_dir_all("/var/cache/ldconfig");
        let cache_link = Path::new("/var/cache/ldconfig/ld.so.cache");
        let _ = fs::remove_file(cache_link);
        let _ = std::os::unix::fs::symlink("/etc/ld.so.cache", cache_link);
    }
}

fn lib_path_alias(path: &str) -> Option<String> {
    if let Some(rest) = path.strip_prefix("/lib/x86_64-linux-gnu/") {
        return Some(format!("/usr/lib/x86_64-linux-gnu/{}", rest));
    }
    path.strip_prefix("/usr/lib/x86_64-linux-gnu/")
        .map(|rest| format!("/lib/x86_64-linux-gnu/{}", rest))
}

fn collect_protected_files(
    installed: BTreeMap<String, InstalledPackage>,
    removing_name: &str,
    target_set: &HashSet<&str>,
) -> HashSet<String> {
    let mut protected = HashSet::new();
    for (other, other_pkg) in installed {
        if other == removing_name || target_set.contains(other.as_str()) {
            continue;
        }
        for file in other_pkg.files {
            if let Some(alias) = lib_path_alias(&file) {
                protected.insert(alias);
            }
            protected.insert(file);
        }
    }
    protected
}

fn cmd_remove(args: &[String]) -> Result<(), String> {
    let mut force = false;
    let mut targets = Vec::new();
    for a in args {
        if a == "--force" || a == "-f" {
            force = true;
        } else {
            targets.push(a.clone());
        }
    }
    if targets.is_empty() {
        return Err("Usage: spkg remove [--force] <pkg...>".to_string());
    }

    let target_set: HashSet<&str> = targets.iter().map(String::as_str).collect();

    for name in &targets {
        let pkg = db::load_installed(name)
            .ok_or_else(|| format!("package '{}' is not installed", name))?;

        if !force {
            let rdeps = db::find_reverse_deps(name)?;
            if !rdeps.is_empty() {
                return Err(format!(
                    "cannot remove '{}': required by {} (use --force to override)",
                    name,
                    rdeps.join(", ")
                ));
            }
        }

        let all_installed = db::list_installed()?;
        let protected_files = collect_protected_files(all_installed, name, &target_set);

        let is_core_lib_pkg = matches!(name.as_str(), "clibrary" | "lib32" | "serenity-base");
        let mut removed = 0usize;
        let mut kept_shared = 0usize;
        for file in &pkg.files {
            let p = Path::new(file);
            if protected_files.contains(file)
                || (!is_core_lib_pkg && archive::is_system_shared_lib_path(p))
            {
                kept_shared += 1;
                continue;
            }
            if p.exists() || p.symlink_metadata().is_ok() {
                if let Err(e) = fs::remove_file(p) {
                    eprintln!("[spkg] warn: failed to remove {}: {}", file, e);
                } else {
                    removed += 1;
                }
            }
        }
        db::delete_installed(name)?;
        if kept_shared > 0 {
            println!(
                "[spkg] Removed {} {} ({} file(s) deleted, {} shared file(s) kept).",
                pkg.name, pkg.version, removed, kept_shared
            );
        } else {
            println!(
                "[spkg] Removed {} {} ({} file(s) deleted).",
                pkg.name, pkg.version, removed
            );
        }
    }
    refresh_ldconfig_cache();
    let _ = std::process::Command::new("/bin/sync").status();
    Ok(())
}

fn cmd_list() -> Result<(), String> {
    let installed = db::list_installed()?;
    if installed.is_empty() {
        println!("No packages installed.");
        return Ok(());
    }
    for (name, pkg) in installed {
        println!("{:<16} {:<10} ({} file(s))", name, pkg.version, pkg.files.len());
    }
    Ok(())
}

fn cmd_unzstd(args: &[String]) -> Result<(), String> {
    use std::io::{self, BufReader};
    let mut stdout = io::stdout().lock();
    match args.first().map(String::as_str) {
        Some(path) if path != "-" => {
            let file = fs::File::open(path)
                .map_err(|e| format!("failed to open {}: {}", path, e))?;
            let reader = BufReader::new(file);
            let mut decoder = ruzstd::decoding::StreamingDecoder::new(reader)
                .map_err(|e| format!("invalid zstd stream {}: {:?}", path, e))?;
            io::copy(&mut decoder, &mut stdout)
                .map_err(|e| format!("zstd decompress {} failed: {}", path, e))?;
        }
        _ => {
            let stdin = io::stdin().lock();
            let mut decoder = ruzstd::decoding::StreamingDecoder::new(stdin)
                .map_err(|e| format!("invalid zstd stream: {:?}", e))?;
            io::copy(&mut decoder, &mut stdout)
                .map_err(|e| format!("zstd decompress failed: {}", e))?;
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print_usage();
        return ExitCode::SUCCESS;
    }

    let result = match args[0].as_str() {
        "update" => cmd_update(),
        "search" => cmd_search(args.get(1).map(String::as_str)),
        "info" => match args.get(1) {
            Some(name) => cmd_info(name),
            None => Err("Usage: spkg info <pkg>".to_string()),
        },
        "install" => cmd_install(&args[1..]),
        "remove" | "uninstall" => cmd_remove(&args[1..]),
        "list" => cmd_list(),
        "unzstd" => cmd_unzstd(&args[1..]),
        "-h" | "--help" | "help" => {
            print_usage();
            Ok(())
        }
        other => Err(format!("unknown command '{}'. Run 'spkg help'.", other)),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[spkg] error: {}", e);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protected_files_normalizes_lib_dirs() {
        let mut installed = BTreeMap::new();
        installed.insert(
            "clibrary".to_string(),
            InstalledPackage {
                name: "clibrary".to_string(),
                version: "1.0.7".to_string(),
                deps: vec![],
                files: vec!["/usr/lib/x86_64-linux-gnu/libwayland-egl.so.1".to_string()],
            },
        );
        installed.insert(
            "serenity-base".to_string(),
            InstalledPackage {
                name: "serenity-base".to_string(),
                version: "0.1.2".to_string(),
                deps: vec![],
                files: vec!["/lib/x86_64-linux-gnu/libGL.so.1".to_string()],
            },
        );
        let targets: HashSet<&str> = ["app-a"].into_iter().collect();
        let protected = collect_protected_files(installed, "app-a", &targets);

        assert!(protected.contains("/usr/lib/x86_64-linux-gnu/libwayland-egl.so.1"));
        assert!(protected.contains("/lib/x86_64-linux-gnu/libwayland-egl.so.1"));
        assert!(protected.contains("/lib/x86_64-linux-gnu/libGL.so.1"));
        assert!(protected.contains("/usr/lib/x86_64-linux-gnu/libGL.so.1"));
    }
}
