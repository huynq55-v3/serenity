mod archive;
mod db;
mod manifest;

use crate::manifest::InstalledPackage;
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
    println!("  spkg install <pkg...>         Install package(s) and dependencies");
    println!("  spkg remove [--force] <pkg..> Remove installed package(s)");
    println!("  spkg list                     List installed packages");
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

fn cmd_install(targets: &[String]) -> Result<(), String> {
    if targets.is_empty() {
        return Err("Usage: spkg install <pkg...>".to_string());
    }
    let index = db::load_index()?;
    let order = db::resolve_install_order(&index, targets)?;

    for name in order {
        let meta = &index.packages[&name];
        if let Some(existing) = db::load_installed(&name) {
            if existing.version == meta.version {
                println!("[spkg] {} {} is already installed.", name, existing.version);
                continue;
            }
            println!(
                "[spkg] Upgrading {} ({} -> {})...",
                name, existing.version, meta.version
            );
        } else {
            println!("[spkg] Installing {} {}...", name, meta.version);
        }

        println!("  -> Downloading {}", meta.url);
        let bytes = archive::fetch_bytes(&meta.url)?;
        println!("  -> Downloaded {} KiB, verifying SHA-256...", bytes.len() / 1024);
        archive::verify_checksum(&bytes, &meta.sha256)?;

        let files = archive::extract_package(&bytes, meta)?;
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
    let _ = std::process::Command::new("/bin/sync").status();
    Ok(())
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

    for name in targets {
        let pkg = db::load_installed(&name)
            .ok_or_else(|| format!("package '{}' is not installed", name))?;

        if !force {
            let rdeps = db::find_reverse_deps(&name)?;
            if !rdeps.is_empty() {
                return Err(format!(
                    "cannot remove '{}': required by {} (use --force to override)",
                    name,
                    rdeps.join(", ")
                ));
            }
        }

        let mut removed = 0;
        for file in &pkg.files {
            let p = Path::new(file);
            if p.exists() || p.symlink_metadata().is_ok() {
                if let Err(e) = fs::remove_file(p) {
                    eprintln!("[spkg] warn: failed to remove {}: {}", file, e);
                } else {
                    removed += 1;
                }
            }
        }
        db::delete_installed(&name)?;
        println!("[spkg] Removed {} {} ({} file(s) deleted).", pkg.name, pkg.version, removed);
    }
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
