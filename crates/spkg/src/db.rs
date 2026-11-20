use crate::manifest::{InstalledPackage, RepoConfig, RepoIndex};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

pub const CONFIG_PATH: &str = "/etc/spkg/repo.json";
pub const INDEX_CACHE_PATH: &str = "/var/db/spkg/index.json";
pub const INSTALLED_DIR: &str = "/var/db/spkg/installed";
pub const DEFAULT_INDEX_URL: &str = "file:///etc/spkg/default-index.json";

pub fn ensure_db_dirs() -> Result<(), String> {
    fs::create_dir_all(INSTALLED_DIR)
        .map_err(|e| format!("failed to create {}: {}", INSTALLED_DIR, e))
}

pub fn load_repo_url() -> String {
    if let Ok(url) = std::env::var("SPKG_REPO_URL") {
        if !url.trim().is_empty() {
            return url;
        }
    }
    if let Ok(content) = fs::read_to_string(CONFIG_PATH) {
        if let Ok(cfg) = serde_json::from_str::<RepoConfig>(&content) {
            return cfg.index_url;
        }
    }
    DEFAULT_INDEX_URL.to_string()
}

pub fn save_index(raw_json: &[u8]) -> Result<RepoIndex, String> {
    let index: RepoIndex =
        serde_json::from_slice(raw_json).map_err(|e| format!("invalid index.json: {}", e))?;
    ensure_db_dirs()?;
    fs::write(INDEX_CACHE_PATH, raw_json)
        .map_err(|e| format!("failed to write {}: {}", INDEX_CACHE_PATH, e))?;
    Ok(index)
}

pub fn load_index() -> Result<RepoIndex, String> {
    let path = if Path::new(INDEX_CACHE_PATH).exists() {
        INDEX_CACHE_PATH
    } else if Path::new("/etc/spkg/default-index.json").exists() {
        "/etc/spkg/default-index.json"
    } else {
        return Err("No package index found. Run 'spkg update' first.".to_string());
    };
    let data = fs::read_to_string(path).map_err(|e| format!("failed to read {}: {}", path, e))?;
    serde_json::from_str(&data).map_err(|e| format!("corrupt index {}: {}", path, e))
}

fn installed_path(name: &str) -> PathBuf {
    Path::new(INSTALLED_DIR).join(format!("{}.json", name))
}

pub fn load_installed(name: &str) -> Option<InstalledPackage> {
    let data = fs::read_to_string(installed_path(name)).ok()?;
    serde_json::from_str(&data).ok()
}

pub fn list_installed() -> Result<BTreeMap<String, InstalledPackage>, String> {
    ensure_db_dirs()?;
    let mut map = BTreeMap::new();
    let entries = fs::read_dir(INSTALLED_DIR)
        .map_err(|e| format!("failed to read {}: {}", INSTALLED_DIR, e))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            if let Ok(data) = fs::read_to_string(&path) {
                if let Ok(pkg) = serde_json::from_str::<InstalledPackage>(&data) {
                    map.insert(pkg.name.clone(), pkg);
                }
            }
        }
    }
    Ok(map)
}

pub fn save_installed(pkg: &InstalledPackage) -> Result<(), String> {
    ensure_db_dirs()?;
    let json = serde_json::to_string_pretty(pkg)
        .map_err(|e| format!("failed to serialize package record: {}", e))?;
    fs::write(installed_path(&pkg.name), json)
        .map_err(|e| format!("failed to save record for {}: {}", pkg.name, e))
}

pub fn delete_installed(name: &str) -> Result<(), String> {
    let p = installed_path(name);
    if p.exists() {
        fs::remove_file(&p).map_err(|e| format!("failed to delete {}: {}", p.display(), e))?;
    }
    Ok(())
}

/// Topological DFS dependency resolver with cycle detection.
/// Returns ordered list of packages to install (dependencies first, targets last).
pub fn resolve_install_order(
    index: &RepoIndex,
    targets: &[String],
) -> Result<Vec<String>, String> {
    let mut order = Vec::new();
    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();

    fn dfs(
        name: &str,
        index: &RepoIndex,
        visiting: &mut HashSet<String>,
        visited: &mut HashSet<String>,
        order: &mut Vec<String>,
    ) -> Result<(), String> {
        if visited.contains(name) {
            return Ok(());
        }
        if !visiting.insert(name.to_string()) {
            return Err(format!("cyclic dependency detected involving '{}'", name));
        }
        let meta = index
            .packages
            .get(name)
            .ok_or_else(|| format!("package '{}' not found in index", name))?;
        for dep in &meta.deps {
            dfs(dep, index, visiting, visited, order)?;
        }
        visiting.remove(name);
        visited.insert(name.to_string());
        order.push(name.to_string());
        Ok(())
    }

    for target in targets {
        dfs(target, index, &mut visiting, &mut visited, &mut order)?;
    }
    Ok(order)
}

/// Finds installed packages that depend on `target`.
pub fn find_reverse_deps(target: &str) -> Result<Vec<String>, String> {
    let installed = list_installed()?;
    let mut dependents = Vec::new();
    for (name, pkg) in installed {
        if name != target && pkg.deps.iter().any(|d| d == target) {
            dependents.push(name);
        }
    }
    Ok(dependents)
}
