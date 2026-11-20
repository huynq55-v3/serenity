use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoConfig {
    pub index_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoIndex {
    pub version: u32,
    pub packages: BTreeMap<String, PackageMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMeta {
    pub version: String,
    pub arch: String,
    pub description: String,
    pub url: String,
    /// Hex-encoded SHA-256 checksum. If empty, verification is skipped with a warning.
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub deps: Vec<String>,
    /// Optional mapping from archive entry basename (e.g. "rg") to target path (e.g. "/usr/bin/rg").
    /// When empty, archive entries are extracted directly relative to `/` (native Serenity package layout).
    #[serde(default)]
    pub extract_files: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub deps: Vec<String>,
    pub files: Vec<String>,
}
