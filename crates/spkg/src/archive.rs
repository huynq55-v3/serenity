use crate::manifest::PackageMeta;
use flate2::read::GzDecoder;
use ruzstd::decoding::StreamingDecoder;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Cursor, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use tar::Archive;

pub fn fetch_bytes(url: &str) -> Result<Vec<u8>, String> {
    if let Some(path) = url.strip_prefix("file://") {
        return fs::read(path).map_err(|e| format!("failed to read {}: {}", path, e));
    }

    let resp = ureq::get(url)
        .set("User-Agent", "spkg/0.1.0 (Serenity Linux)")
        .call()
        .map_err(|e| format!("HTTP GET {} failed: {}", url, e))?;

    let mut bytes = Vec::new();
    resp.into_reader()
        .read_to_end(&mut bytes)
        .map_err(|e| format!("failed reading response from {}: {}", url, e))?;
    Ok(bytes)
}

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

pub fn verify_checksum(data: &[u8], expected: &str) -> Result<(), String> {
    let expected = expected.trim().to_ascii_lowercase();
    if expected.is_empty() {
        eprintln!("[spkg] warn: package has no sha256 checksum; skipping verification");
        return Ok(());
    }
    let actual = sha256_hex(data);
    if actual != expected {
        return Err(format!(
            "SHA-256 mismatch!\n  expected: {}\n  actual  : {}",
            expected, actual
        ));
    }
    Ok(())
}

/// Sanitizes a tar entry path so it cannot escape `/` via `..` components.
fn sanitize_rel_path(path: &Path) -> Result<PathBuf, String> {
    let mut clean = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Normal(c) => clean.push(c),
            Component::CurDir => {}
            Component::RootDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(format!("unsafe archive entry path: {}", path.display()));
            }
        }
    }
    Ok(clean)
}

fn extract_tar<R: Read>(reader: R, meta: &PackageMeta) -> Result<Vec<String>, String> {
    let mut archive = Archive::new(reader);
    let mut installed_files = Vec::new();

    let entries = archive
        .entries()
        .map_err(|e| format!("failed to read tar entries: {}", e))?;

    for entry_res in entries {
        let mut entry = entry_res.map_err(|e| format!("corrupt tar entry: {}", e))?;
        let entry_type = entry.header().entry_type();
        let raw_path = entry
            .path()
            .map_err(|e| format!("invalid tar entry path: {}", e))?
            .into_owned();

        if !meta.extract_files.is_empty() {
            // Selective extraction mode (for upstream GitHub Releases tarballs)
            if !entry_type.is_file() {
                continue;
            }
            let file_name = raw_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            if let Some(dest_str) = meta.extract_files.get(file_name) {
                let dest = Path::new(dest_str);
                if let Some(parent) = dest.parent() {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("mkdir {} failed: {}", parent.display(), e))?;
                }
                let tmp_dest = dest.with_extension("spkg-tmp");
                {
                    let mut out = File::create(&tmp_dest)
                        .map_err(|e| format!("create {} failed: {}", tmp_dest.display(), e))?;
                    io::copy(&mut entry, &mut out)
                        .map_err(|e| format!("extract {} failed: {}", dest.display(), e))?;
                }
                let mode = entry.header().mode().unwrap_or(0o755);
                let _ = fs::set_permissions(&tmp_dest, fs::Permissions::from_mode(mode));
                fs::rename(&tmp_dest, dest)
                    .map_err(|e| format!("install {} failed: {}", dest.display(), e))?;
                installed_files.push(dest_str.clone());
            }
        } else {
            // Native Serenity rootfs-relative extraction mode (extracts directly into `/`)
            let rel = sanitize_rel_path(&raw_path)?;
            if rel.as_os_str().is_empty() {
                continue;
            }
            let dest = Path::new("/").join(&rel);
            if entry_type.is_dir() {
                fs::create_dir_all(&dest)
                    .map_err(|e| format!("mkdir {} failed: {}", dest.display(), e))?;
            } else if entry_type.is_file() || entry_type.is_symlink() {
                if let Some(parent) = dest.parent() {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("mkdir {} failed: {}", parent.display(), e))?;
                }
                let file_name = dest
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("file");
                let tmp_dest = dest
                    .parent()
                    .unwrap_or_else(|| Path::new("/"))
                    .join(format!(".{}.spkg-tmp-{}", file_name, std::process::id()));
                if tmp_dest.symlink_metadata().is_ok() {
                    let _ = fs::remove_file(&tmp_dest);
                }
                if let Err(e) = entry.unpack(&tmp_dest) {
                    let _ = fs::remove_file(&tmp_dest);
                    return Err(format!("unpack {} failed: {}", dest.display(), e));
                }
                if let Err(e) = fs::rename(&tmp_dest, &dest) {
                    let _ = fs::remove_file(&tmp_dest);
                    return Err(format!("install {} failed: {}", dest.display(), e));
                }
                installed_files.push(dest.to_string_lossy().into_owned());
            }
        }
    }

    if !meta.extract_files.is_empty() && installed_files.is_empty() {
        return Err("no matching files found in archive for extract_files map".to_string());
    }

    Ok(installed_files)
}

pub fn extract_package(bytes: &[u8], meta: &PackageMeta) -> Result<Vec<String>, String> {
    let url_lower = meta.url.to_ascii_lowercase();
    if url_lower.ends_with(".tar.zst") || url_lower.ends_with(".tzst") {
        let cursor = Cursor::new(bytes);
        let decoder = StreamingDecoder::new(cursor)
            .map_err(|e| format!("zstd decode init failed: {}", e))?;
        extract_tar(decoder, meta)
    } else if url_lower.ends_with(".tar.gz")
        || url_lower.ends_with(".tgz")
        || url_lower.ends_with(".apk")
    {
        let cursor = Cursor::new(bytes);
        let decoder = GzDecoder::new(cursor);
        extract_tar(decoder, meta)
    } else {
        Err(format!(
            "unsupported archive format for '{}' (expected .tar.zst, .tar.gz, or .apk)",
            meta.url
        ))
    }
}
