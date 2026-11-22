pub mod sysinfo;
pub mod wifi;

use std::path::{Path, PathBuf};

pub const DEJAVU_SANS: &[u8] = include_bytes!("../assets/DejaVuSans.ttf");
pub const ROBOTO_REGULAR: &[u8] = include_bytes!("../assets/Roboto-Regular.ttf");

/// Resolves a sibling Serenity binary (`serenity-shell`, `serenity-login`)
/// from the same directory as the current executable first (works in both `target/debug/` and `/usr/bin/`).
pub fn resolve_bin(name: &str) -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(name);
            if candidate.exists() {
                return candidate;
            }
        }
    }
    let usr_bin = Path::new("/usr/bin").join(name);
    if usr_bin.exists() {
        return usr_bin;
    }
    PathBuf::from(name)
}
