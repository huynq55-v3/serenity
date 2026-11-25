//! Desktop notifications, Wayland clipboard integration, and output path helpers.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use zbus::zvariant::Value;

/// Sends a best-effort desktop notification via `org.freedesktop.Notifications`.
pub fn send_notification(summary: &str, body: &str, icon: &str) {
    let summary = summary.to_string();
    let body = body.to_string();
    let icon = icon.to_string();

    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return;
    };

    let _ = rt.block_on(async move {
        let fut = async {
            let conn = zbus::Connection::session().await?;
            let empty_actions: Vec<&str> = Vec::new();
            let hints: HashMap<&str, Value<'_>> = HashMap::new();
            let _: (u32,) = conn
                .call_method(
                    Some("org.freedesktop.Notifications"),
                    "/org/freedesktop/Notifications",
                    Some("org.freedesktop.Notifications"),
                    "Notify",
                    &(
                        "Serenity Capture",
                        0u32,
                        icon.as_str(),
                        summary.as_str(),
                        body.as_str(),
                        empty_actions,
                        hints,
                        4000i32,
                    ),
                )
                .await?
                .body()
                .deserialize()?;
            Ok::<_, zbus::Error>(())
        };
        let _ = tokio::time::timeout(Duration::from_secs(2), fut).await;
    });
}

/// Copies PNG bytes to the Wayland clipboard using `wl-copy` without leaking open stdio pipes.
pub fn copy_png_to_clipboard(png_bytes: &[u8]) -> Result<(), String> {
    let bin = if Path::new("/usr/bin/wl-copy").exists() {
        "/usr/bin/wl-copy"
    } else {
        "wl-copy"
    };

    let mut child = Command::new(bin)
        .args(["-t", "image/png"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to launch {bin}: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(png_bytes)
            .map_err(|e| format!("failed to write PNG to {bin}: {e}"))?;
    }

    let status = child
        .wait()
        .map_err(|e| format!("failed waiting for {bin}: {e}"))?;
    if !status.success() {
        return Err(format!("{bin} exited with status {status}"));
    }
    Ok(())
}

/// Returns a local timestamp formatted as `YYYYMMDD-HHMMSS`.
pub fn timestamp_string() -> String {
    unsafe {
        let mut now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&mut now, &mut tm).is_null() {
            return format!("ts-{}", now);
        }
        format!(
            "{:04}{:02}{:02}-{:02}{:02}{:02}",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec
        )
    }
}

/// Returns the default screenshot output path and ensures its parent directory exists.
pub fn default_screenshot_path() -> PathBuf {
    let base = xdg_dir("XDG_PICTURES_DIR", "Pictures").join("Screenshots");
    let _ = std::fs::create_dir_all(&base);
    base.join(format!("screenshot-{}.png", timestamp_string()))
}

/// Returns the default screencast output path and ensures its parent directory exists.
pub fn default_recording_path() -> PathBuf {
    let base = xdg_dir("XDG_VIDEOS_DIR", "Videos").join("Screencasts");
    let _ = std::fs::create_dir_all(&base);
    base.join(format!("screencast-{}.mp4", timestamp_string()))
}

fn xdg_dir(env_var: &str, home_fallback: &str) -> PathBuf {
    if let Ok(val) = std::env::var(env_var) {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(home_fallback)
}
