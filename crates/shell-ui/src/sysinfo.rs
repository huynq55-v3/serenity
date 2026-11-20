use std::fs;
use std::path::Path;
use std::process::Command;

pub struct SystemSnapshot {
    pub kernel: String,
    pub uptime: String,
    pub user: String,
    pub installed_pkgs: usize,
}

pub fn read_system_snapshot() -> SystemSnapshot {
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let uptime = fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().and_then(|v| v.parse::<f64>().ok()))
        .map(|secs| {
            let mins = (secs / 60.0) as u64;
            let rem = (secs as u64) % 60;
            format!("{}m {}s", mins, rem)
        })
        .unwrap_or_else(|| "?".to_string());

    let user = std::env::var("USER").unwrap_or_else(|_| "serenity".to_string());

    let installed_pkgs = fs::read_dir("/var/db/spkg/installed")
        .map(|entries| entries.flatten().count())
        .unwrap_or(0);

    SystemSnapshot {
        kernel,
        uptime,
        user,
        installed_pkgs,
    }
}

pub fn run_shell_command(cmd_line: &str) -> String {
    let trimmed = cmd_line.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // Prefer Nushell (/bin/nu or PATH `nu`), fall back to `/bin/sh`.
    let shell = if Path::new("/bin/nu").exists() {
        "/bin/nu"
    } else if Command::new("nu").arg("--version").output().is_ok() {
        "nu"
    } else {
        "/bin/sh"
    };

    match Command::new(shell).args(["-c", trimmed]).output() {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.trim().is_empty() {
                stdout.to_string()
            } else if stdout.trim().is_empty() {
                stderr.to_string()
            } else {
                format!("{}\n[stderr]\n{}", stdout, stderr)
            }
        }
        Err(e) => format!("Failed to execute '{}' via {}: {}", trimmed, shell, e),
    }
}
