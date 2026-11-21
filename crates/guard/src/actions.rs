use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;

pub const BLOCKED_IPS_PATH: &str = "/etc/serenity/blocked-ips.conf";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicReport {
    pub pid: i32,
    pub exists: bool,
    pub captured_at_epoch: u64,
    pub live_status: String,
    pub state: String,
    pub comm: String,
    pub exe: String,
    pub exe_sha256: String,
    pub cmdline: String,
    pub cwd: String,
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
    pub ppid: i32,
    pub parent_chain: Vec<String>,
    pub threads: u32,
    pub rss_kb: u64,
    pub environ_vars: Vec<String>,
    pub network_sockets: Vec<String>,
    pub alert_history: Vec<String>,
    pub open_fds: Vec<String>,
    pub rwx_memory_regions: Vec<String>,
}

pub fn load_blocked_ips() -> HashSet<String> {
    let mut set = HashSet::new();
    let Ok(content) = fs::read_to_string(BLOCKED_IPS_PATH) else {
        return set;
    };
    for line in content.lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if !trimmed.is_empty() && trimmed.parse::<Ipv4Addr>().is_ok() {
            set.insert(trimmed.to_string());
        }
    }
    set
}

pub fn validate_blockable_ipv4(ip_str: &str) -> Result<Ipv4Addr, String> {
    let ip: Ipv4Addr = ip_str
        .trim()
        .parse()
        .map_err(|_| format!("Invalid IPv4 address: '{}'", ip_str))?;
    if ip.is_loopback() || ip.is_unspecified() {
        return Err(format!("Refusing to block loopback/unspecified IP: {}", ip));
    }
    Ok(ip)
}

pub fn block_ip(ip_str: &str) -> Result<String, String> {
    let ip = validate_blockable_ipv4(ip_str)?;
    let ip_s = ip.to_string();

    let fw_bin = if Path::new("/usr/bin/serenity-fw").exists() {
        "/usr/bin/serenity-fw"
    } else {
        return Err("/usr/bin/serenity-fw not found".to_string());
    };

    let output = Command::new(fw_bin)
        .args(["block", &ip_s])
        .output()
        .map_err(|e| format!("Failed to execute serenity-fw block: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Err(format!(
            "serenity-fw block {} failed: {} {}",
            ip_s, stdout, stderr
        ));
    }

    Ok(format!(
        "Blocked IPv4 {} in kernel nftables (inet serenity_fw) and {}",
        ip_s, BLOCKED_IPS_PATH
    ))
}

pub fn unblock_ip(ip_str: &str) -> Result<String, String> {
    let ip: Ipv4Addr = ip_str
        .trim()
        .parse()
        .map_err(|_| format!("Invalid IPv4 address: '{}'", ip_str))?;
    let ip_s = ip.to_string();

    let fw_bin = if Path::new("/usr/bin/serenity-fw").exists() {
        "/usr/bin/serenity-fw"
    } else {
        return Err("/usr/bin/serenity-fw not found".to_string());
    };

    let output = Command::new(fw_bin)
        .args(["unblock", &ip_s])
        .output()
        .map_err(|e| format!("Failed to execute serenity-fw unblock: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Err(format!(
            "serenity-fw unblock {} failed: {} {}",
            ip_s, stdout, stderr
        ));
    }

    Ok(format!("Unblocked IPv4 {} and reloaded nftables", ip_s))
}

pub fn parse_ip_port(addr: &str) -> Result<(Ipv4Addr, u16), String> {
    let (ip_s, port_s) = addr
        .trim()
        .rsplit_once(':')
        .ok_or_else(|| format!("Expected <ipv4>:<port>, got '{}'", addr))?;
    let ip: Ipv4Addr = ip_s
        .parse()
        .map_err(|_| format!("Invalid IPv4 address '{}'", ip_s))?;
    let port: u16 = port_s
        .parse()
        .map_err(|_| format!("Invalid port '{}'", port_s))?;
    Ok((ip, port))
}

pub fn kill_tcp_connection(local_addr: &str, remote_addr: &str) -> Result<String, String> {
    let (l_ip, l_port) = parse_ip_port(local_addr)?;
    let (r_ip, r_port) = parse_ip_port(remote_addr)?;
    crate::net_mon::destroy_tcp_socket_v4(l_ip, l_port, r_ip, r_port)?;
    Ok(format!(
        "Terminated TCP socket {}:{} <-> {}:{} via kernel SOCK_DESTROY",
        l_ip, l_port, r_ip, r_port
    ))
}

fn validate_target_pid(pid: i32) -> Result<(), String> {
    if pid <= 2 {
        return Err(format!("Refusing to signal critical kernel/init PID {}", pid));
    }
    let self_pid = unsafe { libc::getpid() };
    if pid == self_pid {
        return Err("Refusing to signal serenity-guard itself".to_string());
    }
    Ok(())
}

pub fn freeze_process(pid: i32) -> Result<String, String> {
    validate_target_pid(pid)?;
    let (_, _, _, comm, exe, _) = crate::proc_mon::read_proc_meta(pid);
    let rc = unsafe { libc::kill(pid, libc::SIGSTOP) };
    if rc != 0 {
        return Err(format!(
            "kill({}, SIGSTOP) failed: {}",
            pid,
            std::io::Error::last_os_error()
        ));
    }
    Ok(format!(
        "Frozen PID {} ({} [{}]) with SIGSTOP (preserved in RAM for forensic inspection)",
        pid, comm, exe
    ))
}

pub fn resume_process(pid: i32) -> Result<String, String> {
    validate_target_pid(pid)?;
    let (_, _, _, comm, exe, _) = crate::proc_mon::read_proc_meta(pid);
    let rc = unsafe { libc::kill(pid, libc::SIGCONT) };
    if rc != 0 {
        return Err(format!(
            "kill({}, SIGCONT) failed: {}",
            pid,
            std::io::Error::last_os_error()
        ));
    }
    Ok(format!("Resumed PID {} ({} [{}]) with SIGCONT", pid, comm, exe))
}

pub fn kill_process(pid: i32) -> Result<String, String> {
    validate_target_pid(pid)?;
    let (_, _, _, comm, exe, _) = crate::proc_mon::read_proc_meta(pid);
    let rc = unsafe { libc::kill(pid, libc::SIGKILL) };
    if rc != 0 {
        return Err(format!(
            "kill({}, SIGKILL) failed: {}",
            pid,
            std::io::Error::last_os_error()
        ));
    }
    unsafe {
        let _ = libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG);
    }
    Ok(format!(
        "Terminated PID {} ({} [{}]) with SIGKILL",
        pid, comm, exe
    ))
}

pub fn inspect_process(pid: i32) -> ForensicReport {
    let now = crate::epoch_now();
    let proc_dir = format!("/proc/{}", pid);
    if pid <= 0 || !Path::new(&proc_dir).exists() {
        return ForensicReport {
            pid,
            exists: false,
            captured_at_epoch: now,
            live_status: "EXITED (Not running, no snapshot cached for this PID)".to_string(),
            state: "EXITED".to_string(),
            comm: String::new(),
            exe: String::new(),
            exe_sha256: String::new(),
            cmdline: String::new(),
            cwd: String::new(),
            uid: 0,
            euid: 0,
            gid: 0,
            egid: 0,
            ppid: 0,
            parent_chain: Vec::new(),
            threads: 0,
            rss_kb: 0,
            environ_vars: Vec::new(),
            network_sockets: Vec::new(),
            alert_history: Vec::new(),
            open_fds: Vec::new(),
            rwx_memory_regions: Vec::new(),
        };
    }

    let (ppid, uid, euid, comm, exe, cmdline) = crate::proc_mon::read_proc_meta(pid);
    let cwd = fs::read_link(format!("/proc/{}/cwd", pid))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    let exe_sha256 = crate::fim::sha256_file(Path::new(&format!("/proc/{}/exe", pid)))
        .map(|(h, _, _)| h)
        .unwrap_or_default();

    let mut state = String::new();
    let mut gid = 0u32;
    let mut egid = 0u32;
    let mut threads = 1u32;
    let mut rss_kb = 0u64;

    if let Ok(status) = fs::read_to_string(format!("/proc/{}/status", pid)) {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("State:") {
                state = rest.trim().to_string();
            } else if let Some(rest) = line.strip_prefix("Gid:") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() >= 2 {
                    gid = parts[0].parse().unwrap_or(0);
                    egid = parts[1].parse().unwrap_or(0);
                }
            } else if let Some(rest) = line.strip_prefix("Threads:") {
                threads = rest.trim().parse().unwrap_or(1);
            } else if let Some(rest) = line.strip_prefix("VmRSS:") {
                let num = rest
                    .split_whitespace()
                    .next()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0);
                rss_kb = num;
            }
        }
    }

    // Build parent ancestry chain (up to 8 levels)
    let mut parent_chain = Vec::new();
    let mut cur_ppid = ppid;
    for _ in 0..8 {
        if cur_ppid <= 0 {
            break;
        }
        let (next_ppid, _, _, p_comm, p_exe, _) = crate::proc_mon::read_proc_meta(cur_ppid);
        if p_comm.is_empty() && p_exe.is_empty() {
            break;
        }
        parent_chain.push(format!("{} ({} [{}])", cur_ppid, p_comm, p_exe));
        if cur_ppid == 1 || next_ppid == cur_ppid {
            break;
        }
        cur_ppid = next_ppid;
    }

    // Open file descriptors (up to 48)
    let mut open_fds = Vec::new();
    if let Ok(entries) = fs::read_dir(format!("/proc/{}/fd", pid)) {
        for entry in entries.flatten().take(48) {
            let fd_name = entry.file_name().to_string_lossy().into_owned();
            if let Ok(target) = fs::read_link(entry.path()) {
                open_fds.push(format!("fd {} -> {}", fd_name, target.to_string_lossy()));
            }
        }
    }

    // Check for suspicious rwxp (writable + executable) memory mappings
    let mut rwx_memory_regions = Vec::new();
    if let Ok(maps) = fs::read_to_string(format!("/proc/{}/maps", pid)) {
        for line in maps.lines() {
            let mut parts = line.split_whitespace();
            let addr = parts.next().unwrap_or("");
            let perms = parts.next().unwrap_or("");
            if perms.contains('w') && perms.contains('x') {
                rwx_memory_regions.push(line.to_string());
                if rwx_memory_regions.len() >= 16 {
                    let _ = addr;
                    break;
                }
            }
        }
    }

    // Key environment variables (USER, HOME, PWD, SHELL, PATH, LD_*, SUDO_*, SSH_*, DISPLAY...)
    let mut environ_vars = Vec::new();
    if let Ok(env_bytes) = fs::read(format!("/proc/{}/environ", pid)) {
        const INTERESTING_PREFIXES: &[&str] = &[
            "USER=",
            "LOGNAME=",
            "HOME=",
            "PWD=",
            "SHELL=",
            "PATH=",
            "LD_",
            "SUDO_",
            "SSH_",
            "WAYLAND_DISPLAY=",
            "DISPLAY=",
        ];
        for entry in env_bytes.split(|&b| b == 0) {
            if entry.is_empty() {
                continue;
            }
            let s = String::from_utf8_lossy(entry);
            if INTERESTING_PREFIXES.iter().any(|p| s.starts_with(p)) {
                environ_vars.push(s.into_owned());
                if environ_vars.len() >= 20 {
                    break;
                }
            }
        }
    }

    let live_status = format!("ALIVE ({})", state);

    ForensicReport {
        pid,
        exists: true,
        captured_at_epoch: now,
        live_status,
        state,
        comm,
        exe,
        exe_sha256,
        cmdline,
        cwd,
        uid,
        euid,
        gid,
        egid,
        ppid,
        parent_chain,
        threads,
        rss_kb,
        environ_vars,
        network_sockets: Vec::new(),
        alert_history: Vec::new(),
        open_fds,
        rwx_memory_regions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_blockable_ipv4() {
        assert!(validate_blockable_ipv4("127.0.0.1").is_err());
        assert!(validate_blockable_ipv4("0.0.0.0").is_err());
        assert!(validate_blockable_ipv4("not-an-ip").is_err());
        assert_eq!(
            validate_blockable_ipv4("198.51.100.42").unwrap(),
            Ipv4Addr::new(198, 51, 100, 42)
        );
    }

    #[test]
    fn test_parse_ip_port() {
        let (ip, port) = parse_ip_port("192.168.1.15:443").unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 15));
        assert_eq!(port, 443);
    }

    #[test]
    fn test_inspect_self_process() {
        let self_pid = unsafe { libc::getpid() };
        let report = inspect_process(self_pid);
        assert!(report.exists);
        assert_eq!(report.pid, self_pid);
        assert!(!report.exe_sha256.is_empty());
    }
}
