use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};

const NETLINK_SOCK_DIAG: libc::c_int = 4;
const SOCK_DESTROY: u16 = 21;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLMSG_ERROR: u16 = 0x0002;
const TCP_ESTABLISHED: u8 = 1;
const INET_DIAG_NOCOOKIE: u32 = 0xFFFF_FFFF;

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
struct InetDiagSockId {
    idiag_sport: u16, // network byte order (big-endian)
    idiag_dport: u16, // network byte order (big-endian)
    idiag_src: [u32; 4],
    idiag_dst: [u32; 4],
    idiag_if: u32,
    idiag_cookie: [u32; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InetDiagReqV2 {
    sdiag_family: u8,
    sdiag_protocol: u8,
    idiag_ext: u8,
    pad: u8,
    idiag_states: u32,
    id: InetDiagSockId,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DestroyPacket {
    nlh: NlMsgHdr,
    req: InetDiagReqV2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetConnection {
    pub proto: String, // "tcp", "tcp6", "udp", "udp6"
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub state: String, // "ESTABLISHED", "LISTEN", etc.
    pub uid: u32,
    pub inode: u64,
    pub pid: Option<i32>,
    pub comm: String,
    pub exe: String,
    pub cmdline: String,
    pub suspicious: bool,
    pub suspicion_reason: String,
}

#[derive(Debug, Clone)]
pub struct NetSecurityAlert {
    pub severity: &'static str,
    pub rule_id: &'static str,
    pub pid: Option<i32>,
    pub remote_ip: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub exe: String,
    pub summary: String,
    pub recommend_freeze: bool,
    pub recommend_kill_socket: bool,
}

#[derive(Debug, Clone)]
struct SocketOwner {
    pid: i32,
    comm: String,
    exe: String,
    cmdline: String,
}

fn build_inode_owner_map() -> HashMap<u64, SocketOwner> {
    let mut map = HashMap::new();
    let Ok(proc_entries) = fs::read_dir("/proc") else {
        return map;
    };

    for entry in proc_entries.flatten() {
        let name = entry.file_name();
        let Some(pid_str) = name.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<i32>() else {
            continue;
        };

        let fd_dir = format!("/proc/{}/fd", pid);
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };

        let mut proc_meta: Option<(String, String, String)> = None;
        for fd_entry in fds.flatten() {
            let Ok(target) = fs::read_link(fd_entry.path()) else {
                continue;
            };
            let target_str = target.to_string_lossy();
            let Some(inode_str) = target_str
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
            else {
                continue;
            };
            let Ok(inode) = inode_str.parse::<u64>() else {
                continue;
            };

            let (comm, exe, cmdline) = proc_meta.get_or_insert_with(|| {
                let (_, _, _, c, e, cmd) = crate::proc_mon::read_proc_meta(pid);
                (c, e, cmd)
            });

            map.entry(inode).or_insert_with(|| SocketOwner {
                pid,
                comm: comm.clone(),
                exe: exe.clone(),
                cmdline: cmdline.clone(),
            });
        }
    }

    map
}

fn tcp_state_name(st: u8) -> &'static str {
    match st {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        _ => "UNKNOWN",
    }
}

fn parse_ipv4_hex(hex_ip: &str) -> Option<String> {
    if hex_ip.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(hex_ip, 16).ok()?;
    let b = raw.to_le_bytes();
    Some(Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string())
}

fn parse_ipv6_hex(hex_ip: &str) -> Option<String> {
    if hex_ip.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for i in 0..4 {
        let word = u32::from_str_radix(&hex_ip[i * 8..(i + 1) * 8], 16).ok()?;
        octets[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    let addr = Ipv6Addr::from(octets);
    if let Some(v4) = addr.to_ipv4_mapped() {
        Some(v4.to_string())
    } else {
        Some(addr.to_string())
    }
}

fn parse_proc_net_table(
    proto: &str,
    path: &str,
    is_v6: bool,
    owners: &HashMap<u64, SocketOwner>,
) -> Vec<NetConnection> {
    let mut out = Vec::new();
    let Ok(content) = fs::read_to_string(path) else {
        return out;
    };

    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let Some((l_ip_hex, l_port_hex)) = cols[1].split_once(':') else {
            continue;
        };
        let Some((r_ip_hex, r_port_hex)) = cols[2].split_once(':') else {
            continue;
        };

        let local_ip = if is_v6 {
            parse_ipv6_hex(l_ip_hex)
        } else {
            parse_ipv4_hex(l_ip_hex)
        };
        let remote_ip = if is_v6 {
            parse_ipv6_hex(r_ip_hex)
        } else {
            parse_ipv4_hex(r_ip_hex)
        };
        let (Some(local_ip), Some(remote_ip)) = (local_ip, remote_ip) else {
            continue;
        };

        let Ok(local_port) = u16::from_str_radix(l_port_hex, 16) else {
            continue;
        };
        let Ok(remote_port) = u16::from_str_radix(r_port_hex, 16) else {
            continue;
        };
        let Ok(st_code) = u8::from_str_radix(cols[3], 16) else {
            continue;
        };

        let state = if proto.starts_with("udp") {
            if st_code == 0x01 {
                "ESTABLISHED".to_string()
            } else {
                "LISTEN".to_string()
            }
        } else {
            tcp_state_name(st_code).to_string()
        };

        // Keep active connections and listeners (skip TIME_WAIT/CLOSE noise)
        if !matches!(
            state.as_str(),
            "ESTABLISHED" | "LISTEN" | "SYN_SENT" | "SYN_RECV" | "CLOSE_WAIT"
        ) {
            continue;
        }

        let uid = cols[7].parse::<u32>().unwrap_or(0);
        let inode = cols[9].parse::<u64>().unwrap_or(0);
        let owner = owners.get(&inode);

        out.push(NetConnection {
            proto: proto.to_string(),
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            state,
            uid,
            inode,
            pid: owner.map(|o| o.pid),
            comm: owner.map(|o| o.comm.clone()).unwrap_or_default(),
            exe: owner.map(|o| o.exe.clone()).unwrap_or_default(),
            cmdline: owner.map(|o| o.cmdline.clone()).unwrap_or_default(),
            suspicious: false,
            suspicion_reason: String::new(),
        });
    }

    out
}

pub fn classify_connection(
    conn: &mut NetConnection,
    blocked_ips: &HashSet<String>,
) -> Option<NetSecurityAlert> {
    let local_addr = format!("{}:{}", conn.local_ip, conn.local_port);
    let remote_addr = format!("{}:{}", conn.remote_ip, conn.remote_port);

    // 1. Check if remote IP is in blocked-ips.conf
    if !conn.remote_ip.is_empty() && blocked_ips.contains(&conn.remote_ip) {
        conn.suspicious = true;
        conn.suspicion_reason = format!("Connection to blocked IP {}", conn.remote_ip);
        return Some(NetSecurityAlert {
            severity: "CRITICAL",
            rule_id: "NET_BLOCKED_IP_ACTIVE",
            pid: conn.pid,
            remote_ip: conn.remote_ip.clone(),
            local_addr,
            remote_addr,
            exe: conn.exe.clone(),
            summary: format!(
                "Active socket with blocked IP {} ({}:{} <-> {}:{}) owned by PID {:?} ({})",
                conn.remote_ip,
                conn.local_ip,
                conn.local_port,
                conn.remote_ip,
                conn.remote_port,
                conn.pid,
                conn.comm
            ),
            recommend_freeze: false,
            recommend_kill_socket: true,
        });
    }

    // 2. Shell or /tmp /dev/shm / memfd process holding an external network socket (Reverse Shell!)
    let is_loopback_remote =
        conn.remote_ip == "127.0.0.1" || conn.remote_ip == "::1" || conn.remote_ip == "0.0.0.0";
    let is_shell_comm = matches!(
        conn.comm.as_str(),
        "sh" | "bash" | "nu" | "dash" | "zsh" | "nc" | "ncat" | "socat" | "telnet"
    );
    let is_untrusted_exe = conn.exe.starts_with("/tmp/")
        || conn.exe.starts_with("/dev/shm/")
        || conn.exe.starts_with("/var/tmp/")
        || conn.exe.contains("memfd:");

    if conn.state == "ESTABLISHED" && !is_loopback_remote && (is_shell_comm || is_untrusted_exe) {
        conn.suspicious = true;
        conn.suspicion_reason =
            "Potential Reverse Shell / C2 beacon (shell or untrusted binary owns network socket)"
                .to_string();
        return Some(NetSecurityAlert {
            severity: "CRITICAL",
            rule_id: "NET_REVERSE_SHELL_SOCKET",
            pid: conn.pid,
            remote_ip: conn.remote_ip.clone(),
            local_addr,
            remote_addr,
            exe: conn.exe.clone(),
            summary: format!(
                "Reverse Shell / C2 suspected: PID {:?} ({} [{}]) has ESTABLISHED connection to {}:{}",
                conn.pid, conn.comm, conn.exe, conn.remote_ip, conn.remote_port
            ),
            recommend_freeze: true,
            recommend_kill_socket: true,
        });
    }

    // 3. Non-loopback TCP listener (potential backdoor service)
    let is_loopback_local = conn.local_ip == "127.0.0.1" || conn.local_ip == "::1";
    if conn.proto.starts_with("tcp") && conn.state == "LISTEN" && !is_loopback_local {
        conn.suspicious = true;
        conn.suspicion_reason = format!(
            "Exposed TCP listener on {}:{} (process '{}')",
            conn.local_ip, conn.local_port, conn.comm
        );
        return Some(NetSecurityAlert {
            severity: "HIGH",
            rule_id: "NET_EXPOSED_TCP_LISTENER",
            pid: conn.pid,
            remote_ip: String::new(),
            local_addr,
            remote_addr,
            exe: conn.exe.clone(),
            summary: format!(
                "Process '{}' (PID {:?}, exe='{}') opened external TCP listener on {}:{} (protected by inbound firewall, review recommended)",
                conn.comm, conn.pid, conn.exe, conn.local_ip, conn.local_port
            ),
            recommend_freeze: false,
            recommend_kill_socket: false,
        });
    }

    None
}

pub struct NetMonitor {
    alerted_keys: HashSet<String>,
}

impl NetMonitor {
    pub fn new() -> Self {
        Self {
            alerted_keys: HashSet::new(),
        }
    }

    pub fn scan(
        &mut self,
        blocked_ips: &HashSet<String>,
    ) -> (Vec<NetConnection>, Vec<NetSecurityAlert>) {
        let owners = build_inode_owner_map();
        let mut conns = Vec::new();
        conns.extend(parse_proc_net_table(
            "tcp",
            "/proc/net/tcp",
            false,
            &owners,
        ));
        conns.extend(parse_proc_net_table(
            "tcp6",
            "/proc/net/tcp6",
            true,
            &owners,
        ));
        conns.extend(parse_proc_net_table(
            "udp",
            "/proc/net/udp",
            false,
            &owners,
        ));

        let mut alerts = Vec::new();
        let mut active_keys = HashSet::new();

        for conn in &mut conns {
            if let Some(alert) = classify_connection(conn, blocked_ips) {
                let dedup_key = format!(
                    "{}:{}:{}:{}:{}:{:?}",
                    alert.rule_id,
                    conn.proto,
                    conn.local_ip,
                    conn.local_port,
                    conn.remote_ip,
                    conn.pid
                );
                active_keys.insert(dedup_key.clone());
                if self.alerted_keys.insert(dedup_key) {
                    alerts.push(alert);
                }
            }
        }

        // Prune closed sockets from dedup set so re-opened bad sockets trigger again
        self.alerted_keys.retain(|k| active_keys.contains(k));

        // Sort: suspicious first, then ESTABLISHED before LISTEN
        conns.sort_by(|a, b| {
            b.suspicious
                .cmp(&a.suspicious)
                .then_with(|| a.state.cmp(&b.state))
                .then_with(|| a.local_port.cmp(&b.local_port))
        });

        (conns, alerts)
    }
}

/// Immediately destroy an active IPv4 TCP socket inside the Linux kernel using
/// NETLINK_SOCK_DIAG + SOCK_DESTROY (21) (requires CONFIG_INET_DIAG_DESTROY=y, enabled in 6.18.32-serenity).
pub fn destroy_tcp_socket_v4(
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> Result<(), String> {
    let pkt = build_sock_destroy_packet_v4(local_ip, local_port, remote_ip, remote_port);

    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            NETLINK_SOCK_DIAG,
        )
    };
    if fd < 0 {
        return Err(format!(
            "socket(NETLINK_SOCK_DIAG) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;

    let sent = unsafe {
        libc::sendto(
            fd,
            &pkt as *const DestroyPacket as *const libc::c_void,
            std::mem::size_of::<DestroyPacket>(),
            0,
            &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(format!("sendto(SOCK_DESTROY) failed: {}", err));
    }

    let mut rbuf = [0u8; 256];
    let n = unsafe {
        libc::recv(
            fd,
            rbuf.as_mut_ptr() as *mut libc::c_void,
            rbuf.len(),
            0,
        )
    };
    unsafe {
        libc::close(fd);
    }

    if n < (std::mem::size_of::<NlMsgHdr>() + 4) as isize {
        return Err("short response from NETLINK_SOCK_DIAG".to_string());
    }
    let hdr: NlMsgHdr = unsafe { std::ptr::read_unaligned(rbuf.as_ptr() as *const NlMsgHdr) };
    if hdr.nlmsg_type == NLMSG_ERROR {
        let err_offset = std::mem::size_of::<NlMsgHdr>();
        let errno_neg = i32::from_ne_bytes([
            rbuf[err_offset],
            rbuf[err_offset + 1],
            rbuf[err_offset + 2],
            rbuf[err_offset + 3],
        ]);
        if errno_neg == 0 {
            return Ok(());
        }
        return Err(format!(
            "kernel SOCK_DESTROY returned errno {} ({})",
            -errno_neg,
            std::io::Error::from_raw_os_error(-errno_neg)
        ));
    }

    Ok(())
}

fn build_sock_destroy_packet_v4(
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> DestroyPacket {
    let src_be = u32::from_ne_bytes(local_ip.octets());
    let dst_be = u32::from_ne_bytes(remote_ip.octets());

    DestroyPacket {
        nlh: NlMsgHdr {
            nlmsg_len: std::mem::size_of::<DestroyPacket>() as u32,
            nlmsg_type: SOCK_DESTROY,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        },
        req: InetDiagReqV2 {
            sdiag_family: libc::AF_INET as u8,
            sdiag_protocol: libc::IPPROTO_TCP as u8,
            idiag_ext: 0,
            pad: 0,
            idiag_states: 1u32 << TCP_ESTABLISHED,
            id: InetDiagSockId {
                idiag_sport: local_port.to_be(),
                idiag_dport: remote_port.to_be(),
                idiag_src: [src_be, 0, 0, 0],
                idiag_dst: [dst_be, 0, 0, 0],
                idiag_if: 0,
                idiag_cookie: [INET_DIAG_NOCOOKIE, INET_DIAG_NOCOOKIE],
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_hex() {
        assert_eq!(parse_ipv4_hex("0100007F").as_deref(), Some("127.0.0.1"));
        assert_eq!(parse_ipv4_hex("0101A8C0").as_deref(), Some("192.168.1.1"));
    }

    #[test]
    fn test_classify_reverse_shell_socket() {
        let mut conn = NetConnection {
            proto: "tcp".to_string(),
            local_ip: "192.168.1.10".to_string(),
            local_port: 51234,
            remote_ip: "198.51.100.99".to_string(),
            remote_port: 4444,
            state: "ESTABLISHED".to_string(),
            uid: 1000,
            inode: 9999,
            pid: Some(31337),
            comm: "bash".to_string(),
            exe: "/usr/bin/bash".to_string(),
            cmdline: "bash -i".to_string(),
            suspicious: false,
            suspicion_reason: String::new(),
        };
        let blocked = HashSet::new();
        let alert = classify_connection(&mut conn, &blocked).expect("should detect reverse shell");
        assert!(conn.suspicious);
        assert_eq!(alert.severity, "CRITICAL");
        assert_eq!(alert.rule_id, "NET_REVERSE_SHELL_SOCKET");
        assert!(alert.recommend_freeze);
        assert!(alert.recommend_kill_socket);
    }

    #[test]
    fn test_sock_destroy_packet_layout() {
        let pkt = build_sock_destroy_packet_v4(
            Ipv4Addr::new(192, 168, 1, 10),
            51234,
            Ipv4Addr::new(198, 51, 100, 99),
            4444,
        );
        assert_eq!(pkt.nlh.nlmsg_len as usize, std::mem::size_of::<DestroyPacket>());
        assert_eq!(pkt.nlh.nlmsg_type, 21); // SOCK_DESTROY
        assert_eq!(pkt.req.id.idiag_sport, 51234u16.to_be());
        assert_eq!(pkt.req.id.idiag_dport, 4444u16.to_be());
    }
}
