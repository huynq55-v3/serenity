use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::path::Path;

pub const WATCHED_FILES: &[&str] = &[
    "/init",
    "/usr/bin/spkg",
    "/usr/bin/serenity-fw",
    "/usr/bin/serenity-guard",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/resolv.conf",
    "/etc/serenity/blocked-ips.conf",
    "/usr/share/dbus-1/system.conf",
];

const TRUSTED_UPDATERS: &[&str] = &[
    "/usr/bin/spkg",
    "/usr/bin/serenity-fw",
    "/usr/bin/serenity-guard",
    "/init",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimEntry {
    pub path: String,
    pub exists: bool,
    pub baseline_sha256: String,
    pub current_sha256: String,
    pub size_bytes: u64,
    pub mode_octal: String,
    pub status: String, // "OK", "MODIFIED", "DELETED", "CREATED", "MISSING"
    pub last_modified_by_pid: Option<i32>,
    pub last_modified_by_exe: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FimAlert {
    pub severity: &'static str,
    pub rule_id: &'static str,
    pub path: String,
    pub old_hash: String,
    pub new_hash: String,
    pub actor_pid: Option<i32>,
    pub actor_exe: Option<String>,
    pub summary: String,
}

// Pure-Rust FIPS 180-4 SHA-256 implementation (zero external crate dependencies)
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            for b in &mut self.buf[self.buf_len..64] {
                *b = 0;
            }
            let block = self.buf;
            self.compress(&block);
            self.buf_len = 0;
        }
        for b in &mut self.buf[self.buf_len..56] {
            *b = 0;
        }
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buf;
        self.compress(&block);

        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

pub fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex_encode(&hasher.finalize())
}

pub fn sha256_file(path: &Path) -> Option<(String, u64, String)> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let mut file = fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 16384];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let mode_octal = format!("{:04o}", meta.mode() & 0o7777);
    Some((hex_encode(&hasher.finalize()), meta.len(), mode_octal))
}

pub struct FimMonitor {
    entries: HashMap<String, FimEntry>,
    fanotify_fd: i32,
    recent_writer: HashMap<String, (i32, String)>,
}

// Linux fanotify constants (x86_64)
const SYS_FANOTIFY_INIT: libc::c_long = 300;
const SYS_FANOTIFY_MARK: libc::c_long = 301;

const FAN_CLASS_NOTIF: libc::c_uint = 0x0000_0000;
const FAN_CLOEXEC: libc::c_uint = 0x0000_0001;
const FAN_NONBLOCK: libc::c_uint = 0x0000_0002;

const FAN_MARK_ADD: libc::c_uint = 0x0000_0001;
const FAN_MODIFY: u64 = 0x0000_0002;
const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
const FAN_EVENT_ON_CHILD: u64 = 0x0800_0000;

#[repr(C)]
#[derive(Clone, Copy)]
struct FanotifyEventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

impl FimMonitor {
    pub fn new() -> Self {
        let fanotify_fd = Self::init_fanotify();
        let mut mon = Self {
            entries: HashMap::new(),
            fanotify_fd,
            recent_writer: HashMap::new(),
        };
        mon.rebaseline();
        mon
    }

    fn init_fanotify() -> i32 {
        let flags = FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK;
        let event_f_flags = (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as libc::c_uint;
        let fd = unsafe { libc::syscall(SYS_FANOTIFY_INIT, flags, event_f_flags) as i32 };
        if fd < 0 {
            return -1;
        }
        Self::refresh_marks(fd);
        fd
    }

    fn refresh_marks(fd: i32) {
        if fd < 0 {
            return;
        }
        let mask: u64 = FAN_CLOSE_WRITE | FAN_MODIFY | FAN_EVENT_ON_CHILD;
        for &path in WATCHED_FILES {
            if let Ok(c_path) = CString::new(path) {
                unsafe {
                    let _ = libc::syscall(
                        SYS_FANOTIFY_MARK,
                        fd,
                        FAN_MARK_ADD,
                        mask,
                        libc::AT_FDCWD,
                        c_path.as_ptr(),
                    );
                }
            }
        }
        // Also watch parent directories (/etc, /etc/serenity) to catch atomic rename writers
        for dir in ["/etc", "/etc/serenity", "/usr/bin"] {
            if let Ok(c_dir) = CString::new(dir) {
                unsafe {
                    let _ = libc::syscall(
                        SYS_FANOTIFY_MARK,
                        fd,
                        FAN_MARK_ADD,
                        mask,
                        libc::AT_FDCWD,
                        c_dir.as_ptr(),
                    );
                }
            }
        }
    }

    pub fn rebaseline(&mut self) {
        self.entries.clear();
        for &path in WATCHED_FILES {
            let p = Path::new(path);
            let entry = if let Some((hash, size, mode)) = sha256_file(p) {
                FimEntry {
                    path: path.to_string(),
                    exists: true,
                    baseline_sha256: hash.clone(),
                    current_sha256: hash,
                    size_bytes: size,
                    mode_octal: mode,
                    status: "OK".to_string(),
                    last_modified_by_pid: None,
                    last_modified_by_exe: None,
                }
            } else {
                FimEntry {
                    path: path.to_string(),
                    exists: false,
                    baseline_sha256: String::new(),
                    current_sha256: String::new(),
                    size_bytes: 0,
                    mode_octal: String::new(),
                    status: "MISSING".to_string(),
                    last_modified_by_pid: None,
                    last_modified_by_exe: None,
                }
            };
            self.entries.insert(path.to_string(), entry);
        }
        Self::refresh_marks(self.fanotify_fd);
    }

    pub fn snapshot(&self) -> Vec<FimEntry> {
        let mut out: Vec<FimEntry> = WATCHED_FILES
            .iter()
            .filter_map(|&p| self.entries.get(p).cloned())
            .collect();
        out.sort_by(|a, b| a.path.cmp(&b.path));
        out
    }

    fn drain_fanotify_events(&mut self) {
        if self.fanotify_fd < 0 {
            return;
        }
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe {
                libc::read(
                    self.fanotify_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n <= 0 {
                break;
            }
            let n = n as usize;
            let mut offset = 0usize;
            while offset + std::mem::size_of::<FanotifyEventMetadata>() <= n {
                let meta: FanotifyEventMetadata = unsafe {
                    std::ptr::read_unaligned(
                        buf[offset..].as_ptr() as *const FanotifyEventMetadata
                    )
                };
                if meta.event_len < std::mem::size_of::<FanotifyEventMetadata>() as u32 {
                    break;
                }
                if meta.fd >= 0 {
                    let fd_link = format!("/proc/self/fd/{}", meta.fd);
                    if let Ok(target) = fs::read_link(&fd_link) {
                        let target_str = target
                            .to_string_lossy()
                            .trim_end_matches(" (deleted)")
                            .to_string();
                        let exe = fs::read_link(format!("/proc/{}/exe", meta.pid))
                            .ok()
                            .map(|p| p.to_string_lossy().into_owned())
                            .or_else(|| {
                                fs::read_to_string(format!("/proc/{}/comm", meta.pid))
                                    .ok()
                                    .map(|s| s.trim().to_string())
                            })
                            .unwrap_or_else(|| "unknown".to_string());
                        self.recent_writer
                            .insert(target_str, (meta.pid, exe));
                    }
                    unsafe {
                        libc::close(meta.fd);
                    }
                }
                offset += meta.event_len as usize;
            }
        }
    }

    pub fn poll_changes(&mut self) -> Vec<FimAlert> {
        self.drain_fanotify_events();
        let mut alerts = Vec::new();

        for &path in WATCHED_FILES {
            let p = Path::new(path);
            let current = sha256_file(p);
            let Some(entry) = self.entries.get_mut(path) else {
                continue;
            };

            match (entry.exists, current) {
                (true, Some((new_hash, size, mode))) => {
                    entry.size_bytes = size;
                    entry.mode_octal = mode;
                    if new_hash != entry.current_sha256 {
                        let old_hash = entry.current_sha256.clone();
                        entry.current_sha256 = new_hash.clone();
                        let writer = self.recent_writer.remove(path);
                        let (actor_pid, actor_exe) = match writer {
                            Some((pid, exe)) => (Some(pid), Some(exe)),
                            None => (None, None),
                        };
                        entry.last_modified_by_pid = actor_pid;
                        entry.last_modified_by_exe = actor_exe.clone();

                        let trusted = actor_exe
                            .as_deref()
                            .map(|e| TRUSTED_UPDATERS.iter().any(|&t| e == t))
                            .unwrap_or(false);

                        if new_hash == entry.baseline_sha256 {
                            entry.status = "OK".to_string();
                        } else {
                            entry.status = "MODIFIED".to_string();
                        }

                        let severity = if trusted && path == "/etc/serenity/blocked-ips.conf" {
                            "INFO"
                        } else if trusted {
                            "HIGH"
                        } else {
                            "CRITICAL"
                        };

                        let actor_desc = match (actor_pid, actor_exe.as_deref()) {
                            (Some(pid), Some(exe)) => format!(" by PID {} ({})", pid, exe),
                            _ => String::new(),
                        };

                        alerts.push(FimAlert {
                            severity,
                            rule_id: "FIM_CORE_FILE_MODIFIED",
                            path: path.to_string(),
                            old_hash: old_hash.chars().take(16).collect(),
                            new_hash: new_hash.chars().take(16).collect(),
                            actor_pid,
                            actor_exe,
                            summary: format!(
                                "Core file '{}' modified{} (sha256: {}.. -> {}..)",
                                path,
                                actor_desc,
                                &old_hash[..old_hash.len().min(12)],
                                &new_hash[..new_hash.len().min(12)]
                            ),
                        });
                        Self::refresh_marks(self.fanotify_fd);
                    }
                }
                (true, None) => {
                    entry.exists = false;
                    let old_hash = entry.current_sha256.clone();
                    entry.current_sha256.clear();
                    entry.status = "DELETED".to_string();
                    alerts.push(FimAlert {
                        severity: "CRITICAL",
                        rule_id: "FIM_CORE_FILE_DELETED",
                        path: path.to_string(),
                        old_hash,
                        new_hash: String::new(),
                        actor_pid: None,
                        actor_exe: None,
                        summary: format!("CRITICAL: Core system file '{}' was DELETED!", path),
                    });
                }
                (false, Some((new_hash, size, mode))) => {
                    entry.exists = true;
                    entry.size_bytes = size;
                    entry.mode_octal = mode;
                    if entry.baseline_sha256.is_empty() {
                        entry.baseline_sha256 = new_hash.clone();
                        entry.status = "OK".to_string();
                    } else if entry.baseline_sha256 == new_hash {
                        entry.status = "OK".to_string();
                    } else {
                        entry.status = "CREATED".to_string();
                    }
                    entry.current_sha256 = new_hash.clone();
                    alerts.push(FimAlert {
                        severity: "INFO",
                        rule_id: "FIM_CORE_FILE_CREATED",
                        path: path.to_string(),
                        old_hash: String::new(),
                        new_hash: new_hash.chars().take(16).collect(),
                        actor_pid: None,
                        actor_exe: None,
                        summary: format!(
                            "Core system file '{}' created (sha256: {}..)",
                            path,
                            &new_hash[..new_hash.len().min(12)]
                        ),
                    });
                    Self::refresh_marks(self.fanotify_fd);
                }
                (false, None) => {}
            }
        }

        alerts
    }
}

impl Drop for FimMonitor {
    fn drop(&mut self) {
        if self.fanotify_fd >= 0 {
            unsafe {
                libc::close(self.fanotify_fd);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_vectors() {
        assert_eq!(
            sha256_bytes(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_bytes(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }
}
