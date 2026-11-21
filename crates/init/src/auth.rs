use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::FromRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{compiler_fence, Ordering};
use std::thread;
use std::time::Duration;

const SHADOW_PATH: &str = "/etc/shadow";
const SUDO_TS_DIR: &str = "/run/sudo-ts";
const SUDO_TS_TTL_SECS: i64 = 300;
pub const DEFAULT_ITERATIONS: u32 = 200_000;
const HASH_PREFIX: &str = "$pbkdf2-sha256$";

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

const SHA256_H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: pointer is valid and aligned for the slice lifetime; volatile prevents dead-store elimination.
        unsafe {
            std::ptr::write_volatile(b, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

fn zeroize_string(s: &mut String) {
    // SAFETY: writing zero bytes leaves valid UTF-8.
    unsafe {
        zeroize(s.as_bytes_mut());
    }
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        let j = i * 4;
        w[i] = u32::from_be_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
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

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[derive(Clone)]
struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: SHA256_H0,
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        let mut offset = 0;

        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            if data.len() < need {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buf[self.buf_len..64].copy_from_slice(&data[..need]);
            let block = self.buf;
            sha256_compress(&mut self.state, &block);
            self.buf_len = 0;
            offset = need;
        }

        while offset + 64 <= data.len() {
            let block: &[u8; 64] = data[offset..offset + 64]
                .try_into()
                .expect("64-byte slice");
            sha256_compress(&mut self.state, block);
            offset += 64;
        }

        let rem = data.len() - offset;
        if rem > 0 {
            self.buf[..rem].copy_from_slice(&data[offset..]);
            self.buf_len = rem;
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            self.buf[self.buf_len..64].fill(0);
            let block = self.buf;
            sha256_compress(&mut self.state, &block);
            self.buf_len = 0;
        }

        self.buf[self.buf_len..56].fill(0);
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buf;
        sha256_compress(&mut self.state, &block);

        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k_pad = [0u8; 64];
    if key.len() > 64 {
        let digest = sha256(key);
        k_pad[..32].copy_from_slice(&digest);
    } else {
        k_pad[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_pad[i];
        opad[i] ^= k_pad[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    let result = outer.finalize();

    zeroize(&mut k_pad);
    zeroize(&mut ipad);
    zeroize(&mut opad);
    result
}

pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    // Prepare HMAC key & precomputed inner/outer contexts once for all iterations.
    let mut k_pad = [0u8; 64];
    if password.len() > 64 {
        let digest = sha256(password);
        k_pad[..32].copy_from_slice(&digest);
    } else {
        k_pad[..password.len()].copy_from_slice(password);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_pad[i];
        opad[i] ^= k_pad[i];
    }

    let mut inner_base = Sha256::new();
    inner_base.update(&ipad);
    let mut outer_base = Sha256::new();
    outer_base.update(&opad);

    // Block index 1 (output is 32 bytes == SHA-256 block size).
    let mut first_inner = inner_base.clone();
    first_inner.update(salt);
    first_inner.update(&1u32.to_be_bytes());
    let d1 = first_inner.finalize();
    let mut first_outer = outer_base.clone();
    first_outer.update(&d1);
    let mut u = first_outer.finalize();
    let mut acc = u;

    for _ in 1..iterations {
        let mut hin = inner_base.clone();
        hin.update(&u);
        let din = hin.finalize();
        let mut hout = outer_base.clone();
        hout.update(&din);
        u = hout.finalize();
        for (a, &b) in acc.iter_mut().zip(u.iter()) {
            *a ^= b;
        }
    }

    zeroize(&mut k_pad);
    zeroize(&mut ipad);
    zeroize(&mut opad);
    zeroize(&mut u);
    acc
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let val = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        out.push((val(pair[0])? << 4) | val(pair[1])?);
    }
    Some(out)
}

fn random_bytes(out: &mut [u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < out.len() {
        let n = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                out[offset..].as_mut_ptr(),
                out.len() - offset,
                0 as libc::c_uint,
            )
        };
        if n > 0 {
            offset += n as usize;
            continue;
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if err.raw_os_error() == Some(libc::ENOSYS) {
            let mut urandom = File::open("/dev/urandom")?;
            urandom.read_exact(&mut out[offset..])?;
            return Ok(());
        }
        return Err(err);
    }
    Ok(())
}

pub fn hash_password_with_iters(password: &[u8], salt: &[u8], iterations: u32) -> String {
    let mut dk = pbkdf2_hmac_sha256(password, salt, iterations);
    let formatted = format!(
        "{}{}${}${}",
        HASH_PREFIX,
        iterations,
        hex_encode(salt),
        hex_encode(&dk)
    );
    zeroize(&mut dk);
    formatted
}

pub fn hash_password(password: &[u8]) -> io::Result<String> {
    let mut salt = [0u8; 16];
    random_bytes(&mut salt)?;
    Ok(hash_password_with_iters(password, &salt, DEFAULT_ITERATIONS))
}

fn parse_hash_fields(stored: &str) -> Option<(u32, Vec<u8>, Vec<u8>)> {
    let rest = stored.strip_prefix(HASH_PREFIX)?;
    let mut parts = rest.split('$');
    let iters_s = parts.next()?;
    let salt_hex = parts.next()?;
    let dk_hex = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let iterations: u32 = iters_s.parse().ok()?;
    if iterations == 0 || iterations > 10_000_000 {
        return None;
    }
    let salt = hex_decode(salt_hex)?;
    let dk = hex_decode(dk_hex)?;
    if salt.is_empty() || dk.len() != 32 {
        return None;
    }
    Some((iterations, salt, dk))
}

pub fn verify_password(password: &[u8], stored: &str) -> bool {
    let Some((iterations, salt, expected_dk)) = parse_hash_fields(stored) else {
        return false;
    };
    let mut actual_dk = pbkdf2_hmac_sha256(password, &salt, iterations);
    let matched = ct_eq(&actual_dk, &expected_dk);
    zeroize(&mut actual_dk);
    matched
}

fn shadow_hash_for_user(content: &str, user: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut fields = trimmed.split(':');
        if fields.next() == Some(user) {
            return fields.next().map(str::to_string);
        }
    }
    None
}

pub fn has_password(user: &str) -> bool {
    let Ok(content) = fs::read_to_string(SHADOW_PATH) else {
        return false;
    };
    let Some(hash) = shadow_hash_for_user(&content, user) else {
        return false;
    };
    parse_hash_fields(&hash).is_some()
}

pub fn verify_user_password(user: &str, password: &[u8]) -> bool {
    let Ok(content) = fs::read_to_string(SHADOW_PATH) else {
        return false;
    };
    let Some(hash) = shadow_hash_for_user(&content, user) else {
        return false;
    };
    verify_password(password, &hash)
}

pub fn update_shadow_content(existing: &str, user: &str, hash: &str) -> String {
    let new_entry = format!("{}:{}:19700:0:99999:7:::", user, hash);
    let mut lines: Vec<String> = Vec::new();
    let mut replaced = false;

    for line in existing.lines() {
        if line.is_empty() {
            continue;
        }
        if line.split(':').next() == Some(user) {
            if !replaced {
                lines.push(new_entry.clone());
                replaced = true;
            }
        } else {
            lines.push(line.to_string());
        }
    }
    if !replaced {
        lines.push(new_entry);
    }

    let mut out = lines.join("\n");
    out.push('\n');
    out
}

fn write_root_only_atomic(path: &Path, content: &[u8]) -> io::Result<()> {
    let tmp_name = format!(
        "{}.serenity-new",
        path.file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid filename"))?
    );
    let tmp_path = path.with_file_name(tmp_name);
    let c_tmp = CString::new(tmp_path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interior NUL in path"))?;

    let fd = unsafe {
        libc::open(
            c_tmp.as_ptr(),
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC | libc::O_NOFOLLOW,
            0o600 as libc::mode_t,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let write_res = (|| -> io::Result<()> {
        if unsafe { libc::fchown(fd, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fchmod(fd, 0o600) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is an exclusively opened file descriptor owned by this scope.
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(content)?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    fs::rename(&tmp_path, path)
}

pub fn set_user_password(user: &str, password: &[u8]) -> io::Result<()> {
    let hash = hash_password(password)?;
    let existing = match fs::read_to_string(SHADOW_PATH) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    let updated = update_shadow_content(&existing, user, &hash);
    write_root_only_atomic(Path::new(SHADOW_PATH), updated.as_bytes())
}

struct TermiosGuard {
    fd: libc::c_int,
    orig: libc::termios,
}

impl Drop for TermiosGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.orig);
        }
    }
}

fn write_all_fd(fd: libc::c_int, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        let n = unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) };
        if n > 0 {
            data = &data[n as usize..];
            continue;
        }
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "short write to tty"));
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
    Ok(())
}

pub fn read_password_from_fd(fd: libc::c_int, prompt: &str) -> io::Result<Option<String>> {
    unsafe {
        libc::tcflush(fd, libc::TCIFLUSH);
    }

    let mut orig: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut orig) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut no_echo = orig;
    no_echo.c_lflag &= !(libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ECHONL);
    no_echo.c_lflag |= libc::ICANON;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &no_echo) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let _guard = TermiosGuard { fd, orig };

    write_all_fd(fd, prompt.as_bytes())?;

    let mut buf: Vec<u8> = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let n = unsafe { libc::read(fd, byte.as_mut_ptr() as *mut libc::c_void, 1) };
        if n < 0 {
            let err = io::Error::last_os_error();
            zeroize(&mut buf);
            return Err(err);
        }
        if n == 0 {
            if buf.is_empty() {
                let _ = write_all_fd(fd, b"\n");
                return Ok(None);
            }
            break;
        }
        if byte[0] == b'\n' || byte[0] == b'\r' {
            break;
        }
        if buf.len() < 256 {
            buf.push(byte[0]);
        }
    }
    zeroize(&mut byte);

    let _ = write_all_fd(fd, b"\n");

    match String::from_utf8(buf) {
        Ok(s) => Ok(Some(s)),
        Err(e) => {
            let mut raw = e.into_bytes();
            zeroize(&mut raw);
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "password contains invalid UTF-8",
            ))
        }
    }
}

pub fn read_password_tty(prompt: &str) -> io::Result<Option<String>> {
    let fd = unsafe {
        libc::open(
            b"/dev/tty\0".as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_NOCTTY,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let res = read_password_from_fd(fd, prompt);
    unsafe {
        libc::close(fd);
    }
    res
}

fn ensure_ts_dir() -> io::Result<()> {
    match fs::create_dir(SUDO_TS_DIR) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }

    let c_dir = CString::new(SUDO_TS_DIR).expect("static path has no NUL");
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(c_dir.as_ptr(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "/run/sudo-ts is not a directory",
        ));
    }

    if unsafe { libc::chown(c_dir.as_ptr(), 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::chmod(c_dir.as_ptr(), 0o700) } != 0 {
        return Err(io::Error::last_os_error());
    }

    if unsafe { libc::lstat(c_dir.as_ptr(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR
        || st.st_uid != 0
        || st.st_gid != 0
        || (st.st_mode & 0o077) != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe ownership/permissions on /run/sudo-ts",
        ));
    }
    Ok(())
}

fn controlling_tty_rdev() -> Option<u64> {
    let fd = unsafe {
        libc::open(
            b"/dev/tty\0".as_ptr() as *const libc::c_char,
            libc::O_RDONLY | libc::O_NOCTTY,
        )
    };
    if fd < 0 {
        return None;
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut st) };
    let is_tty = unsafe { libc::isatty(fd) } == 1;
    unsafe {
        libc::close(fd);
    }
    if rc != 0 || !is_tty || (st.st_mode & libc::S_IFMT) != libc::S_IFCHR {
        return None;
    }
    Some(st.st_rdev as u64)
}

fn ts_token_path(uid: libc::uid_t) -> Option<PathBuf> {
    let rdev = controlling_tty_rdev()?;
    let sid = unsafe { libc::getsid(0) };
    if sid <= 0 {
        return None;
    }
    Some(PathBuf::from(format!("{}/{}-{}-{}", SUDO_TS_DIR, uid, rdev, sid)))
}

fn monotonic_boot_secs() -> Option<i64> {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) } == 0 {
        Some(ts.tv_sec as i64)
    } else {
        None
    }
}

pub fn check_sudo_timestamp(uid: libc::uid_t) -> bool {
    if ensure_ts_dir().is_err() {
        return false;
    }
    let Some(path) = ts_token_path(uid) else {
        return false;
    };
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };

    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW) };
    if fd < 0 {
        return false;
    }

    let valid = (|| -> Option<bool> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return None;
        }
        if st.st_uid != 0
            || st.st_gid != 0
            || (st.st_mode & libc::S_IFMT) != libc::S_IFREG
            || (st.st_mode & 0o077) != 0
        {
            return None;
        }
        let mut buf = [0u8; 64];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            return None;
        }
        let text = std::str::from_utf8(&buf[..n as usize]).ok()?.trim();
        let saved_secs: i64 = text.parse().ok()?;
        let now = monotonic_boot_secs()?;
        Some(now >= saved_secs && (now - saved_secs) < SUDO_TS_TTL_SECS)
    })();

    unsafe {
        libc::close(fd);
    }
    valid.unwrap_or(false)
}

pub fn update_sudo_timestamp(uid: libc::uid_t) {
    if ensure_ts_dir().is_err() {
        return;
    }
    let Some(path) = ts_token_path(uid) else {
        return;
    };
    let Some(now) = monotonic_boot_secs() else {
        return;
    };
    let payload = format!("{}\n", now);
    let _ = write_root_only_atomic(&path, payload.as_bytes());
}

pub fn clear_sudo_timestamp(uid: libc::uid_t) {
    if ensure_ts_dir().is_err() {
        return;
    }
    if let Some(path) = ts_token_path(uid) {
        let _ = fs::remove_file(path);
    }
}

pub fn clear_all_sudo_timestamps() {
    if ensure_ts_dir().is_err() {
        return;
    }
    if let Ok(entries) = fs::read_dir(SUDO_TS_DIR) {
        for entry in entries.flatten() {
            let _ = fs::remove_file(entry.path());
        }
    }
}

pub fn sanitize_sudo_env() {
    const DANGEROUS_VARS: &[&str] = &[
        "GCONV_PATH",
        "GETCONF_DIR",
        "HOSTALIASES",
        "LOCALDOMAIN",
        "LOCPATH",
        "MALLOC_TRACE",
        "NIS_PATH",
        "NLSPATH",
        "RESOLV_HOST_CONF",
        "RES_OPTIONS",
        "TMPDIR",
        "TZDIR",
        "BASH_ENV",
        "ENV",
        "CDPATH",
        "SHELLOPTS",
        "BASHOPTS",
        "PS4",
        "IFS",
        "PYTHONPATH",
        "PERL5OPT",
        "PERL5LIB",
        "RUBYOPT",
    ];

    let to_remove: Vec<_> = std::env::vars_os()
        .filter_map(|(k, _)| {
            let ks = k.to_str()?;
            if ks.starts_with("LD_") || DANGEROUS_VARS.contains(&ks) {
                Some(k)
            } else {
                None
            }
        })
        .collect();

    for k in to_remove {
        std::env::remove_var(k);
    }
}

pub fn run_passwd_applet() -> ! {
    let ruid = unsafe { libc::getuid() };
    if ruid != 0 && ruid != 1000 {
        eprintln!("passwd: permission denied (uid {})", ruid);
        std::process::exit(1);
    }

    let args: Vec<String> = std::env::args().skip(1).collect();
    let target = match args.as_slice() {
        [] => {
            if ruid == 0 {
                "root"
            } else {
                "serenity"
            }
        }
        [user] if !user.starts_with('-') => {
            if user != "serenity" && user != "root" {
                eprintln!("passwd: unknown user '{}'", user);
                std::process::exit(1);
            }
            if ruid != 0 && user != "serenity" {
                eprintln!("passwd: you may not modify password information for '{}'.", user);
                std::process::exit(1);
            }
            user.as_str()
        }
        _ => {
            eprintln!("Usage: passwd [serenity|root]");
            std::process::exit(1);
        }
    };

    if ruid == 1000 && has_password("serenity") {
        match read_password_tty("Current password: ") {
            Ok(Some(mut cur)) => {
                let valid = verify_user_password("serenity", cur.as_bytes());
                zeroize_string(&mut cur);
                if !valid {
                    thread::sleep(Duration::from_millis(1500));
                    eprintln!("passwd: Authentication token manipulation error.");
                    std::process::exit(1);
                }
            }
            Ok(None) => {
                eprintln!("passwd: no password supplied.");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("passwd: failed to read password from terminal: {}", e);
                std::process::exit(1);
            }
        }
    }

    let mut pw1 = match read_password_tty("New password: ") {
        Ok(Some(pw)) => pw,
        Ok(None) => {
            eprintln!("passwd: password unchanged.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("passwd: failed to read new password from terminal: {}", e);
            std::process::exit(1);
        }
    };

    if pw1.is_empty() || pw1.len() < 4 {
        zeroize_string(&mut pw1);
        eprintln!("passwd: password must be at least 4 characters.");
        std::process::exit(1);
    }

    let mut pw2 = match read_password_tty("Retype new password: ") {
        Ok(Some(pw)) => pw,
        Ok(None) => {
            zeroize_string(&mut pw1);
            eprintln!("passwd: passwords do not match.");
            std::process::exit(1);
        }
        Err(e) => {
            zeroize_string(&mut pw1);
            eprintln!("passwd: failed to read confirmation password: {}", e);
            std::process::exit(1);
        }
    };

    let matched = ct_eq(pw1.as_bytes(), pw2.as_bytes());
    zeroize_string(&mut pw2);
    if !matched {
        zeroize_string(&mut pw1);
        eprintln!("passwd: Sorry, passwords do not match.");
        std::process::exit(1);
    }

    let res = set_user_password(target, pw1.as_bytes());
    zeroize_string(&mut pw1);

    if let Err(e) = res {
        eprintln!("passwd: failed to update /etc/shadow: {}", e);
        std::process::exit(1);
    }

    clear_all_sudo_timestamps();
    println!("passwd: password updated successfully for {}.", target);
    std::process::exit(0);
}

pub fn run_sudo_applet() -> ! {
    let mut flag_k = false;
    let mut flag_v = false;
    let mut flag_h = false;
    let mut cmd_args: Vec<String> = Vec::new();

    let mut raw_args = std::env::args().skip(1);
    while let Some(arg) = raw_args.next() {
        match arg.as_str() {
            "-k" => flag_k = true,
            "-v" => flag_v = true,
            "-E" => {} // accepted for compatibility; dangerous loader/shell vars are still stripped
            "-H" => flag_h = true,
            "--" => {
                cmd_args.extend(raw_args);
                break;
            }
            s if s.starts_with('-') => {
                eprintln!("sudo: unknown option '{}'", s);
                eprintln!("Usage: sudo [-k|-v|-E|-H] <command> [args...]");
                std::process::exit(1);
            }
            _ => {
                cmd_args.push(arg);
                cmd_args.extend(raw_args);
                break;
            }
        }
    }

    let ruid = unsafe { libc::getuid() };
    // Only allow root (0) or primary desktop user 'serenity' (1000)
    if ruid != 0 && ruid != 1000 {
        eprintln!("sudo: permission denied (uid {})", ruid);
        std::process::exit(1);
    }

    if flag_k && ruid == 1000 {
        clear_sudo_timestamp(ruid);
        if cmd_args.is_empty() && !flag_v {
            std::process::exit(0);
        }
    }

    if cmd_args.is_empty() && !flag_v {
        eprintln!("Usage: sudo [-k|-v|-E|-H] <command> [args...]");
        std::process::exit(1);
    }

    if ruid == 1000 {
        if has_password("serenity") {
            let needs_prompt = flag_k || !check_sudo_timestamp(ruid);
            if needs_prompt {
                let mut authed = false;
                for attempt in 0..3 {
                    match read_password_tty("[sudo] password for serenity: ") {
                        Ok(Some(mut pw)) => {
                            let ok = verify_user_password("serenity", pw.as_bytes());
                            zeroize_string(&mut pw);
                            if ok {
                                update_sudo_timestamp(ruid);
                                authed = true;
                                break;
                            }
                            thread::sleep(Duration::from_millis(1500));
                            if attempt < 2 {
                                eprintln!("Sorry, try again.");
                            } else {
                                eprintln!("sudo: 3 incorrect password attempts");
                            }
                        }
                        Ok(None) => {
                            eprintln!("sudo: 1 incorrect password attempt");
                            std::process::exit(1);
                        }
                        Err(e) => {
                            eprintln!("sudo: a terminal is required to read the password ({})", e);
                            std::process::exit(1);
                        }
                    }
                }
                if !authed {
                    std::process::exit(1);
                }
            } else if flag_v {
                update_sudo_timestamp(ruid);
            }
        } else {
            eprintln!("[sudo] WARNING: no password set for 'serenity' — run 'passwd' to protect sudo.");
        }
    }

    if flag_v && cmd_args.is_empty() {
        std::process::exit(0);
    }

    sanitize_sudo_env();

    unsafe {
        let root_gid: libc::gid_t = 0;
        libc::setgroups(1, &root_gid);
        if libc::setgid(0) != 0 || libc::setuid(0) != 0 {
            eprintln!("sudo: failed to escalate privileges: {}", io::Error::last_os_error());
            std::process::exit(1);
        }
    }

    std::env::set_var("USER", "root");
    std::env::set_var("LOGNAME", "root");
    std::env::set_var(
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );
    if flag_h {
        std::env::set_var("HOME", "/root");
    }

    let err = Command::new(&cmd_args[0]).args(&cmd_args[1..]).exec();
    eprintln!("sudo: {}: {}", cmd_args[0], err);
    std::process::exit(127);
}

fn open_login_tty() -> Option<(libc::c_int, &'static str)> {
    for (dev, name) in [
        (b"/dev/tty1\0".as_slice(), "tty1"),
        (b"/dev/tty0\0".as_slice(), "tty0"),
        (b"/dev/console\0".as_slice(), "console"),
    ] {
        let fd = unsafe { libc::open(dev.as_ptr() as *const libc::c_char, libc::O_RDWR | libc::O_NOCTTY) };
        if fd >= 0 {
            return Some((fd, name));
        }
    }
    None
}

pub fn tty_login_gate(user: &str, on_interrupt: fn()) {
    let (fd, tty_name) = loop {
        on_interrupt();
        if let Some(opened) = open_login_tty() {
            break opened;
        }
        thread::sleep(Duration::from_millis(500));
    };

    let header = format!(
        "\nSerenity Linux 0.1.0 ({})\nLogin required for '{}' (Ctrl+Alt+Del to reboot)\n\n",
        tty_name, user
    );
    let _ = write_all_fd(fd, header.as_bytes());
    let prompt = format!("Password for {}: ", user);

    loop {
        on_interrupt();
        match read_password_from_fd(fd, &prompt) {
            Ok(Some(mut pw)) => {
                let valid = verify_user_password(user, pw.as_bytes());
                zeroize_string(&mut pw);
                if valid {
                    unsafe {
                        libc::close(fd);
                    }
                    return;
                }
                let _ = write_all_fd(fd, b"Authentication failed.\n");
                thread::sleep(Duration::from_millis(1500));
                on_interrupt();
            }
            Ok(None) => {
                thread::sleep(Duration::from_millis(200));
                on_interrupt();
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                on_interrupt();
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(500));
                on_interrupt();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_fips_vectors() {
        assert_eq!(
            hex_encode(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_encode(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex_encode(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn hmac_sha256_rfc4231_vectors() {
        // Test Case 1
        assert_eq!(
            hex_encode(&hmac_sha256(&[0x0bu8; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // Test Case 2
        assert_eq!(
            hex_encode(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn pbkdf2_hmac_sha256_rfc7914_vectors() {
        assert_eq!(
            hex_encode(&pbkdf2_hmac_sha256(b"password", b"salt", 1)),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
        assert_eq!(
            hex_encode(&pbkdf2_hmac_sha256(b"password", b"salt", 2)),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
        );
        assert_eq!(
            hex_encode(&pbkdf2_hmac_sha256(b"password", b"salt", 4096)),
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
        );
    }

    #[test]
    fn password_hash_and_verify_roundtrip() {
        let hash = hash_password_with_iters(b"s3r3n1ty!", b"0123456789abcdef", 1000);
        assert!(hash.starts_with("$pbkdf2-sha256$1000$"));
        assert!(verify_password(b"s3r3n1ty!", &hash));
        assert!(!verify_password(b"wrong", &hash));
        assert!(!verify_password(b"s3r3n1ty!", "$pbkdf2-sha256$0$aa$bb"));
        assert!(!verify_password(b"s3r3n1ty!", "invalid-format"));
    }

    #[test]
    fn update_shadow_preserves_and_replaces_entries() {
        let initial = "root:$pbkdf2-sha256$1000$aa$00:19700:0:99999:7:::\n";
        let added = update_shadow_content(initial, "serenity", "HASH1");
        assert!(added.contains("root:$pbkdf2-sha256$1000$aa$00:19700:0:99999:7:::\n"));
        assert!(added.contains("serenity:HASH1:19700:0:99999:7:::\n"));

        let replaced = update_shadow_content(&added, "serenity", "HASH2");
        assert!(!replaced.contains("HASH1"));
        assert!(replaced.contains("serenity:HASH2:19700:0:99999:7:::\n"));
        assert_eq!(shadow_hash_for_user(&replaced, "serenity").as_deref(), Some("HASH2"));
        assert_eq!(
            shadow_hash_for_user(&replaced, "root").as_deref(),
            Some("$pbkdf2-sha256$1000$aa$00")
        );
    }

    #[test]
    fn constant_time_eq_checks() {
        assert!(ct_eq(b"hello", b"hello"));
        assert!(!ct_eq(b"hello", b"hellp"));
        assert!(!ct_eq(b"hello", b"hell"));
    }
}
