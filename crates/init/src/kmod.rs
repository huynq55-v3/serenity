//! Kernel driver loading for Serenity PID 1.
//!
//! Primary path (when the `kmod` + `linux` packages are installed):
//!   * coldplug: read every `modalias` file under /sys/devices and hand them to
//!     `modprobe -a -b -q`, which resolves them through /lib/modules/$(uname -r)/modules.alias.
//!     Repeated a few times because loading a bus driver (PCI -> I2C, USB hub, ...)
//!     exposes new child devices with their own modalias.
//!   * hotplug: a thread listens on the kernel uevent netlink socket and runs
//!     `modprobe -b -q <MODALIAS>` for every `ACTION=add` (USB, Thunderbolt, Bluetooth...).
//!   * /etc/serenity/modules.load lines that are bare module names are modprobe'd too
//!     (for drivers without a modalias, e.g. `tcp_bbr`).
//!
//! Legacy fallback (no modprobe or no modules.alias): load the absolute `.ko` paths
//! listed in /etc/serenity/modules.load via finit_module(2), like before.

use std::collections::HashSet;
use std::ffi::CStr;
use std::fs::{self, File};
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

const MODULES_LOAD_PATH: &str = "/etc/serenity/modules.load";
const MODPROBE: &str = "/sbin/modprobe";
const COLDPLUG_PASSES: usize = 4;
const MODPROBE_BATCH: usize = 256;

pub fn kernel_release() -> String {
    unsafe {
        let mut uts: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut uts) != 0 {
            return String::new();
        }
        CStr::from_ptr(uts.release.as_ptr()).to_string_lossy().into_owned()
    }
}

fn modules_dir() -> PathBuf {
    Path::new("/lib/modules").join(kernel_release())
}

/// True when kmod's modprobe and a depmod'ed module tree for the running kernel exist.
pub fn modprobe_available() -> bool {
    Path::new(MODPROBE).exists() && modules_dir().join("modules.alias").exists()
}

/// Count of currently loaded modules (lines of /proc/modules).
fn loaded_module_count() -> usize {
    fs::read_to_string("/proc/modules")
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

/// Opens the kernel uevent netlink socket early, so events emitted while coldplug
/// runs are buffered instead of lost. Returns None if netlink is unavailable.
pub fn open_uevent_socket() -> Option<OwnedFd> {
    unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::NETLINK_KOBJECT_UEVENT,
        );
        if fd < 0 {
            return None;
        }
        let owned = OwnedFd::from_raw_fd(fd);

        // Boot can emit thousands of uevents: ask for a large receive buffer.
        let size: libc::c_int = 16 * 1024 * 1024;
        let sz_ptr = &size as *const libc::c_int as *const libc::c_void;
        let sz_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        if libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, sz_ptr, sz_len) != 0 {
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, sz_ptr, sz_len);
        }

        let mut addr: libc::sockaddr_nl = std::mem::zeroed();
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_pid = 0;
        addr.nl_groups = 1; // kernel uevent multicast group
        let rc = libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        );
        if rc != 0 {
            return None;
        }
        Some(owned)
    }
}

/// Tell the kernel where modprobe lives, for its own request_module() calls
/// (filesystems, crypto, net protocols, "binfmt-*", ...).
pub fn set_kernel_modprobe_helper() {
    let _ = fs::write("/proc/sys/kernel/modprobe", format!("{}\n", MODPROBE));
}

fn collect_modaliases(dir: &Path, out: &mut HashSet<String>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        // DirEntry::file_type does not follow symlinks: sysfs is full of loops.
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            collect_modaliases(&entry.path(), out);
        } else if ft.is_file() && entry.file_name() == "modalias" {
            if let Ok(alias) = fs::read_to_string(entry.path()) {
                let alias = alias.trim();
                if !alias.is_empty() {
                    out.insert(alias.to_string());
                }
            }
        }
    }
}

/// Runs `modprobe -a -b -q -- <args...>` in batches and waits for each batch.
fn modprobe_many(args: &[String]) {
    for chunk in args.chunks(MODPROBE_BATCH) {
        let _ = Command::new(MODPROBE)
            .args(["-a", "-b", "-q", "--"])
            .args(chunk)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Bare module names from /etc/serenity/modules.load (lines not starting with '/').
fn extra_module_names() -> Vec<String> {
    fs::read_to_string(MODULES_LOAD_PATH)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('/'))
        .map(str::to_string)
        .collect()
}

/// Loads drivers for every device currently present. Returns how many modules got loaded.
pub fn coldplug() -> usize {
    let before = loaded_module_count();
    let mut tried: HashSet<String> = HashSet::new();

    for _ in 0..COLDPLUG_PASSES {
        let mut found = HashSet::new();
        collect_modaliases(Path::new("/sys/devices"), &mut found);
        let fresh: Vec<String> = found.into_iter().filter(|a| !tried.contains(a)).collect();
        if fresh.is_empty() {
            break;
        }
        modprobe_many(&fresh);
        tried.extend(fresh);
    }

    let extra = extra_module_names();
    if !extra.is_empty() {
        modprobe_many(&extra);
    }

    loaded_module_count().saturating_sub(before)
}

/// Parses one uevent datagram ("add@/devices/...\0ACTION=add\0MODALIAS=...\0...")
/// and returns the MODALIAS of an `add` event.
fn modalias_of_add_event(buf: &[u8]) -> Option<String> {
    let mut action_add = false;
    let mut modalias = None;
    for field in buf.split(|b| *b == 0) {
        if field == b"ACTION=add" {
            action_add = true;
        } else if let Some(v) = field.strip_prefix(b"MODALIAS=") {
            modalias = Some(String::from_utf8_lossy(v).into_owned());
        }
    }
    if action_add {
        modalias.filter(|m| !m.is_empty())
    } else {
        None
    }
}

/// Background hotplug loop. Children are spawned without waiting: PID 1's main
/// loop reaps them via waitpid(-1).
pub fn spawn_hotplug_thread(sock: OwnedFd) {
    let _ = thread::Builder::new()
        .name("hotplug".into())
        .spawn(move || hotplug_loop(sock.as_raw_fd(), sock));
}

fn hotplug_loop(fd: RawFd, _keep_alive: OwnedFd) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                // Receive buffer overflowed during an event storm: rescan everything.
                Some(libc::ENOBUFS) => {
                    let mut found = HashSet::new();
                    collect_modaliases(Path::new("/sys/devices"), &mut found);
                    let all: Vec<String> = found.into_iter().collect();
                    for chunk in all.chunks(MODPROBE_BATCH) {
                        let _ = Command::new(MODPROBE)
                            .args(["-a", "-b", "-q", "--"])
                            .args(chunk)
                            .stdin(Stdio::null())
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .spawn();
                    }
                    continue;
                }
                _ => {
                    eprintln!("[init] hotplug: uevent socket error: {}", err);
                    return;
                }
            }
        }
        if let Some(alias) = modalias_of_add_event(&buf[..n as usize]) {
            let _ = Command::new(MODPROBE)
                .args(["-b", "-q", "--", &alias])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
        }
    }
}

/// True if a PCI display controller (class 0x03xxxx) exists, i.e. a GPU driver should appear.
fn has_pci_display_device() -> bool {
    let Ok(entries) = fs::read_dir("/sys/bus/pci/devices") else { return false };
    entries.flatten().any(|e| {
        fs::read_to_string(e.path().join("class"))
            .map(|c| c.trim().starts_with("0x03"))
            .unwrap_or(false)
    })
}

fn has_drm_card() -> bool {
    fs::read_dir("/sys/class/drm")
        .map(|it| {
            it.flatten().any(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                n.starts_with("card") && !n.contains('-')
            })
        })
        .unwrap_or(false)
}

/// GPU drivers (i915, amdgpu, xe, nouveau) load firmware and probe asynchronously.
/// Wait up to `max_ms` for /sys/class/drm/cardN so desktop setup sees the GPU.
pub fn wait_for_gpu(max_ms: u64) {
    if !has_pci_display_device() {
        return;
    }
    let step = 50;
    let mut waited = 0;
    while waited < max_ms && !has_drm_card() {
        thread::sleep(std::time::Duration::from_millis(step));
        waited += step;
    }
}

/// Legacy: loads uncompressed `.ko` paths listed in `/etc/serenity/modules.load`
/// in order using finit_module(2) (no external modprobe needed).
pub fn load_kernel_modules() -> usize {
    let content = match fs::read_to_string(MODULES_LOAD_PATH) {
        Ok(c) => c,
        Err(_) => return 0,
    };

    let mut loaded = 0;
    for line in content.lines() {
        let path_str = line.trim();
        if !path_str.starts_with('/') {
            continue;
        }
        let path = Path::new(path_str);
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[init] kmod: cannot open {}: {}", path_str, e);
                continue;
            }
        };

        let empty_params = b"\0";
        let rc = unsafe {
            libc::syscall(
                libc::SYS_finit_module,
                file.as_raw_fd(),
                empty_params.as_ptr(),
                0 as libc::c_int,
            )
        };

        if rc == 0 {
            loaded += 1;
        } else {
            let err = io::Error::last_os_error();
            // EEXIST means module is already loaded; ignore quietly.
            if err.raw_os_error() != Some(libc::EEXIST) {
                eprintln!("[init] kmod: finit_module({}) failed: {}", path_str, err);
            }
        }
    }
    loaded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_add_event_with_modalias() {
        let ev = b"add@/devices/pci0000:00/0000:00:14.0/usb1/1-2\0ACTION=add\0DEVPATH=/devices/x\0MODALIAS=usb:v046DpC52Bd2411dc00dsc00dp00ic03isc01ip01in00\0SEQNUM=42\0";
        assert_eq!(
            modalias_of_add_event(ev).as_deref(),
            Some("usb:v046DpC52Bd2411dc00dsc00dp00ic03isc01ip01in00")
        );
    }

    #[test]
    fn ignores_remove_and_events_without_modalias() {
        assert_eq!(modalias_of_add_event(b"remove@/x\0ACTION=remove\0MODALIAS=usb:v1\0"), None);
        assert_eq!(modalias_of_add_event(b"add@/x\0ACTION=add\0SUBSYSTEM=block\0"), None);
    }
}
