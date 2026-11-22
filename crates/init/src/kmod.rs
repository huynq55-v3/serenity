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
use std::ffi::{CStr, CString};
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
const AUDIO_GID: libc::gid_t = 29;
const VIDEO_GID: libc::gid_t = 44;

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

struct DeviceUevent {
    subsystem: String,
    devname: Option<String>,
    devpath: Option<String>,
    major: Option<String>,
    minor: Option<String>,
}

struct SoundEvent {
    devname: Option<String>,
    devpath: Option<String>,
    major: Option<String>,
    minor: Option<String>,
}

struct VideoEvent {
    is_video4linux: bool,
    devname: Option<String>,
    major: Option<String>,
    minor: Option<String>,
}

fn chown_chmod_device(path: &Path, gid: libc::gid_t) {
    if let Ok(c_path) = CString::new(path.to_string_lossy().as_bytes()) {
        unsafe {
            libc::chown(c_path.as_ptr(), 0, gid);
            libc::chmod(c_path.as_ptr(), 0o660);
        }
    }
}

fn write_sound_udev_tag(udev_file: &str, name_str: &str) {
    let _ = fs::create_dir_all("/run/udev/data");
    let udev_data = format!(
        "E:SOUND_INITIALIZED=1\nE:ID_SEAT=seat0\nE:ID_FOR_SEAT=sound-{}\nG:seat\n",
        name_str
    );
    let _ = fs::write(format!("/run/udev/data/{}", udev_file), udev_data);
}

fn write_video_udev_tag(udev_file: &str, name_str: &str) {
    let _ = fs::create_dir_all("/run/udev/data");
    let udev_data = format!(
        "E:ID_V4L_VERSION=2\nE:ID_V4L_CAPABILITIES=:capture:\nE:ID_SEAT=seat0\nE:ID_FOR_SEAT=video4linux-{}\nG:seat\n",
        name_str
    );
    let _ = fs::write(format!("/run/udev/data/{}", udev_file), udev_data);
}

/// Grants `audio` group access on `/dev/snd/*` and writes `/run/udev/data` tags so
/// PipeWire/WirePlumber (`spa/alsa-udev` checks `SOUND_INITIALIZED=1`) discovers cards without udevd.
pub fn setup_sound_devices() {
    if let Ok(entries) = fs::read_dir("/dev/snd") {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                continue;
            }
            chown_chmod_device(&entry.path(), AUDIO_GID);
        }
    }

    if let Ok(entries) = fs::read_dir("/sys/class/sound") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else { continue };
            if name_str.starts_with("card") {
                write_sound_udev_tag(&format!("+sound:{}", name_str), name_str);
            } else if name_str.starts_with("controlC") {
                if let Ok(dev_num) = fs::read_to_string(entry.path().join("dev")) {
                    let dev_num = dev_num.trim();
                    if !dev_num.is_empty() {
                        write_sound_udev_tag(&format!("c{}", dev_num), name_str);
                    }
                }
            }
        }
    }
}

/// Grants `video` group access on `/dev/video*` / `/dev/media*` and writes `/run/udev/data`
/// V4L2 tags so PipeWire / libudev / webcam apps discover cameras without udevd.
pub fn setup_video_devices() {
    if let Ok(entries) = fs::read_dir("/dev") {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                continue;
            }
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else { continue };
            if name_str.starts_with("video") || name_str.starts_with("media") {
                chown_chmod_device(&entry.path(), VIDEO_GID);
            }
        }
    }

    if let Ok(entries) = fs::read_dir("/sys/class/video4linux") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else { continue };
            if name_str.starts_with("video") {
                if let Ok(dev_num) = fs::read_to_string(entry.path().join("dev")) {
                    let dev_num = dev_num.trim();
                    if !dev_num.is_empty() {
                        write_video_udev_tag(&format!("c{}", dev_num), name_str);
                    }
                }
            }
        }
    }
}

fn parse_uevent(buf: &[u8], allowed_subsystems: &[&[u8]]) -> Option<DeviceUevent> {
    let mut subsystem: Option<String> = None;
    let mut action_ok = false;
    let mut devname = None;
    let mut devpath = None;
    let mut major = None;
    let mut minor = None;

    for field in buf.split(|b| *b == 0) {
        if let Some(sub) = field.strip_prefix(b"SUBSYSTEM=") {
            if allowed_subsystems.iter().any(|s| *s == sub) {
                subsystem = Some(String::from_utf8_lossy(sub).into_owned());
            }
        } else if field == b"ACTION=add" || field == b"ACTION=change" {
            action_ok = true;
        } else if let Some(v) = field.strip_prefix(b"DEVNAME=") {
            let s = String::from_utf8_lossy(v).into_owned();
            if !s.is_empty() {
                devname = Some(s);
            }
        } else if let Some(v) = field.strip_prefix(b"DEVPATH=") {
            let s = String::from_utf8_lossy(v).into_owned();
            if !s.is_empty() {
                devpath = Some(s);
            }
        } else if let Some(v) = field.strip_prefix(b"MAJOR=") {
            let s = String::from_utf8_lossy(v).into_owned();
            if !s.is_empty() {
                major = Some(s);
            }
        } else if let Some(v) = field.strip_prefix(b"MINOR=") {
            let s = String::from_utf8_lossy(v).into_owned();
            if !s.is_empty() {
                minor = Some(s);
            }
        }
    }

    let subsystem = subsystem?;
    if action_ok {
        Some(DeviceUevent {
            subsystem,
            devname,
            devpath,
            major,
            minor,
        })
    } else {
        None
    }
}

fn parse_sound_event(buf: &[u8]) -> Option<SoundEvent> {
    let ev = parse_uevent(buf, &[b"sound"])?;
    Some(SoundEvent {
        devname: ev.devname,
        devpath: ev.devpath,
        major: ev.major,
        minor: ev.minor,
    })
}

fn parse_video_event(buf: &[u8]) -> Option<VideoEvent> {
    let ev = parse_uevent(buf, &[b"video4linux", b"media"])?;
    Some(VideoEvent {
        is_video4linux: ev.subsystem == "video4linux",
        devname: ev.devname,
        major: ev.major,
        minor: ev.minor,
    })
}

fn handle_sound_event(ev: &SoundEvent) {
    if let Some(devname) = ev.devname.as_deref() {
        let rel = devname.trim_start_matches('/');
        if !rel.is_empty() {
            chown_chmod_device(&Path::new("/dev").join(rel), AUDIO_GID);
        }
        let base = Path::new(rel)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if base.starts_with("controlC") {
            if let (Some(maj), Some(min)) = (ev.major.as_deref(), ev.minor.as_deref()) {
                write_sound_udev_tag(&format!("c{}:{}", maj, min), base);
            }
        }
    }
    if let Some(devpath) = ev.devpath.as_deref() {
        if let Some(base) = devpath.trim_end_matches('/').rsplit('/').next() {
            if base.starts_with("card") {
                write_sound_udev_tag(&format!("+sound:{}", base), base);
            }
        }
    }
}

fn handle_video_event(ev: &VideoEvent) {
    if let Some(devname) = ev.devname.as_deref() {
        let rel = devname.trim_start_matches('/');
        if !rel.is_empty() {
            chown_chmod_device(&Path::new("/dev").join(rel), VIDEO_GID);
        }
        let base = Path::new(rel)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if ev.is_video4linux && base.starts_with("video") {
            if let (Some(maj), Some(min)) = (ev.major.as_deref(), ev.minor.as_deref()) {
                write_video_udev_tag(&format!("c{}:{}", maj, min), base);
            }
        }
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
                    setup_sound_devices();
                    setup_video_devices();
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
        if let Some(ev) = parse_sound_event(&buf[..n as usize]) {
            handle_sound_event(&ev);
        }
        if let Some(ev) = parse_video_event(&buf[..n as usize]) {
            handle_video_event(&ev);
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

/// True if a PCI audio controller (class 0x0401xx or 0x0403xx) exists.
fn has_pci_audio_device() -> bool {
    let Ok(entries) = fs::read_dir("/sys/bus/pci/devices") else { return false };
    entries.flatten().any(|e| {
        fs::read_to_string(e.path().join("class"))
            .map(|c| {
                let c = c.trim();
                c.starts_with("0x0401") || c.starts_with("0x0403")
            })
            .unwrap_or(false)
    })
}

fn has_sound_card() -> bool {
    fs::read_dir("/sys/class/sound")
        .map(|it| {
            it.flatten().any(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                if !n.starts_with("card") {
                    return false;
                }
                fs::read_to_string(e.path().join("id"))
                    .map(|id| id.trim() != "pcsp")
                    .unwrap_or(true)
            })
        })
        .unwrap_or(false)
}

/// Audio drivers (e.g. Intel SOF) load DSP firmware and probe asynchronously.
/// Wait up to `max_ms` for a non-pcsp ALSA card before desktop permission setup.
pub fn wait_for_sound(max_ms: u64) {
    if !has_pci_audio_device() {
        return;
    }
    let step = 50;
    let mut waited = 0;
    while waited < max_ms && !has_sound_card() {
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

    #[test]
    fn parses_sound_add_and_change_events() {
        let ctl = b"add@/devices/pci0000:00/0000:00:1f.3/sound/card0/controlC0\0ACTION=add\0DEVPATH=/devices/pci0000:00/0000:00:1f.3/sound/card0/controlC0\0SUBSYSTEM=sound\0MAJOR=116\0MINOR=3\0DEVNAME=snd/controlC0\0";
        let ev = parse_sound_event(ctl).expect("controlC0 add event");
        assert_eq!(ev.devname.as_deref(), Some("snd/controlC0"));
        assert_eq!(ev.major.as_deref(), Some("116"));
        assert_eq!(ev.minor.as_deref(), Some("3"));

        let card = b"change@/devices/pci0000:00/0000:00:1f.3/sound/card0\0ACTION=change\0DEVPATH=/devices/pci0000:00/0000:00:1f.3/sound/card0\0SUBSYSTEM=sound\0";
        let ev = parse_sound_event(card).expect("card0 change event");
        assert_eq!(ev.devpath.as_deref(), Some("/devices/pci0000:00/0000:00:1f.3/sound/card0"));
        assert_eq!(ev.devname, None);
    }

    #[test]
    fn ignores_sound_remove_and_non_sound_events() {
        let rem = b"remove@/devices/x/sound/card0\0ACTION=remove\0SUBSYSTEM=sound\0DEVPATH=/devices/x/sound/card0\0";
        assert!(parse_sound_event(rem).is_none());

        let input = b"add@/devices/x/input/event0\0ACTION=add\0SUBSYSTEM=input\0DEVNAME=input/event0\0";
        assert!(parse_sound_event(input).is_none());
    }

    #[test]
    fn parses_video_and_media_add_events() {
        let vid = b"add@/devices/pci0000:00/usb3/3-3/3-3:1.0/video4linux/video0\0ACTION=add\0SUBSYSTEM=video4linux\0MAJOR=81\0MINOR=0\0DEVNAME=video0\0";
        let ev = parse_video_event(vid).expect("video0 add event");
        assert!(ev.is_video4linux);
        assert_eq!(ev.devname.as_deref(), Some("video0"));
        assert_eq!(ev.major.as_deref(), Some("81"));
        assert_eq!(ev.minor.as_deref(), Some("0"));

        let media = b"change@/devices/pci0000:00/usb3/3-3/3-3:1.0/media0\0ACTION=change\0SUBSYSTEM=media\0MAJOR=240\0MINOR=0\0DEVNAME=media0\0";
        let ev = parse_video_event(media).expect("media0 change event");
        assert!(!ev.is_video4linux);
        assert_eq!(ev.devname.as_deref(), Some("media0"));
    }

    #[test]
    fn ignores_video_remove_and_unrelated_subsystems() {
        let rem = b"remove@/devices/x/video4linux/video0\0ACTION=remove\0SUBSYSTEM=video4linux\0DEVNAME=video0\0";
        assert!(parse_video_event(rem).is_none());

        let sound = b"add@/devices/x/sound/card0\0ACTION=add\0SUBSYSTEM=sound\0DEVNAME=snd/controlC0\0";
        assert!(parse_video_event(sound).is_none());
    }
}
