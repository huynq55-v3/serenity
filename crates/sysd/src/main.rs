//! Minimal Rust System D-Bus daemon for Serenity Linux (no systemd required).
//!
//! Provides the exact D-Bus interfaces that COSMIC Desktop applets and settings rely on:
//! - `org.freedesktop.login1` (`/org/freedesktop/login1` and `/org/freedesktop/login1/session/auto`):
//!   - `SetBrightness(subsystem, name, brightness)` -> writes `/sys/class/<subsystem>/<name>/brightness`
//!   - `PowerOff(interactive)` -> sync + reboot(POWER_OFF)
//!   - `Reboot(interactive)` -> sync + reboot(RESTART)
//!   - `Suspend(interactive)` -> writes `mem` to `/sys/power/state`
//! - `org.freedesktop.UPower` (`/org/freedesktop/UPower` and `/org/freedesktop/UPower/devices/DisplayDevice`):
//!   - Reads real battery state/percentage from `/sys/class/power_supply/BAT*` & `AC*` so
//!     `cosmic-applet-battery` displays battery percentage + display brightness slider cleanly.

use std::fs;
use std::net::UdpSocket;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zbus::{connection::Builder, fdo, interface, object_server::SignalEmitter, zvariant::OwnedObjectPath};

struct Login1Manager;

#[interface(name = "org.freedesktop.login1.Manager")]
impl Login1Manager {
    async fn power_off(&self, _interactive: bool) -> fdo::Result<()> {
        eprintln!("[serenity-sysd] login1.Manager.PowerOff requested");
        unsafe {
            libc::sync();
            libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
        }
        Ok(())
    }

    async fn reboot(&self, _interactive: bool) -> fdo::Result<()> {
        eprintln!("[serenity-sysd] login1.Manager.Reboot requested");
        unsafe {
            libc::sync();
            libc::reboot(libc::LINUX_REBOOT_CMD_RESTART);
        }
        Ok(())
    }

    async fn suspend(&self, _interactive: bool) -> fdo::Result<()> {
        eprintln!("[serenity-sysd] login1.Manager.Suspend requested");
        unsafe { libc::sync(); }
        fs::write("/sys/power/state", "mem")
            .or_else(|_| fs::write("/sys/power/state", "freeze"))
            .map_err(|e| fdo::Error::Failed(format!("failed to enter sleep state: {}", e)))?;
        Ok(())
    }

    async fn can_power_off(&self) -> String {
        "yes".to_string()
    }

    async fn can_reboot(&self) -> String {
        "yes".to_string()
    }

    async fn can_suspend(&self) -> String {
        if Path::new("/sys/power/state").exists() {
            "yes".to_string()
        } else {
            "no".to_string()
        }
    }

    async fn get_session(&self, _session_id: &str) -> fdo::Result<OwnedObjectPath> {
        OwnedObjectPath::try_from("/org/freedesktop/login1/session/auto")
            .map_err(|e| fdo::Error::Failed(e.to_string()))
    }
}

struct Login1Session;

#[interface(name = "org.freedesktop.login1.Session")]
impl Login1Session {
    async fn set_brightness(
        &self,
        subsystem: &str,
        name: &str,
        brightness: u32,
    ) -> fdo::Result<()> {
        // Strict allow-list: only backlight or leds sysfs subsystems, no path traversal
        if (subsystem != "backlight" && subsystem != "leds")
            || name.is_empty()
            || name.contains('/')
            || name.contains("..")
        {
            return Err(fdo::Error::InvalidArgs(format!(
                "invalid subsystem/name: {}/{}",
                subsystem, name
            )));
        }

        let path = format!("/sys/class/{}/{}/brightness", subsystem, name);
        fs::write(&path, brightness.to_string()).map_err(|e| {
            fdo::Error::Failed(format!("failed to write {} -> {}: {}", brightness, path, e))
        })?;
        Ok(())
    }
}

/// Reads battery info from `/sys/class/power_supply/*`.
/// Returns `(is_present, percentage, state)` where UPower state is:
/// 1 = Charging, 2 = Discharging, 4 = Fully charged, 0 = Unknown.
fn read_battery_sysfs() -> (bool, f64, u32) {
    let Ok(entries) = fs::read_dir("/sys/class/power_supply") else {
        return (false, 100.0, 0);
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        let kind = fs::read_to_string(dir.join("type")).unwrap_or_default();
        if kind.trim() != "Battery" {
            continue;
        }
        let cap = fs::read_to_string(dir.join("capacity"))
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .unwrap_or(100.0);
        let status = fs::read_to_string(dir.join("status")).unwrap_or_default();
        let state = match status.trim() {
            "Charging" => 1,
            "Discharging" => 2,
            "Full" => 4,
            "Not charging" => 5,
            _ => 0,
        };
        return (true, cap, state);
    }
    (false, 100.0, 0)
}

fn read_on_battery() -> bool {
    let (present, _, state) = read_battery_sysfs();
    present && state == 2
}

struct UPowerRoot;

#[interface(name = "org.freedesktop.UPower")]
impl UPowerRoot {
    async fn get_display_device(&self) -> fdo::Result<OwnedObjectPath> {
        OwnedObjectPath::try_from("/org/freedesktop/UPower/devices/DisplayDevice")
            .map_err(|e| fdo::Error::Failed(e.to_string()))
    }

    async fn enumerate_devices(&self) -> fdo::Result<Vec<OwnedObjectPath>> {
        let p = OwnedObjectPath::try_from("/org/freedesktop/UPower/devices/DisplayDevice")
            .map_err(|e| fdo::Error::Failed(e.to_string()))?;
        Ok(vec![p])
    }

    #[zbus(property)]
    async fn on_battery(&self) -> bool {
        read_on_battery()
    }

    #[zbus(property)]
    async fn lid_is_present(&self) -> bool {
        Path::new("/proc/acpi/button/lid").exists()
    }

    #[zbus(property)]
    async fn lid_is_closed(&self) -> bool {
        false
    }

    #[zbus(property)]
    async fn daemon_version(&self) -> String {
        "1.90.0".to_string()
    }
}

struct UPowerDisplayDevice;

#[interface(name = "org.freedesktop.UPower.Device")]
impl UPowerDisplayDevice {
    #[zbus(property)]
    async fn is_present(&self) -> bool {
        read_battery_sysfs().0
    }

    #[zbus(property)]
    async fn percentage(&self) -> f64 {
        read_battery_sysfs().1
    }

    #[zbus(property)]
    async fn state(&self) -> u32 {
        read_battery_sysfs().2
    }

    #[zbus(property, name = "Type")]
    async fn device_type(&self) -> u32 {
        // 2 = Battery, 1 = Line Power
        if read_battery_sysfs().0 { 2 } else { 1 }
    }

    #[zbus(property)]
    async fn time_to_empty(&self) -> i64 {
        0
    }

    #[zbus(property)]
    async fn time_to_full(&self) -> i64 {
        0
    }

    #[zbus(property)]
    async fn icon_name(&self) -> String {
        if read_battery_sysfs().0 {
            "battery-good-symbolic".to_string()
        } else {
            "ac-adapter-symbolic".to_string()
        }
    }
}

/// Synchronizes system wall clock via SNTP (UDP/123). Returns true on success.
fn sync_clock_sntp() -> bool {
    const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;
    for server in ["time.google.com:123", "pool.ntp.org:123", "time.cloudflare.com:123"] {
        let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
            continue;
        };
        let _ = sock.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = sock.set_write_timeout(Some(Duration::from_secs(3)));

        let mut req = [0u8; 48];
        req[0] = 0x1b; // LI=0, VN=3, Mode=3 (Client)
        if sock.send_to(&req, server).is_err() {
            continue;
        }

        let mut resp = [0u8; 48];
        let Ok(n) = sock.recv(&mut resp) else {
            continue;
        };
        if n < 48 {
            continue;
        }

        let ntp_sec = u32::from_be_bytes([resp[40], resp[41], resp[42], resp[43]]) as u64;
        let ntp_frac = u32::from_be_bytes([resp[44], resp[45], resp[46], resp[47]]) as u64;
        let Some(unix_sec) = ntp_sec.checked_sub(NTP_EPOCH_OFFSET) else {
            continue;
        };
        if unix_sec <= 1_700_000_000 {
            continue;
        }

        let nsec = ((ntp_frac * 1_000_000_000) >> 32) as i64;
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        ts.tv_sec = unix_sec as _;
        ts.tv_nsec = nsec as libc::c_long;
        let rc = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) };
        if rc == 0 {
            eprintln!("[serenity-sysd] SNTP synchronized clock from {} (unix={})", server, unix_sec);
            return true;
        }
    }
    false
}

fn read_current_timezone() -> String {
    if let Ok(tz) = fs::read_to_string("/etc/timezone") {
        let trimmed = tz.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(target) = fs::read_link("/etc/localtime") {
        let target_str = target.to_string_lossy();
        if let Some(rel) = target_str.strip_prefix("/usr/share/zoneinfo/") {
            if !rel.is_empty() {
                return rel.to_string();
            }
        }
    }
    "UTC".to_string()
}

fn collect_timezones(base: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if path.is_dir() {
            if name_str == "posix" || name_str == "right" {
                continue;
            }
            collect_timezones(base, &path, out);
        } else if path.is_file() {
            if matches!(
                name_str,
                "posixrules"
                    | "leapseconds"
                    | "leap-seconds.list"
                    | "tzdata.zi"
                    | "zone.tab"
                    | "zone1970.tab"
                    | "iso3166.tab"
                    | "zonenow.tab"
                    | "SECURITY"
                    | "README"
                    | "Factory"
            ) || name_str.ends_with(".tab")
                || name_str.ends_with(".list")
                || name_str.ends_with(".zi")
            {
                continue;
            }
            if let Ok(rel) = path.strip_prefix(base) {
                if let Some(rel_str) = rel.to_str() {
                    out.push(rel_str.to_string());
                }
            }
        }
    }
}

struct Timedate1 {
    ntp_enabled: Arc<AtomicBool>,
    ntp_synced: Arc<AtomicBool>,
    local_rtc: AtomicBool,
}

#[interface(name = "org.freedesktop.timedate1")]
impl Timedate1 {
    #[zbus(property, name = "Timezone")]
    async fn timezone(&self) -> String {
        read_current_timezone()
    }

    #[zbus(property, name = "LocalRTC")]
    async fn local_rtc(&self) -> bool {
        self.local_rtc.load(Ordering::Relaxed)
    }

    #[zbus(property, name = "CanNTP")]
    async fn can_ntp(&self) -> bool {
        true
    }

    #[zbus(property, name = "NTP")]
    async fn ntp(&self) -> bool {
        self.ntp_enabled.load(Ordering::Relaxed)
    }

    #[zbus(property, name = "NTPSynchronized")]
    async fn ntp_synchronized(&self) -> bool {
        self.ntp_synced.load(Ordering::Relaxed)
    }

    #[zbus(property, name = "TimeUSec")]
    async fn time_usec(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0)
    }

    #[zbus(property, name = "RTCTimeUSec")]
    async fn rtc_time_usec(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0)
    }

    async fn set_timezone(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        timezone: &str,
        _interactive: bool,
    ) -> fdo::Result<()> {
        if timezone.is_empty() || timezone.starts_with('/') || timezone.contains("..") {
            return Err(fdo::Error::InvalidArgs(format!(
                "invalid timezone: {}",
                timezone
            )));
        }
        let zone_path = Path::new("/usr/share/zoneinfo").join(timezone);
        if !zone_path.is_file() {
            return Err(fdo::Error::InvalidArgs(format!(
                "unknown timezone: {}",
                timezone
            )));
        }

        match fs::remove_file("/etc/localtime") {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(fdo::Error::Failed(format!(
                    "failed to remove /etc/localtime: {}",
                    e
                )));
            }
        }
        symlink(&zone_path, "/etc/localtime").map_err(|e| {
            fdo::Error::Failed(format!("failed to symlink /etc/localtime: {}", e))
        })?;
        fs::write("/etc/timezone", format!("{}\n", timezone)).map_err(|e| {
            fdo::Error::Failed(format!("failed to write /etc/timezone: {}", e))
        })?;

        let _ = self.timezone_changed(&emitter).await;
        Ok(())
    }

    async fn set_time(
        &self,
        usec_utc: i64,
        relative: bool,
        _interactive: bool,
    ) -> fdo::Result<()> {
        let mut target_ns: i128 = if relative {
            let mut cur: libc::timespec = unsafe { std::mem::zeroed() };
            let rc = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut cur) };
            if rc != 0 {
                return Err(fdo::Error::Failed("clock_gettime failed".to_string()));
            }
            (cur.tv_sec as i128) * 1_000_000_000
                + (cur.tv_nsec as i128)
                + (usec_utc as i128) * 1_000
        } else {
            (usec_utc as i128) * 1_000
        };

        if target_ns < 0 {
            return Err(fdo::Error::InvalidArgs(
                "negative timestamp is not supported".to_string(),
            ));
        }

        let secs = target_ns / 1_000_000_000;
        let nsecs = target_ns % 1_000_000_000;
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        ts.tv_sec = secs as _;
        ts.tv_nsec = nsecs as libc::c_long;
        let rc = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) };
        if rc != 0 {
            return Err(fdo::Error::Failed(format!(
                "clock_settime failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        target_ns = 0;
        let _ = target_ns;
        Ok(())
    }

    #[zbus(name = "SetLocalRTC")]
    async fn set_local_rtc(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        local_rtc: bool,
        _fix_system: bool,
        _interactive: bool,
    ) -> fdo::Result<()> {
        self.local_rtc.store(local_rtc, Ordering::Relaxed);
        let _ = self.local_r_t_c_changed(&emitter).await;
        Ok(())
    }

    #[zbus(name = "SetNTP")]
    async fn set_ntp(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        use_ntp: bool,
        _interactive: bool,
    ) -> fdo::Result<()> {
        self.ntp_enabled.store(use_ntp, Ordering::Relaxed);
        if use_ntp {
            let synced = sync_clock_sntp();
            self.ntp_synced.store(synced, Ordering::Relaxed);
        } else {
            self.ntp_synced.store(false, Ordering::Relaxed);
        }
        let _ = self.n_t_p_changed(&emitter).await;
        let _ = self.n_t_p_synchronized_changed(&emitter).await;
        Ok(())
    }

    async fn list_timezones(&self) -> fdo::Result<Vec<String>> {
        let base = Path::new("/usr/share/zoneinfo");
        let mut zones = Vec::new();
        collect_timezones(base, base, &mut zones);
        zones.sort();
        zones.dedup();
        Ok(zones)
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Wait briefly for /run/dbus/system_bus_socket to appear
    for _ in 0..40 {
        if Path::new("/run/dbus/system_bus_socket").exists()
            || Path::new("/var/run/dbus/system_bus_socket").exists()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let ntp_enabled = Arc::new(AtomicBool::new(true));
    let ntp_synced = Arc::new(AtomicBool::new(false));
    let timedate = Timedate1 {
        ntp_enabled: Arc::clone(&ntp_enabled),
        ntp_synced: Arc::clone(&ntp_synced),
        local_rtc: AtomicBool::new(false),
    };

    let _conn = Builder::system()?
        .name("org.freedesktop.login1")?
        .name("org.freedesktop.UPower")?
        .name("org.freedesktop.timedate1")?
        .serve_at("/org/freedesktop/login1", Login1Manager)?
        .serve_at("/org/freedesktop/login1/session/auto", Login1Session)?
        .serve_at("/org/freedesktop/UPower", UPowerRoot)?
        .serve_at("/org/freedesktop/UPower/devices/DisplayDevice", UPowerDisplayDevice)?
        .serve_at("/org/freedesktop/timedate1", timedate)?
        .build()
        .await?;

    let bg_enabled = Arc::clone(&ntp_enabled);
    let bg_synced = Arc::clone(&ntp_synced);
    std::thread::spawn(move || {
        for delay_secs in [2u64, 5, 10, 20, 30] {
            std::thread::sleep(Duration::from_secs(delay_secs));
            if !bg_enabled.load(Ordering::Relaxed) {
                return;
            }
            if sync_clock_sntp() {
                bg_synced.store(true, Ordering::Relaxed);
                return;
            }
        }
    });

    eprintln!(
        "[serenity-sysd] Serving org.freedesktop.login1 + org.freedesktop.UPower + org.freedesktop.timedate1 on System D-Bus"
    );
    std::future::pending::<()>().await;
    Ok(())
}
