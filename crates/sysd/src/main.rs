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
use std::path::Path;
use zbus::{connection::Builder, fdo, interface, zvariant::OwnedObjectPath};

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

    let _conn = Builder::system()?
        .name("org.freedesktop.login1")?
        .name("org.freedesktop.UPower")?
        .serve_at("/org/freedesktop/login1", Login1Manager)?
        .serve_at("/org/freedesktop/login1/session/auto", Login1Session)?
        .serve_at("/org/freedesktop/UPower", UPowerRoot)?
        .serve_at("/org/freedesktop/UPower/devices/DisplayDevice", UPowerDisplayDevice)?
        .build()
        .await?;

    eprintln!("[serenity-sysd] Serving org.freedesktop.login1 + org.freedesktop.UPower on System D-Bus");
    std::future::pending::<()>().await;
    Ok(())
}
