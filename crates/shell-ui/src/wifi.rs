use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct WifiNetwork {
    pub ssid: String,
    pub signal: String,
    pub security: String,
}

pub fn detect_wifi_interface() -> Option<String> {
    let entries = fs::read_dir("/sys/class/net").ok()?;
    let mut ifaces: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| Path::new(&format!("/sys/class/net/{}/wireless", name)).exists())
        .collect();
    ifaces.sort();
    ifaces.into_iter().next()
}

pub fn scan_networks(iface: Option<&str>) -> Result<Vec<WifiNetwork>, String> {
    // 1. Try nmcli (works when testing on Ubuntu host desktop)
    if let Ok(out) = Command::new("nmcli")
        .args(["-t", "-f", "SSID,SIGNAL,SECURITY", "dev", "wifi", "list"])
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut dedup: BTreeMap<String, WifiNetwork> = BTreeMap::new();
            for line in text.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 {
                    let ssid = parts[0].trim();
                    if ssid.is_empty() {
                        continue;
                    }
                    let signal = format!("{}%", parts[1].trim());
                    let security = if parts[2].trim().is_empty() {
                        "Open".to_string()
                    } else {
                        parts[2].trim().to_string()
                    };
                    dedup.entry(ssid.to_string()).or_insert(WifiNetwork {
                        ssid: ssid.to_string(),
                        signal,
                        security,
                    });
                }
            }
            return Ok(dedup.into_values().collect());
        }
    }

    // 2. Try `iw dev <iface> scan` (minimal Linux / Serenity bare-metal)
    if let Some(dev) = iface {
        if let Ok(out) = Command::new("iw").args(["dev", dev, "scan"]).output() {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                let mut nets = Vec::new();
                for line in text.lines() {
                    let trimmed = line.trim();
                    if let Some(ssid) = trimmed.strip_prefix("SSID:") {
                        let ssid = ssid.trim();
                        if !ssid.is_empty() && !nets.iter().any(|n: &WifiNetwork| n.ssid == ssid) {
                            nets.push(WifiNetwork {
                                ssid: ssid.to_string(),
                                signal: "OK".to_string(),
                                security: "WPA".to_string(),
                            });
                        }
                    }
                }
                return Ok(nets);
            }
        }
    }

    Err("No Wi-Fi scanner backend found (install `iwd` or `iw` via spkg, or test on Ubuntu with `nmcli`).".to_string())
}

pub fn connect_network(iface: Option<&str>, ssid: &str, password: &str) -> Result<String, String> {
    if ssid.trim().is_empty() {
        return Err("Please select or enter a Wi-Fi SSID first.".to_string());
    }

    // 1. Try nmcli (Ubuntu host test)
    if Command::new("nmcli").arg("--version").output().is_ok() {
        let mut cmd = Command::new("nmcli");
        cmd.args(["dev", "wifi", "connect", ssid]);
        if !password.is_empty() {
            cmd.args(["password", password]);
        }
        let out = cmd.output().map_err(|e| e.to_string())?;
        if out.status.success() {
            return Ok(format!("Connected to '{}'", ssid));
        }
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }

    // 2. Try iwctl (iwd daemon on Serenity)
    if let Some(dev) = iface {
        if Command::new("iwctl").arg("--version").output().is_ok() {
            let mut cmd = Command::new("iwctl");
            if !password.is_empty() {
                cmd.args(["--passphrase", password]);
            }
            cmd.args(["station", dev, "connect", ssid]);
            let out = cmd.output().map_err(|e| e.to_string())?;
            if out.status.success() {
                return Ok(format!("Connected '{}' on {}", ssid, dev));
            }
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
    }

    Err(format!(
        "Cannot connect to '{}': neither `iwctl` (iwd) nor `nmcli` is available yet.",
        ssid
    ))
}
