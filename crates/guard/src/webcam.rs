use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ffi::CString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::thread;
use std::time::Duration;

pub const VIDEO_GID: libc::gid_t = 44;
pub const INITIAL_GRACE_SECS: u64 = 60;
pub const IDLE_RELOCK_SECS: u64 = 5;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebcamHolder {
    pub pid: i32,
    pub comm: String,
    pub exe: String,
    pub device: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebcamStatus {
    pub has_device: bool,
    pub devices: Vec<String>,
    pub unlocked: bool,
    pub state: String,
    pub auto_lock_secs_remaining: Option<u64>,
    pub holders: Vec<WebcamHolder>,
}

impl Default for WebcamStatus {
    fn default() -> Self {
        Self {
            has_device: false,
            devices: Vec::new(),
            unlocked: false,
            state: "LOCKED".to_string(),
            auto_lock_secs_remaining: None,
            holders: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebcamAlert {
    pub severity: &'static str,
    pub rule_id: &'static str,
    pub summary: String,
    pub pid: Option<i32>,
    pub exe: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoLockReason {
    IdleAfterUse,
    UnusedGraceExpired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoLockEval {
    pub state: &'static str,
    pub remaining_secs: Option<u64>,
    pub trigger_relock: Option<AutoLockReason>,
}

/// Evaluates current webcam privacy state and whether auto-relock should fire.
pub fn evaluate_auto_lock(
    unlocked: bool,
    ever_used: bool,
    unlocked_at: u64,
    idle_since: Option<u64>,
    has_holders: bool,
    now: u64,
) -> AutoLockEval {
    if !unlocked {
        return AutoLockEval {
            state: "LOCKED",
            remaining_secs: None,
            trigger_relock: None,
        };
    }

    if has_holders {
        return AutoLockEval {
            state: "IN_USE",
            remaining_secs: None,
            trigger_relock: None,
        };
    }

    if ever_used {
        let start = idle_since.unwrap_or(now);
        let elapsed = now.saturating_sub(start);
        if elapsed >= IDLE_RELOCK_SECS {
            return AutoLockEval {
                state: "LOCKED",
                remaining_secs: Some(0),
                trigger_relock: Some(AutoLockReason::IdleAfterUse),
            };
        }
        return AutoLockEval {
            state: "IDLE_RELOCKING",
            remaining_secs: Some(IDLE_RELOCK_SECS - elapsed),
            trigger_relock: None,
        };
    }

    let elapsed = now.saturating_sub(unlocked_at);
    if elapsed >= INITIAL_GRACE_SECS {
        return AutoLockEval {
            state: "LOCKED",
            remaining_secs: Some(0),
            trigger_relock: Some(AutoLockReason::UnusedGraceExpired),
        };
    }

    AutoLockEval {
        state: "WAITING",
        remaining_secs: Some(INITIAL_GRACE_SECS - elapsed),
        trigger_relock: None,
    }
}

fn is_video_or_media_name(name: &str) -> bool {
    name.starts_with("video") || name.starts_with("media")
}

pub fn list_video_devices() -> Vec<String> {
    let mut devs = Vec::new();
    if let Ok(entries) = fs::read_dir("/dev") {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                continue;
            }
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("video") {
                    devs.push(format!("/dev/{}", name));
                }
            }
        }
    }
    devs.sort();
    devs
}

pub fn is_any_video_device_unlocked() -> bool {
    for dev in list_video_devices() {
        if let Ok(meta) = fs::metadata(&dev) {
            if (meta.mode() & 0o066) != 0 {
                return true;
            }
        }
    }
    false
}

pub fn set_video_devices_locked(locked: bool) -> Result<usize, String> {
    let entries = fs::read_dir("/dev").map_err(|e| format!("failed to read /dev: {}", e))?;
    let mut updated = 0usize;
    let gid = if locked { 0 } else { VIDEO_GID };
    let mode = if locked { 0o600 } else { 0o660 };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if !is_video_or_media_name(name_str) {
            continue;
        }
        if let Ok(c_path) = CString::new(path.to_string_lossy().as_bytes()) {
            let rc_chown = unsafe { libc::chown(c_path.as_ptr(), 0, gid) };
            let rc_chmod = unsafe { libc::chmod(c_path.as_ptr(), mode) };
            if rc_chown != 0 || rc_chmod != 0 {
                return Err(format!(
                    "failed to {} {} (root privileges required)",
                    if locked { "lock" } else { "unlock" },
                    path.display()
                ));
            }
            updated += 1;
        }
    }

    Ok(updated)
}

pub fn scan_video_holders() -> Vec<WebcamHolder> {
    let mut holders = Vec::new();
    let mut seen = HashSet::new();

    let Ok(procs) = fs::read_dir("/proc") else {
        return holders;
    };

    for entry in procs.flatten() {
        let fname = entry.file_name();
        let Some(pid_str) = fname.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<i32>() else {
            continue;
        };
        if pid <= 1 {
            continue;
        }

        let proc_dir = entry.path();
        let Ok(fds) = fs::read_dir(proc_dir.join("fd")) else {
            continue;
        };

        let mut comm: Option<String> = None;
        let mut exe: Option<String> = None;

        for fd_entry in fds.flatten() {
            let Ok(target) = fs::read_link(fd_entry.path()) else {
                continue;
            };
            let target_str = target.to_string_lossy();
            let dev_path = target_str
                .strip_suffix(" (deleted)")
                .unwrap_or(target_str.as_ref());
            if !dev_path.starts_with("/dev/video") && !dev_path.starts_with("/dev/media") {
                continue;
            }
            if !seen.insert((pid, dev_path.to_string())) {
                continue;
            }
            let c = comm.get_or_insert_with(|| {
                fs::read_to_string(proc_dir.join("comm"))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "unknown".to_string())
            });
            let e = exe.get_or_insert_with(|| {
                fs::read_link(proc_dir.join("exe"))
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default()
            });
            holders.push(WebcamHolder {
                pid,
                comm: c.clone(),
                exe: e.clone(),
                device: dev_path.to_string(),
            });
        }
    }

    holders.sort_by(|a, b| a.pid.cmp(&b.pid).then(a.device.cmp(&b.device)));
    holders
}

pub struct WebcamShield {
    unlocked: bool,
    unlocked_at: u64,
    ever_used: bool,
    idle_since: Option<u64>,
    reported_pids: HashSet<i32>,
    last_status: WebcamStatus,
}

impl WebcamShield {
    pub fn new(now: u64) -> Self {
        let devices = list_video_devices();
        let holders = scan_video_holders();
        let mut unlocked = is_any_video_device_unlocked();

        // Enforce default-closed privacy at daemon startup when nobody is actively using the camera.
        if unlocked && holders.is_empty() && set_video_devices_locked(true).is_ok() {
            unlocked = false;
        }

        let ever_used = !holders.is_empty();
        let reported_pids: HashSet<i32> = holders.iter().map(|h| h.pid).collect();
        let eval = evaluate_auto_lock(unlocked, ever_used, now, None, !holders.is_empty(), now);
        let status = WebcamStatus {
            has_device: !devices.is_empty(),
            devices,
            unlocked,
            state: eval.state.to_string(),
            auto_lock_secs_remaining: eval.remaining_secs,
            holders,
        };

        Self {
            unlocked,
            unlocked_at: now,
            ever_used,
            idle_since: None,
            reported_pids,
            last_status: status,
        }
    }

    pub fn one_shot_status() -> WebcamStatus {
        let devices = list_video_devices();
        let holders = scan_video_holders();
        let unlocked = is_any_video_device_unlocked();
        let state = if !unlocked {
            "LOCKED"
        } else if !holders.is_empty() {
            "IN_USE"
        } else {
            "UNLOCKED"
        };
        WebcamStatus {
            has_device: !devices.is_empty(),
            devices,
            unlocked,
            state: state.to_string(),
            auto_lock_secs_remaining: None,
            holders,
        }
    }

    pub fn status(&self) -> WebcamStatus {
        self.last_status.clone()
    }

    pub fn unlock(&mut self, now: u64) -> Result<String, String> {
        let devices = list_video_devices();
        if devices.is_empty() {
            return Err("No /dev/video* webcam device found".to_string());
        }
        let count = set_video_devices_locked(false)?;
        let holders = scan_video_holders();
        self.unlocked = true;
        self.unlocked_at = now;
        self.ever_used = !holders.is_empty();
        self.idle_since = None;
        self.reported_pids = holders.iter().map(|h| h.pid).collect();
        self.refresh_status_now(now, devices, holders);

        Ok(format!(
            "Webcam UNLOCKED ({} device node(s) -> 0660 root:video; auto-locks after {}s idle or {}s unused)",
            count, IDLE_RELOCK_SECS, INITIAL_GRACE_SECS
        ))
    }

    pub fn lock(&mut self, now: u64, force_kill: bool) -> Result<String, String> {
        let mut holders = scan_video_holders();
        let mut killed_pids = Vec::new();
        if force_kill && !holders.is_empty() {
            let unique_pids: HashSet<i32> = holders.iter().map(|h| h.pid).collect();
            for pid in unique_pids {
                if pid > 1 {
                    unsafe {
                        libc::kill(pid, libc::SIGTERM);
                    }
                    killed_pids.push(pid);
                }
            }
            thread::sleep(Duration::from_millis(150));
            holders = scan_video_holders();
        }

        let count = set_video_devices_locked(true)?;
        self.unlocked = false;
        self.ever_used = false;
        self.idle_since = None;
        self.reported_pids.clear();

        let devices = list_video_devices();
        self.refresh_status_now(now, devices, holders.clone());

        if !killed_pids.is_empty() {
            killed_pids.sort_unstable();
            Ok(format!(
                "Webcam FORCE-LOCKED ({} device node(s) -> 0600 root:root; sent SIGTERM to PID {:?})",
                count, killed_pids
            ))
        } else if !holders.is_empty() {
            Ok(format!(
                "Webcam LOCKED ({} device node(s) -> 0600 root:root; note: {} holder(s) still have existing fd open)",
                count,
                holders.len()
            ))
        } else {
            Ok(format!(
                "Webcam LOCKED ({} device node(s) -> 0600 root:root)",
                count
            ))
        }
    }

    fn refresh_status_now(&mut self, now: u64, devices: Vec<String>, holders: Vec<WebcamHolder>) {
        let eval = evaluate_auto_lock(
            self.unlocked,
            self.ever_used,
            self.unlocked_at,
            self.idle_since,
            !holders.is_empty(),
            now,
        );
        self.last_status = WebcamStatus {
            has_device: !devices.is_empty(),
            devices,
            unlocked: self.unlocked,
            state: eval.state.to_string(),
            auto_lock_secs_remaining: eval.remaining_secs,
            holders,
        };
    }

    pub fn poll(&mut self, now: u64) -> (WebcamStatus, bool, Option<WebcamAlert>) {
        let devices = list_video_devices();
        let disk_unlocked = is_any_video_device_unlocked();
        let holders = scan_video_holders();
        let mut changed = false;
        let mut alert: Option<WebcamAlert> = None;

        // Reconcile if permissions were changed externally via sudo webcam-ctl / chmod.
        if !self.unlocked && disk_unlocked {
            self.unlocked = true;
            self.unlocked_at = now;
            self.ever_used = !holders.is_empty();
            self.idle_since = None;
            changed = true;
        } else if self.unlocked && !disk_unlocked {
            self.unlocked = false;
            self.ever_used = false;
            self.idle_since = None;
            self.reported_pids.clear();
            changed = true;
        }

        let has_holders = !holders.is_empty();
        if has_holders {
            self.ever_used = true;
            self.idle_since = None;

            self.reported_pids
                .retain(|p| holders.iter().any(|h| h.pid == *p));
            for h in &holders {
                if self.reported_pids.insert(h.pid) && alert.is_none() {
                    alert = Some(WebcamAlert {
                        severity: "INFO",
                        rule_id: "WEBCAM_IN_USE",
                        summary: format!(
                            "Webcam in use by {} (PID {}) on {}",
                            h.comm, h.pid, h.device
                        ),
                        pid: Some(h.pid),
                        exe: h.exe.clone(),
                    });
                }
            }
        } else {
            self.reported_pids.clear();
            if self.unlocked && self.ever_used && self.idle_since.is_none() {
                self.idle_since = Some(now);
                changed = true;
            }
        }

        let mut eval = evaluate_auto_lock(
            self.unlocked,
            self.ever_used,
            self.unlocked_at,
            self.idle_since,
            has_holders,
            now,
        );

        if let Some(reason) = eval.trigger_relock {
            let _ = set_video_devices_locked(true);
            self.unlocked = false;
            self.ever_used = false;
            self.idle_since = None;
            self.reported_pids.clear();
            changed = true;

            let summary = match reason {
                AutoLockReason::IdleAfterUse => format!(
                    "Auto-Lock: Webcam closed by all processes for {}s — locked /dev/video* to 0600 root:root",
                    IDLE_RELOCK_SECS
                ),
                AutoLockReason::UnusedGraceExpired => format!(
                    "Auto-Lock: Webcam unused for {}s grace window — locked /dev/video* to 0600 root:root",
                    INITIAL_GRACE_SECS
                ),
            };
            alert = Some(WebcamAlert {
                severity: "DEFENSE",
                rule_id: "WEBCAM_AUTO_LOCKED",
                summary,
                pid: None,
                exe: String::new(),
            });

            eval = evaluate_auto_lock(false, false, now, None, false, now);
        }

        let next_status = WebcamStatus {
            has_device: !devices.is_empty(),
            devices,
            unlocked: self.unlocked,
            state: eval.state.to_string(),
            auto_lock_secs_remaining: eval.remaining_secs,
            holders,
        };
        if next_status != self.last_status {
            changed = true;
        }
        self.last_status = next_status.clone();

        (next_status, changed, alert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unused_grace_window_counts_down_and_expires() {
        let unlocked_at = 1_000;
        let mid = evaluate_auto_lock(true, false, unlocked_at, None, false, 1_015);
        assert_eq!(mid.state, "WAITING");
        assert_eq!(mid.remaining_secs, Some(45));
        assert_eq!(mid.trigger_relock, None);

        let expired = evaluate_auto_lock(
            true,
            false,
            unlocked_at,
            None,
            false,
            unlocked_at + INITIAL_GRACE_SECS,
        );
        assert_eq!(expired.state, "LOCKED");
        assert_eq!(expired.remaining_secs, Some(0));
        assert_eq!(
            expired.trigger_relock,
            Some(AutoLockReason::UnusedGraceExpired)
        );
    }

    #[test]
    fn active_holder_stays_in_use_regardless_of_elapsed_time() {
        let active = evaluate_auto_lock(true, true, 1_000, None, true, 5_000);
        assert_eq!(active.state, "IN_USE");
        assert_eq!(active.remaining_secs, None);
        assert_eq!(active.trigger_relock, None);
    }

    #[test]
    fn post_use_idle_transitions_and_autolocks_after_five_seconds() {
        let idle = evaluate_auto_lock(true, true, 1_000, Some(2_000), false, 2_002);
        assert_eq!(idle.state, "IDLE_RELOCKING");
        assert_eq!(idle.remaining_secs, Some(3));
        assert_eq!(idle.trigger_relock, None);

        let locked = evaluate_auto_lock(
            true,
            true,
            1_000,
            Some(2_000),
            false,
            2_000 + IDLE_RELOCK_SECS,
        );
        assert_eq!(locked.state, "LOCKED");
        assert_eq!(locked.remaining_secs, Some(0));
        assert_eq!(locked.trigger_relock, Some(AutoLockReason::IdleAfterUse));
    }

    #[test]
    fn reopen_within_grace_cancels_idle_countdown() {
        let relocking = evaluate_auto_lock(true, true, 1_000, Some(2_000), false, 2_003);
        assert_eq!(relocking.state, "IDLE_RELOCKING");
        assert_eq!(relocking.remaining_secs, Some(2));

        // Holder reopens /dev/video0 at t=2004 -> idle_since cleared and stays IN_USE
        let reopened = evaluate_auto_lock(true, true, 1_000, None, true, 2_004);
        assert_eq!(reopened.state, "IN_USE");
        assert_eq!(reopened.remaining_secs, None);
        assert_eq!(reopened.trigger_relock, None);
    }
}
