pub mod actions;
pub mod dashboard;
pub mod fim;
pub mod mcp;
pub mod net_mon;
pub mod proc_mon;

use fim::{FimEntry, FimMonitor};
use net_mon::{NetConnection, NetMonitor};
use proc_mon::{ProcConnectorSocket, ProcEventRecord};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const RUN_DIR: &str = "/run/serenity-guard";
pub const STATUS_JSON_PATH: &str = "/run/serenity-guard/status.json";
pub const ALERTS_JSONL_PATH: &str = "/run/serenity-guard/alerts.jsonl";
pub const PID_FILE_PATH: &str = "/run/serenity-guard/daemon.pid";
pub const LOG_FILE_PATH: &str = "/run/serenity-guard/daemon.log";

const MAX_ALERTS: usize = 200;
const MAX_RECENT_PROCS: usize = 80;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub id: u64,
    pub timestamp_epoch: u64,
    pub severity: String, // "CRITICAL", "HIGH", "DEFENSE", "INFO"
    pub rule_id: String,
    pub summary: String,
    pub pid: Option<i32>,
    pub exe: String,
    pub remote_ip: String,
    pub local_addr: String,
    pub remote_addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardSnapshot {
    pub daemon_pid: i32,
    pub uptime_secs: u64,
    pub timestamp_epoch: u64,
    pub dashboard_url: String,
    pub auto_defend: bool,
    pub proc_connector_active: bool,
    pub blocked_ips: Vec<String>,
    pub alerts: Vec<SecurityAlert>,
    pub connections: Vec<NetConnection>,
    pub fim_entries: Vec<FimEntry>,
    pub recent_procs: Vec<ProcEventRecord>,
}

pub struct GuardState {
    pub started_epoch: u64,
    pub next_alert_id: u64,
    pub auto_defend: bool,
    pub proc_connector_active: bool,
    pub blocked_ips: Vec<String>,
    pub alerts: VecDeque<SecurityAlert>,
    pub connections: Vec<NetConnection>,
    pub fim_entries: Vec<FimEntry>,
    pub recent_procs: VecDeque<ProcEventRecord>,
    pub request_fim_rebaseline: bool,
}

impl GuardState {
    pub fn new(now: u64, proc_connector_active: bool) -> Self {
        Self {
            started_epoch: now,
            next_alert_id: 1,
            auto_defend: true,
            proc_connector_active,
            blocked_ips: Vec::new(),
            alerts: VecDeque::new(),
            connections: Vec::new(),
            fim_entries: Vec::new(),
            recent_procs: VecDeque::new(),
            request_fim_rebaseline: false,
        }
    }

    pub fn push_alert(
        &mut self,
        now: u64,
        severity: &str,
        rule_id: &str,
        summary: String,
        pid: Option<i32>,
        exe: String,
        remote_ip: String,
        local_addr: String,
        remote_addr: String,
    ) -> SecurityAlert {
        let alert = SecurityAlert {
            id: self.next_alert_id,
            timestamp_epoch: now,
            severity: severity.to_string(),
            rule_id: rule_id.to_string(),
            summary,
            pid,
            exe,
            remote_ip,
            local_addr,
            remote_addr,
        };
        self.next_alert_id += 1;
        self.alerts.push_front(alert.clone());
        while self.alerts.len() > MAX_ALERTS {
            self.alerts.pop_back();
        }
        append_alert_jsonl(&alert);
        alert
    }

    pub fn push_proc_event(&mut self, rec: ProcEventRecord) {
        self.recent_procs.push_front(rec);
        while self.recent_procs.len() > MAX_RECENT_PROCS {
            self.recent_procs.pop_back();
        }
    }

    pub fn build_snapshot(&self) -> GuardSnapshot {
        let now = epoch_now();
        GuardSnapshot {
            daemon_pid: unsafe { libc::getpid() },
            uptime_secs: now.saturating_sub(self.started_epoch),
            timestamp_epoch: now,
            dashboard_url: format!("http://{}", dashboard::DASHBOARD_BIND_ADDR),
            auto_defend: self.auto_defend,
            proc_connector_active: self.proc_connector_active,
            blocked_ips: self.blocked_ips.clone(),
            alerts: self.alerts.iter().cloned().collect(),
            connections: self.connections.clone(),
            fim_entries: self.fim_entries.clone(),
            recent_procs: self.recent_procs.iter().cloned().collect(),
        }
    }
}

#[derive(Clone)]
pub struct GuardShared {
    pub state: Arc<Mutex<GuardState>>,
    pub sse_subscribers: Arc<Mutex<Vec<mpsc::Sender<String>>>>,
}

impl GuardShared {
    pub fn broadcast_snapshot(&self) {
        let snap = {
            let st = self.state.lock().unwrap();
            st.build_snapshot()
        };
        let Ok(json_str) = serde_json::to_string(&snap) else {
            return;
        };

        // Write atomic snapshot to /run/serenity-guard/status.json (mode 0644 so Antigravity can read directly)
        let tmp_path = format!("{}.tmp", STATUS_JSON_PATH);
        if fs::write(&tmp_path, &json_str).is_ok() {
            let _ = fs::rename(&tmp_path, STATUS_JSON_PATH);
        }

        let sse_msg = format!("event: snapshot\ndata: {}\n\n", json_str);
        let mut subs = self.sse_subscribers.lock().unwrap();
        subs.retain(|tx| tx.send(sse_msg.clone()).is_ok());
    }

    pub fn execute_action(
        &self,
        action: &str,
        ip: &str,
        pid: i32,
        local_addr: &str,
        remote_addr: &str,
        enabled: bool,
    ) -> Result<String, String> {
        let now = epoch_now();
        let res = match action {
            "block_ip" => {
                let msg = actions::block_ip(ip)?;
                let mut st = self.state.lock().unwrap();
                let mut set = actions::load_blocked_ips();
                set.insert(ip.trim().to_string());
                let mut list: Vec<String> = set.into_iter().collect();
                list.sort();
                st.blocked_ips = list;
                st.push_alert(
                    now,
                    "DEFENSE",
                    "ACTIVE_BLOCK_IP",
                    msg.clone(),
                    None,
                    String::new(),
                    ip.trim().to_string(),
                    String::new(),
                    String::new(),
                );
                Ok(msg)
            }
            "unblock_ip" => {
                let msg = actions::unblock_ip(ip)?;
                let mut st = self.state.lock().unwrap();
                let mut list: Vec<String> = actions::load_blocked_ips().into_iter().collect();
                list.sort();
                st.blocked_ips = list;
                st.push_alert(
                    now,
                    "DEFENSE",
                    "ACTIVE_UNBLOCK_IP",
                    msg.clone(),
                    None,
                    String::new(),
                    ip.trim().to_string(),
                    String::new(),
                    String::new(),
                );
                Ok(msg)
            }
            "kill_socket" => {
                let msg = actions::kill_tcp_connection(local_addr, remote_addr)?;
                let mut st = self.state.lock().unwrap();
                st.push_alert(
                    now,
                    "DEFENSE",
                    "ACTIVE_SOCK_DESTROY",
                    msg.clone(),
                    None,
                    String::new(),
                    String::new(),
                    local_addr.to_string(),
                    remote_addr.to_string(),
                );
                Ok(msg)
            }
            "freeze_pid" => {
                let msg = actions::freeze_process(pid)?;
                let mut st = self.state.lock().unwrap();
                st.push_alert(
                    now,
                    "DEFENSE",
                    "ACTIVE_FREEZE_PID",
                    msg.clone(),
                    Some(pid),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                );
                Ok(msg)
            }
            "resume_pid" => {
                let msg = actions::resume_process(pid)?;
                let mut st = self.state.lock().unwrap();
                st.push_alert(
                    now,
                    "DEFENSE",
                    "ACTIVE_RESUME_PID",
                    msg.clone(),
                    Some(pid),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                );
                Ok(msg)
            }
            "kill_pid" => {
                let msg = actions::kill_process(pid)?;
                let mut st = self.state.lock().unwrap();
                st.push_alert(
                    now,
                    "DEFENSE",
                    "ACTIVE_KILL_PID",
                    msg.clone(),
                    Some(pid),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                );
                Ok(msg)
            }
            "set_auto_defend" => {
                let mut st = self.state.lock().unwrap();
                st.auto_defend = enabled;
                let msg = format!(
                    "Auto-Defend (automatic SIGSTOP + SOCK_DESTROY on critical reverse shells) is now {}",
                    if enabled { "ENABLED" } else { "DISABLED" }
                );
                st.push_alert(
                    now,
                    "INFO",
                    "CONFIG_AUTO_DEFEND",
                    msg.clone(),
                    None,
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                );
                Ok(msg)
            }
            "clear_alerts" => {
                let mut st = self.state.lock().unwrap();
                st.alerts.clear();
                Ok("Cleared alert history".to_string())
            }
            "rebaseline_fim" => {
                let mut st = self.state.lock().unwrap();
                st.request_fim_rebaseline = true;
                st.push_alert(
                    now,
                    "INFO",
                    "FIM_REBASELINED",
                    "Re-computed SHA-256 baseline for all core OS files".to_string(),
                    None,
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                );
                Ok("Requested SHA-256 FIM re-baseline".to_string())
            }
            "simulate_alert" => {
                let self_pid = unsafe { libc::getpid() };
                let mut st = self.state.lock().unwrap();
                st.push_alert(
                    now,
                    "CRITICAL",
                    "DRILL_SIMULATED_INTRUSION",
                    "SIMULATED DRILL: Reverse shell beacon detected to 198.51.100.77:4444 (use 'Block 198.51.100.77' or 'Inspect' to test active response)".to_string(),
                    Some(self_pid),
                    "/usr/bin/serenity-guard".to_string(),
                    "198.51.100.77".to_string(),
                    "127.0.0.1:55443".to_string(),
                    "198.51.100.77:4444".to_string(),
                );
                Ok("Triggered simulated intrusion drill alert".to_string())
            }
            _ => Err(format!("Unknown action: '{}'", action)),
        };

        self.broadcast_snapshot();
        res
    }
}

pub fn epoch_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn append_alert_jsonl(alert: &SecurityAlert) {
    if let Ok(line) = serde_json::to_string(alert) {
        if let Ok(mut f) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(ALERTS_JSONL_PATH)
        {
            let _ = writeln!(f, "{}", line);
        }
    }
}

fn run_daemon() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("serenity-guard daemon must run as root (UID 0)".to_string());
    }

    let _ = fs::create_dir_all(RUN_DIR);
    let my_pid = unsafe { libc::getpid() };
    let _ = fs::write(PID_FILE_PATH, format!("{}\n", my_pid));

    let now = epoch_now();
    let proc_sock = ProcConnectorSocket::open();
    let proc_active = proc_sock.is_some();

    let mut fim_mon = FimMonitor::new();
    let mut net_mon = NetMonitor::new();

    let blocked_set = actions::load_blocked_ips();
    let mut blocked_vec: Vec<String> = blocked_set.iter().cloned().collect();
    blocked_vec.sort();

    let (init_conns, _) = net_mon.scan(&blocked_set);
    let mut init_state = GuardState::new(now, proc_active);
    init_state.blocked_ips = blocked_vec;
    init_state.connections = init_conns;
    init_state.fim_entries = fim_mon.snapshot();
    init_state.push_alert(
        now,
        "INFO",
        "GUARD_DAEMON_STARTED",
        format!(
            "Serenity Guard active on http://{} (PROC_EVENTS={}, fanotify+SHA256={} core files, Auto-Defend=ON)",
            dashboard::DASHBOARD_BIND_ADDR,
            if proc_active { "ONLINE" } else { "OFFLINE" },
            init_state.fim_entries.len()
        ),
        Some(my_pid),
        "/usr/bin/serenity-guard".to_string(),
        String::new(),
        String::new(),
        String::new(),
    );

    let shared = GuardShared {
        state: Arc::new(Mutex::new(init_state)),
        sse_subscribers: Arc::new(Mutex::new(Vec::new())),
    };

    dashboard::spawn_http_server(shared.clone())?;
    shared.broadcast_snapshot();

    println!(
        "[serenity-guard] Daemon started (PID {}). SOC Dashboard: http://{}",
        my_pid,
        dashboard::DASHBOARD_BIND_ADDR
    );

    let mut tick: u64 = 0;
    loop {
        thread::sleep(Duration::from_millis(250));
        tick = tick.wrapping_add(1);
        let now = epoch_now();
        let mut changed = false;

        // 1. Poll real-time NETLINK_CONNECTOR PROC_EVENTS every 250ms
        if let Some(ref sock) = proc_sock {
            let events = sock.poll_events(now);
            if !events.is_empty() {
                let mut auto_actions: Vec<i32> = Vec::new();
                {
                    let mut st = shared.state.lock().unwrap();
                    for (rec, maybe_alert) in events {
                        if rec.kind == "EXEC" {
                            st.push_proc_event(rec.clone());
                            changed = true;
                        }
                        if let Some(a) = maybe_alert {
                            st.push_alert(
                                now,
                                a.severity,
                                a.rule_id,
                                a.summary,
                                Some(a.pid),
                                a.exe,
                                String::new(),
                                String::new(),
                                String::new(),
                            );
                            if st.auto_defend && a.recommend_freeze {
                                auto_actions.push(a.pid);
                            }
                            changed = true;
                        }
                    }
                }
                for bad_pid in auto_actions {
                    if let Ok(msg) = actions::freeze_process(bad_pid) {
                        let mut st = shared.state.lock().unwrap();
                        st.push_alert(
                            now,
                            "DEFENSE",
                            "AUTO_DEFEND_FREEZE",
                            format!("Auto-Defend: {}", msg),
                            Some(bad_pid),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                        );
                    }
                }
            }
        }

        // 2. Scan active sockets & FIM every 1.5s (6 ticks * 250ms)
        if tick % 6 == 0 {
            let do_rebaseline = {
                let mut st = shared.state.lock().unwrap();
                let r = st.request_fim_rebaseline;
                st.request_fim_rebaseline = false;
                r
            };
            if do_rebaseline {
                fim_mon.rebaseline();
                changed = true;
            }

            let fim_alerts = fim_mon.poll_changes();
            let fim_snap = fim_mon.snapshot();

            let blocked_set = actions::load_blocked_ips();
            let mut blocked_list: Vec<String> = blocked_set.iter().cloned().collect();
            blocked_list.sort();

            let (conns, net_alerts) = net_mon.scan(&blocked_set);

            let mut auto_freezes: Vec<i32> = Vec::new();
            let mut auto_cuts: Vec<(String, String)> = Vec::new();

            {
                let mut st = shared.state.lock().unwrap();
                if st.connections.len() != conns.len() || st.blocked_ips != blocked_list {
                    changed = true;
                }
                st.blocked_ips = blocked_list;
                st.connections = conns;
                st.fim_entries = fim_snap;

                for fa in fim_alerts {
                    st.push_alert(
                        now,
                        fa.severity,
                        fa.rule_id,
                        fa.summary,
                        fa.actor_pid,
                        fa.actor_exe.unwrap_or_default(),
                        String::new(),
                        String::new(),
                        String::new(),
                    );
                    changed = true;
                }

                for na in net_alerts {
                    st.push_alert(
                        now,
                        na.severity,
                        na.rule_id,
                        na.summary,
                        na.pid,
                        na.exe,
                        na.remote_ip,
                        na.local_addr.clone(),
                        na.remote_addr.clone(),
                    );
                    if st.auto_defend {
                        if na.recommend_kill_socket
                            && !na.local_addr.is_empty()
                            && !na.remote_addr.is_empty()
                        {
                            auto_cuts.push((na.local_addr, na.remote_addr));
                        }
                        if na.recommend_freeze {
                            if let Some(p) = na.pid {
                                auto_freezes.push(p);
                            }
                        }
                    }
                    changed = true;
                }
            }

            for (l_addr, r_addr) in auto_cuts {
                if let Ok(msg) = actions::kill_tcp_connection(&l_addr, &r_addr) {
                    let mut st = shared.state.lock().unwrap();
                    st.push_alert(
                        now,
                        "DEFENSE",
                        "AUTO_DEFEND_SOCK_DESTROY",
                        format!("Auto-Defend: {}", msg),
                        None,
                        String::new(),
                        String::new(),
                        l_addr,
                        r_addr,
                    );
                    changed = true;
                }
            }

            for bad_pid in auto_freezes {
                if let Ok(msg) = actions::freeze_process(bad_pid) {
                    let mut st = shared.state.lock().unwrap();
                    st.push_alert(
                        now,
                        "DEFENSE",
                        "AUTO_DEFEND_FREEZE",
                        format!("Auto-Defend: {}", msg),
                        Some(bad_pid),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                    );
                    changed = true;
                }
            }
        }

        // Broadcast SSE update on any change or every 3 seconds
        if changed || tick % 12 == 0 {
            shared.broadcast_snapshot();
        }
    }
}

fn is_daemon_running() -> Option<i32> {
    if let Ok(s) = fs::read_to_string(PID_FILE_PATH) {
        if let Ok(pid) = s.trim().parse::<i32>() {
            if pid > 1 && Path::new(&format!("/proc/{}", pid)).exists() {
                return Some(pid);
            }
        }
    }
    None
}

fn start_background_daemon() -> Result<(), String> {
    if let Some(pid) = is_daemon_running() {
        println!(
            "[serenity-guard] Daemon is already running (PID {}). Dashboard: http://{}",
            pid,
            dashboard::DASHBOARD_BIND_ADDR
        );
        return Ok(());
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err("Run 'sudo serenity-guard start' (root required)".to_string());
    }
    let _ = fs::create_dir_all(RUN_DIR);
    let log_file = fs::File::create(LOG_FILE_PATH)
        .map_err(|e| format!("Failed to open {}: {}", LOG_FILE_PATH, e))?;
    let err_file = log_file
        .try_clone()
        .map_err(|e| format!("Failed to clone log file handle: {}", e))?;

    let exe = std::env::current_exe().unwrap_or_else(|_| "/usr/bin/serenity-guard".into());
    let child = Command::new(exe)
        .arg("daemon")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log_file))
        .stderr(std::process::Stdio::from(err_file))
        .spawn()
        .map_err(|e| format!("Failed to spawn daemon: {}", e))?;

    println!(
        "[serenity-guard] Started background daemon (PID {}).",
        child.id()
    );
    println!(
        "[serenity-guard] Live Web SOC Dashboard: http://{}",
        dashboard::DASHBOARD_BIND_ADDR
    );
    Ok(())
}

fn stop_background_daemon() -> Result<(), String> {
    let Some(pid) = is_daemon_running() else {
        println!("[serenity-guard] Daemon is not running.");
        return Ok(());
    };
    if unsafe { libc::geteuid() } != 0 {
        return Err("Run 'sudo serenity-guard stop' (root required)".to_string());
    }
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let _ = fs::remove_file(PID_FILE_PATH);
    println!("[serenity-guard] Stopped daemon (PID {}).", pid);
    Ok(())
}

fn print_usage() {
    println!("Usage: serenity-guard <command> [args]");
    println!();
    println!("Commands:");
    println!("  start                          Start serenity-guard daemon in background (root)");
    println!("  stop                           Stop running serenity-guard daemon (root)");
    println!("  daemon                         Run serenity-guard daemon in foreground (root)");
    println!("  status [--json]                Show real-time security posture & summary");
    println!("  alerts [--json]                List recent security alerts");
    println!("  conns  [--json]                List active TCP/UDP sockets with owning PID/binary");
    println!("  fim    [--json]                Show SHA-256 + fanotify file integrity status");
    println!("  inspect <pid>                  Deep forensic dump of a PID (JSON)");
    println!("  block <ipv4>                   Block IPv4 in kernel nftables & blocked-ips.conf");
    println!("  unblock <ipv4>                 Unblock IPv4 in kernel nftables");
    println!("  kill-conn <src:port> <dst:port> Destroy active TCP socket via kernel SOCK_DESTROY");
    println!("  freeze <pid>                   Freeze suspicious process in RAM (SIGSTOP)");
    println!("  resume <pid>                   Resume frozen process (SIGCONT)");
    println!("  kill <pid>                     Terminate malicious process (SIGKILL)");
    println!("  mcp                            Run JSON-RPC 2.0 MCP server over stdio for AI agents");
}

fn load_snapshot_for_cli() -> Result<GuardSnapshot, String> {
    if let Ok(body) = mcp::http_get_local("/api/status") {
        if let Ok(snap) = serde_json::from_str::<GuardSnapshot>(&body) {
            return Ok(snap);
        }
    }
    if let Ok(content) = fs::read_to_string(STATUS_JSON_PATH) {
        if let Ok(snap) = serde_json::from_str::<GuardSnapshot>(&content) {
            return Ok(snap);
        }
    }
    // Live one-shot fallback if daemon is not started yet
    let now = epoch_now();
    let fim_mon = FimMonitor::new();
    let mut net_mon = NetMonitor::new();
    let blocked = actions::load_blocked_ips();
    let mut blocked_ips: Vec<String> = blocked.iter().cloned().collect();
    blocked_ips.sort();
    let (connections, _) = net_mon.scan(&blocked);
    Ok(GuardSnapshot {
        daemon_pid: 0,
        uptime_secs: 0,
        timestamp_epoch: now,
        dashboard_url: format!("http://{}", dashboard::DASHBOARD_BIND_ADDR),
        auto_defend: true,
        proc_connector_active: false,
        blocked_ips,
        alerts: Vec::new(),
        connections,
        fim_entries: fim_mon.snapshot(),
        recent_procs: Vec::new(),
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("status");
    let json_flag = args.iter().any(|a| a == "--json");

    let result: Result<(), String> = match cmd {
        "daemon" => run_daemon(),
        "start" => start_background_daemon(),
        "stop" => stop_background_daemon(),
        "mcp" => {
            mcp::run_mcp_stdio();
            Ok(())
        }
        "status" => match load_snapshot_for_cli() {
            Ok(snap) => {
                if json_flag {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&snap).unwrap_or_default()
                    );
                } else {
                    let crit = snap
                        .alerts
                        .iter()
                        .filter(|a| a.severity == "CRITICAL")
                        .count();
                    let high = snap.alerts.iter().filter(|a| a.severity == "HIGH").count();
                    let susp_conns = snap.connections.iter().filter(|c| c.suspicious).count();
                    let fim_ok = snap
                        .fim_entries
                        .iter()
                        .filter(|f| f.status == "OK")
                        .count();
                    println!("=== Serenity Guard Security Posture ===");
                    println!(
                        "Daemon Status : {}",
                        if snap.daemon_pid > 0 {
                            format!(
                                "RUNNING (PID {}, uptime {}s)",
                                snap.daemon_pid, snap.uptime_secs
                            )
                        } else {
                            "STOPPED (run 'sudo serenity-guard start')".to_string()
                        }
                    );
                    println!("SOC Dashboard : {}", snap.dashboard_url);
                    println!(
                        "Auto-Defend   : {}",
                        if snap.auto_defend { "ENABLED" } else { "DISABLED" }
                    );
                    println!(
                        "Alerts        : {} total ({} CRITICAL, {} HIGH)",
                        snap.alerts.len(),
                        crit,
                        high
                    );
                    println!(
                        "Active Sockets: {} total ({} suspicious)",
                        snap.connections.len(),
                        susp_conns
                    );
                    println!(
                        "FIM Integrity : {}/{} core files OK",
                        fim_ok,
                        snap.fim_entries.len()
                    );
                    println!(
                        "Blocked IPs   : {}",
                        if snap.blocked_ips.is_empty() {
                            "none".to_string()
                        } else {
                            snap.blocked_ips.join(", ")
                        }
                    );
                }
                Ok(())
            }
            Err(e) => Err(e),
        },
        "alerts" => match load_snapshot_for_cli() {
            Ok(snap) => {
                if json_flag {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&snap.alerts).unwrap_or_default()
                    );
                } else if snap.alerts.is_empty() {
                    println!("[serenity-guard] No security alerts.");
                } else {
                    for a in &snap.alerts {
                        println!(
                            "[#{}][{}][{}] {}",
                            a.id, a.severity, a.rule_id, a.summary
                        );
                    }
                }
                Ok(())
            }
            Err(e) => Err(e),
        },
        "conns" => match load_snapshot_for_cli() {
            Ok(snap) => {
                if json_flag {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&snap.connections).unwrap_or_default()
                    );
                } else {
                    println!(
                        "{:<6} {:<22} {:<22} {:<12} {:<8} {}",
                        "PROTO", "LOCAL", "REMOTE", "STATE", "PID", "PROCESS"
                    );
                    for c in &snap.connections {
                        let flag = if c.suspicious { "[!]" } else { "" };
                        println!(
                            "{:<6} {:<22} {:<22} {:<12} {:<8} {}{} ({})",
                            c.proto,
                            format!("{}:{}", c.local_ip, c.local_port),
                            format!("{}:{}", c.remote_ip, c.remote_port),
                            c.state,
                            c.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                            flag,
                            c.comm,
                            c.exe
                        );
                    }
                }
                Ok(())
            }
            Err(e) => Err(e),
        },
        "fim" => match load_snapshot_for_cli() {
            Ok(snap) => {
                if json_flag {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&snap.fim_entries).unwrap_or_default()
                    );
                } else {
                    println!(
                        "{:<34} {:<10} {:<6} {}",
                        "PATH", "STATUS", "MODE", "SHA-256"
                    );
                    for f in &snap.fim_entries {
                        println!(
                            "{:<34} {:<10} {:<6} {}",
                            f.path,
                            f.status,
                            f.mode_octal,
                            &f.current_sha256[..f.current_sha256.len().min(24)]
                        );
                    }
                }
                Ok(())
            }
            Err(e) => Err(e),
        },
        "inspect" => {
            let pid = args
                .get(1)
                .and_then(|s| s.parse::<i32>().ok())
                .ok_or_else(|| "Usage: serenity-guard inspect <pid>".to_string());
            pid.map(|p| {
                let rep = actions::inspect_process(p);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&rep).unwrap_or_default()
                );
            })
        }
        "block" => {
            let ip = args
                .get(1)
                .map(|s| s.as_str())
                .ok_or_else(|| "Usage: serenity-guard block <ipv4>".to_string());
            ip.and_then(|ip_str| {
                if let Ok(resp) = mcp::http_post_action(&json!({"action": "block_ip", "ip": ip_str})) {
                    println!("{}", resp);
                    Ok(())
                } else {
                    let msg = actions::block_ip(ip_str)?;
                    println!("[serenity-guard] {}", msg);
                    Ok(())
                }
            })
        }
        "unblock" => {
            let ip = args
                .get(1)
                .map(|s| s.as_str())
                .ok_or_else(|| "Usage: serenity-guard unblock <ipv4>".to_string());
            ip.and_then(|ip_str| {
                if let Ok(resp) = mcp::http_post_action(&json!({"action": "unblock_ip", "ip": ip_str})) {
                    println!("{}", resp);
                    Ok(())
                } else {
                    let msg = actions::unblock_ip(ip_str)?;
                    println!("[serenity-guard] {}", msg);
                    Ok(())
                }
            })
        }
        "kill-conn" => {
            if args.len() < 3 {
                Err("Usage: serenity-guard kill-conn <local_ipv4:port> <remote_ipv4:port>".to_string())
            } else {
                let l = &args[1];
                let r = &args[2];
                if let Ok(resp) = mcp::http_post_action(&json!({
                    "action": "kill_socket",
                    "local_addr": l,
                    "remote_addr": r
                })) {
                    println!("{}", resp);
                    Ok(())
                } else {
                    actions::kill_tcp_connection(l, r).map(|msg| {
                        println!("[serenity-guard] {}", msg);
                    })
                }
            }
        }
        "freeze" => {
            let pid = args
                .get(1)
                .and_then(|s| s.parse::<i32>().ok())
                .ok_or_else(|| "Usage: serenity-guard freeze <pid>".to_string());
            pid.and_then(|p| {
                if let Ok(resp) = mcp::http_post_action(&json!({"action": "freeze_pid", "pid": p})) {
                    println!("{}", resp);
                    Ok(())
                } else {
                    let msg = actions::freeze_process(p)?;
                    println!("[serenity-guard] {}", msg);
                    Ok(())
                }
            })
        }
        "resume" => {
            let pid = args
                .get(1)
                .and_then(|s| s.parse::<i32>().ok())
                .ok_or_else(|| "Usage: serenity-guard resume <pid>".to_string());
            pid.and_then(|p| {
                if let Ok(resp) = mcp::http_post_action(&json!({"action": "resume_pid", "pid": p})) {
                    println!("{}", resp);
                    Ok(())
                } else {
                    let msg = actions::resume_process(p)?;
                    println!("[serenity-guard] {}", msg);
                    Ok(())
                }
            })
        }
        "kill" => {
            let pid = args
                .get(1)
                .and_then(|s| s.parse::<i32>().ok())
                .ok_or_else(|| "Usage: serenity-guard kill <pid>".to_string());
            pid.and_then(|p| {
                if let Ok(resp) = mcp::http_post_action(&json!({"action": "kill_pid", "pid": p})) {
                    println!("{}", resp);
                    Ok(())
                } else {
                    let msg = actions::kill_process(p)?;
                    println!("[serenity-guard] {}", msg);
                    Ok(())
                }
            })
        }
        "-h" | "--help" | "help" => {
            print_usage();
            Ok(())
        }
        other => {
            print_usage();
            Err(format!("Unknown command: '{}'", other))
        }
    };

    if let Err(e) = result {
        eprintln!("[serenity-guard] error: {}", e);
        std::process::exit(1);
    }
}
