use crate::GuardShared;
use serde::Deserialize;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

pub const DASHBOARD_BIND_ADDR: &str = "127.0.0.1:9443";

#[derive(Debug, Deserialize)]
struct ActionRequest {
    action: String,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    pid: i32,
    #[serde(default)]
    local_addr: String,
    #[serde(default)]
    remote_addr: String,
    #[serde(default)]
    enabled: bool,
}

pub fn spawn_http_server(shared: GuardShared) -> Result<(), String> {
    let listener = TcpListener::bind(DASHBOARD_BIND_ADDR)
        .map_err(|e| format!("Failed to bind {}: {}", DASHBOARD_BIND_ADDR, e))?;

    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let shared_clone = shared.clone();
            thread::spawn(move || {
                let _ = handle_client(stream, shared_clone);
            });
        }
    });

    Ok(())
}

fn handle_client(mut stream: TcpStream, shared: GuardShared) -> Result<(), std::io::Error> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let cloned = stream.try_clone()?;
    let mut reader = BufReader::new(cloned);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }
    let method = parts[0];
    let raw_path = parts[1];

    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
    }

    let mut body = vec![0u8; content_length.min(65536)];
    if !body.is_empty() {
        reader.read_exact(&mut body)?;
    }

    let (path, query) = match raw_path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (raw_path, ""),
    };

    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => {
            write_response(
                &mut stream,
                "200 OK",
                "text/html; charset=utf-8",
                DASHBOARD_HTML.as_bytes(),
            )
        }
        ("GET", "/api/status") => {
            let json = {
                let st = shared.state.lock().unwrap();
                serde_json::to_string(&st.build_snapshot()).unwrap_or_else(|_| "{}".to_string())
            };
            write_response(&mut stream, "200 OK", "application/json", json.as_bytes())
        }
        ("GET", "/api/alerts") => {
            let json = {
                let st = shared.state.lock().unwrap();
                serde_json::to_string(&st.alerts).unwrap_or_else(|_| "[]".to_string())
            };
            write_response(&mut stream, "200 OK", "application/json", json.as_bytes())
        }
        ("GET", "/api/connections") => {
            let json = {
                let st = shared.state.lock().unwrap();
                serde_json::to_string(&st.connections).unwrap_or_else(|_| "[]".to_string())
            };
            write_response(&mut stream, "200 OK", "application/json", json.as_bytes())
        }
        ("GET", "/api/fim") => {
            let json = {
                let st = shared.state.lock().unwrap();
                serde_json::to_string(&st.fim_entries).unwrap_or_else(|_| "[]".to_string())
            };
            write_response(&mut stream, "200 OK", "application/json", json.as_bytes())
        }
        ("GET", "/api/inspect") => {
            let pid = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("pid="))
                .and_then(|v| v.parse::<i32>().ok())
                .unwrap_or(0);
            let report = {
                let mut st = shared.state.lock().unwrap();
                st.get_forensic_report(pid)
            };
            let json = serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string());
            write_response(&mut stream, "200 OK", "application/json", json.as_bytes())
        }
        ("GET", "/api/events") => handle_sse_stream(stream, shared),
        ("POST", "/api/action") => {
            let req: ActionRequest = match serde_json::from_slice(&body) {
                Ok(r) => r,
                Err(e) => {
                    let err_json = serde_json::json!({
                        "ok": false,
                        "message": format!("Invalid JSON request: {}", e),
                    });
                    return write_response(
                        &mut stream,
                        "400 Bad Request",
                        "application/json",
                        err_json.to_string().as_bytes(),
                    );
                }
            };
            let result = shared.execute_action(
                &req.action,
                &req.ip,
                req.pid,
                &req.local_addr,
                &req.remote_addr,
                req.enabled,
            );
            let resp_json = match result {
                Ok(msg) => serde_json::json!({ "ok": true, "message": msg }),
                Err(err) => serde_json::json!({ "ok": false, "message": err }),
            };
            write_response(
                &mut stream,
                "200 OK",
                "application/json",
                resp_json.to_string().as_bytes(),
            )
        }
        _ => write_response(
            &mut stream,
            "404 Not Found",
            "application/json",
            b"{\"error\":\"not found\"}",
        ),
    }
}

fn handle_sse_stream(mut stream: TcpStream, shared: GuardShared) -> Result<(), std::io::Error> {
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let headers = concat!(
        "HTTP/1.1 200 OK\r\n",
        "Content-Type: text/event-stream\r\n",
        "Cache-Control: no-cache\r\n",
        "Connection: keep-alive\r\n",
        "Access-Control-Allow-Origin: *\r\n\r\n"
    );
    stream.write_all(headers.as_bytes())?;
    stream.flush()?;

    let (tx, rx) = mpsc::channel::<String>();
    {
        let mut subs = shared.sse_subscribers.lock().unwrap();
        subs.push(tx);
    }

    // Push initial full snapshot immediately
    let init_json = {
        let st = shared.state.lock().unwrap();
        serde_json::to_string(&st.build_snapshot()).unwrap_or_else(|_| "{}".to_string())
    };
    stream.write_all(format!("event: snapshot\ndata: {}\n\n", init_json).as_bytes())?;
    stream.flush()?;

    loop {
        match rx.recv_timeout(Duration::from_secs(15)) {
            Ok(payload) => {
                if stream.write_all(payload.as_bytes()).is_err() || stream.flush().is_err() {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if stream.write_all(b": heartbeat\n\n").is_err() || stream.flush().is_err() {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    Ok(())
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> Result<(), std::io::Error> {
    let header = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        status,
        content_type,
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Serenity Guard // Real-Time HIDS & Active Defense</title>
<style>
  :root {
    --bg: #080c14;
    --panel: #0f1623;
    --panel-alt: #141d2f;
    --border: #1f2d46;
    --text: #e2e8f0;
    --muted: #8b9bb4;
    --accent: #38bdf8;
    --crit: #ef4444;
    --crit-bg: rgba(239, 68, 68, 0.14);
    --high: #f59e0b;
    --high-bg: rgba(245, 158, 11, 0.14);
    --ok: #10b981;
    --ok-bg: rgba(16, 185, 129, 0.14);
    --info: #3b82f6;
    --info-bg: rgba(59, 130, 246, 0.14);
    --mono: 'JetBrains Mono', 'Fira Code', 'DejaVu Sans Mono', monospace;
    --sans: 'Roboto', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 13px;
    line-height: 1.45;
    padding: 16px 20px;
  }
  header {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 14px 18px;
    background: linear-gradient(90deg, #0f172a 0%, #111c33 100%);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 16px;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .shield {
    width: 34px;
    height: 34px;
    border-radius: 8px;
    background: rgba(56, 189, 248, 0.15);
    border: 1px solid var(--accent);
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: var(--mono);
    font-weight: 800;
    color: var(--accent);
    font-size: 16px;
  }
  .brand h1 {
    font-size: 16px;
    font-weight: 700;
    letter-spacing: 0.5px;
    color: #f8fafc;
  }
  .brand p {
    font-size: 11px;
    color: var(--muted);
    font-family: var(--mono);
  }
  .header-controls {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
  }
  .live-pill {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 5px 11px;
    border-radius: 999px;
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 600;
    background: var(--ok-bg);
    color: var(--ok);
    border: 1px solid rgba(16, 185, 129, 0.35);
  }
  .live-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--ok);
    box-shadow: 0 0 8px var(--ok);
    animation: pulse 1.6s infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.35; }
  }
  button, .btn {
    background: var(--panel-alt);
    color: var(--text);
    border: 1px solid var(--border);
    padding: 6px 11px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.12s ease;
    font-family: var(--sans);
  }
  button:hover { border-color: var(--accent); color: #fff; }
  .btn-crit { background: var(--crit-bg); color: #fca5a5; border-color: rgba(239,68,68,0.4); }
  .btn-crit:hover { background: var(--crit); color: #fff; border-color: var(--crit); }
  .btn-warn { background: var(--high-bg); color: #fcd34d; border-color: rgba(245,158,11,0.4); }
  .btn-warn:hover { background: var(--high); color: #000; border-color: var(--high); }
  .btn-ok { background: var(--ok-bg); color: #6ee7b7; border-color: rgba(16,185,129,0.4); }
  .btn-ok:hover { background: var(--ok); color: #000; border-color: var(--ok); }
  .btn-info { background: var(--info-bg); color: #93c5fd; border-color: rgba(59,130,246,0.4); }
  .btn-info:hover { background: var(--info); color: #fff; border-color: var(--info); }
  .btn-xs { padding: 3px 8px; font-size: 11px; font-family: var(--mono); }

  .kpi-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 14px;
    margin-bottom: 16px;
  }
  .kpi-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px 16px;
  }
  .kpi-title {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.7px;
    color: var(--muted);
    margin-bottom: 6px;
    display: flex;
    justify-content: space-between;
  }
  .kpi-val {
    font-size: 22px;
    font-weight: 800;
    font-family: var(--mono);
    margin-bottom: 6px;
  }
  .kpi-sub {
    font-size: 11px;
    color: var(--muted);
    font-family: var(--mono);
  }

  .grid-2 {
    display: grid;
    grid-template-columns: 1.35fr 1fr;
    gap: 16px;
    margin-bottom: 16px;
  }
  @media (max-width: 1100px) {
    .grid-2 { grid-template-columns: 1fr; }
  }
  .panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }
  .panel-hdr {
    padding: 11px 15px;
    background: var(--panel-alt);
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
  }
  .panel-hdr h2 {
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 0.3px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .panel-body {
    padding: 0;
    max-height: 360px;
    overflow-y: auto;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  th {
    text-align: left;
    padding: 8px 12px;
    background: rgba(15, 23, 42, 0.7);
    color: var(--muted);
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    position: sticky;
    top: 0;
    border-bottom: 1px solid var(--border);
  }
  td {
    padding: 8px 12px;
    border-bottom: 1px solid rgba(31, 45, 70, 0.55);
    vertical-align: middle;
  }
  tr:hover td { background: rgba(56, 189, 248, 0.04); }
  tr.row-suspicious td { background: rgba(239, 68, 68, 0.09); }
  .mono { font-family: var(--mono); font-size: 11.5px; }
  .badge {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 4px;
    font-family: var(--mono);
    font-size: 10.5px;
    font-weight: 700;
  }
  .badge-CRITICAL { background: var(--crit-bg); color: #f87171; border: 1px solid rgba(239,68,68,0.4); }
  .badge-HIGH { background: var(--high-bg); color: #fbbf24; border: 1px solid rgba(245,158,11,0.4); }
  .badge-DEFENSE, .badge-OK { background: var(--ok-bg); color: #34d399; border: 1px solid rgba(16,185,129,0.4); }
  .badge-INFO { background: var(--info-bg); color: #60a5fa; border: 1px solid rgba(59,130,246,0.4); }
  .badge-MODIFIED, .badge-DELETED { background: var(--crit-bg); color: #f87171; border: 1px solid rgba(239,68,68,0.4); }

  .ip-input-row {
    display: flex;
    gap: 6px;
    margin-top: 8px;
  }
  input[type="text"] {
    background: #070b12;
    border: 1px solid var(--border);
    color: var(--text);
    padding: 5px 9px;
    border-radius: 5px;
    font-family: var(--mono);
    font-size: 12px;
    width: 150px;
  }
  input[type="text"]:focus { outline: none; border-color: var(--accent); }
  .chip-list {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 8px;
  }
  .ip-chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 2px 8px;
    border-radius: 4px;
    background: var(--crit-bg);
    border: 1px solid rgba(239,68,68,0.4);
    color: #fca5a5;
    font-family: var(--mono);
    font-size: 11px;
  }
  .ip-chip button {
    border: none;
    background: transparent;
    color: #fca5a5;
    padding: 0 2px;
    font-size: 12px;
    cursor: pointer;
  }
  .toast {
    position: fixed;
    bottom: 18px;
    right: 18px;
    padding: 11px 16px;
    border-radius: 8px;
    background: #1e293b;
    border: 1px solid var(--accent);
    color: #f8fafc;
    font-family: var(--mono);
    font-size: 12px;
    box-shadow: 0 10px 25px rgba(0,0,0,0.5);
    display: none;
    z-index: 1000;
  }
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(3, 7, 18, 0.78);
    display: none;
    align-items: center;
    justify-content: center;
    z-index: 900;
    padding: 20px;
  }
  .modal {
    background: var(--panel);
    border: 1px solid var(--accent);
    border-radius: 10px;
    max-width: 780px;
    width: 100%;
    max-height: 85vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .modal-body {
    padding: 14px 16px;
    overflow-y: auto;
    font-family: var(--mono);
    font-size: 12px;
    white-space: pre-wrap;
  }
  .action-bar { display: flex; gap: 5px; flex-wrap: wrap; }
  @keyframes critFlash {
    0%, 100% { box-shadow: inset 0 0 0 0 rgba(239, 68, 68, 0); }
    25%, 75% { box-shadow: inset 0 0 0 4px rgba(239, 68, 68, 0.9), inset 0 0 48px rgba(239, 68, 68, 0.35); }
  }
  body.alert-flash {
    animation: critFlash 0.9s ease-in-out 2;
  }
</style>
</head>
<body>

<header>
  <div class="brand">
    <div class="shield">SG</div>
    <div>
      <h1>SERENITY GUARD // REAL-TIME HIDS &amp; ACTIVE DEFENSE</h1>
      <p id="host-subtitle">Kernel 6.18.32-serenity • NETLINK_CONNECTOR • fanotify • SOCK_DESTROY • nftables</p>
    </div>
  </div>
  <div class="header-controls">
    <div class="live-pill" id="sse-pill">
      <span class="live-dot" id="sse-dot"></span>
      <span id="sse-text">LIVE SSE STREAM</span>
    </div>
    <button id="btn-autodefend" class="btn-ok" onclick="toggleAutoDefend()">Auto-Defend: ON</button>
    <button id="btn-siren" class="btn-ok" onclick="toggleSirenAndNoti()">🔔 Siren &amp; Noti: ON</button>
    <button class="btn-info" onclick="testSirenAndNoti()">🔊 Test Alarm</button>
    <button class="btn-warn" onclick="simulateDrill()">Simulate Attack Drill</button>
    <button onclick="clearAlerts()">Clear Alerts</button>
  </div>
</header>

<div class="kpi-grid">
  <div class="kpi-card">
    <div class="kpi-title"><span>SECURITY ALERTS</span><span id="kpi-alert-crit" class="badge badge-CRITICAL">0 CRIT</span></div>
    <div class="kpi-val" id="kpi-alerts-total">0</div>
    <div class="kpi-sub" id="kpi-alerts-sub">0 High • 0 Defense Actions</div>
  </div>

  <div class="kpi-card">
    <div class="kpi-title"><span>ACTIVE SOCKETS</span><span id="kpi-conn-susp" class="badge badge-OK">0 SUSPICIOUS</span></div>
    <div class="kpi-val" id="kpi-conns-total">0</div>
    <div class="kpi-sub" id="kpi-conns-sub">0 ESTABLISHED • 0 LISTEN</div>
  </div>

  <div class="kpi-card">
    <div class="kpi-title"><span>CORE FILE INTEGRITY (FIM)</span><span id="kpi-fim-badge" class="badge badge-OK">ALL INTACT</span></div>
    <div class="kpi-val" id="kpi-fim-val">0 / 0</div>
    <div class="kpi-sub">SHA-256 + fanotify real-time watchdog</div>
  </div>

  <div class="kpi-card">
    <div class="kpi-title"><span>NFTABLES FIREWALL</span><span class="badge badge-OK">INPUT=DROP</span></div>
    <div class="ip-input-row">
      <input type="text" id="block-ip-input" placeholder="e.g. 198.51.100.77" />
      <button class="btn-crit btn-xs" onclick="blockIpFromInput()">Block IP</button>
    </div>
    <div class="chip-list" id="blocked-ips-chips"></div>
  </div>
</div>

<div class="grid-2">
  <div class="panel">
    <div class="panel-hdr">
      <h2><span>⚡ LIVE SECURITY ALERTS &amp; ACTIVE RESPONSE</span></h2>
      <span class="mono" style="color:var(--muted)" id="alerts-count-label">0 events</span>
    </div>
    <div class="panel-body">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Severity</th>
            <th>Rule / Source</th>
            <th>Details</th>
            <th>1-Click Active Response</th>
          </tr>
        </thead>
        <tbody id="alerts-tbody"></tbody>
      </table>
    </div>
  </div>

  <div class="panel">
    <div class="panel-hdr">
      <h2><span>🌐 ACTIVE NETWORK CONNECTIONS (SOCK_DIAG)</span></h2>
      <span class="mono" style="color:var(--muted)" id="conns-count-label">0 sockets</span>
    </div>
    <div class="panel-body">
      <table>
        <thead>
          <tr>
            <th>Proto</th>
            <th>Local</th>
            <th>Remote</th>
            <th>State</th>
            <th>Process (PID)</th>
            <th>Response</th>
          </tr>
        </thead>
        <tbody id="conns-tbody"></tbody>
      </table>
    </div>
  </div>
</div>

<div class="grid-2">
  <div class="panel">
    <div class="panel-hdr">
      <h2><span>🛡️ CORE FILE INTEGRITY WATCHDOG (SHA-256 + FANOTIFY)</span></h2>
      <button class="btn-xs btn-info" onclick="rebaselineFim()">Re-Baseline SHA-256</button>
    </div>
    <div class="panel-body">
      <table>
        <thead>
          <tr>
            <th>Core Path</th>
            <th>Status</th>
            <th>Mode</th>
            <th>Baseline SHA-256</th>
            <th>Current SHA-256</th>
            <th>Last Writer</th>
          </tr>
        </thead>
        <tbody id="fim-tbody"></tbody>
      </table>
    </div>
  </div>

  <div class="panel">
    <div class="panel-hdr">
      <h2><span>⚙️ REAL-TIME PROCESS EXEC STREAM (NETLINK PROC_EVENTS)</span></h2>
      <span class="mono" style="color:var(--muted)" id="procs-count-label">0 execs</span>
    </div>
    <div class="panel-body">
      <table>
        <thead>
          <tr>
            <th>PID / PPID</th>
            <th>UID</th>
            <th>Binary</th>
            <th>Command Line</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody id="procs-tbody"></tbody>
      </table>
    </div>
  </div>
</div>

<div class="modal-backdrop" id="inspect-modal" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <div class="panel-hdr">
      <h2 id="modal-title">Forensic Process Inspection</h2>
      <div class="action-bar" id="modal-actions"></div>
    </div>
    <div class="modal-body" id="modal-content">Loading...</div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
let currentState = null;
let alarmEnabled = true;
let audioCtx = null;
let lastMaxAlertId = null;

function ensureAudioAndNotiPermission() {
  if (!audioCtx && (window.AudioContext || window.webkitAudioContext)) {
    const Ctx = window.AudioContext || window.webkitAudioContext;
    audioCtx = new Ctx();
  }
  if (audioCtx && audioCtx.state === 'suspended') {
    audioCtx.resume().catch(() => {});
  }
  if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission().catch(() => {});
  }
}

document.addEventListener('click', () => ensureAudioAndNotiPermission(), { once: true });

function playSiren(severity) {
  if (!alarmEnabled) return;
  try {
    ensureAudioAndNotiPermission();
    if (!audioCtx) return;
    const now = audioCtx.currentTime;
    if (severity === 'CRITICAL') {
      // 6 alternating dual-tone klaxon sweeps (960Hz <-> 1440Hz)
      for (let i = 0; i < 6; i++) {
        const start = now + i * 0.28;
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(i % 2 === 0 ? 960 : 1440, start);
        osc.frequency.linearRampToValueAtTime(i % 2 === 0 ? 1440 : 960, start + 0.26);
        gain.gain.setValueAtTime(0.001, start);
        gain.gain.exponentialRampToValueAtTime(0.28, start + 0.03);
        gain.gain.exponentialRampToValueAtTime(0.001, start + 0.27);
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start(start);
        osc.stop(start + 0.28);
      }
    } else {
      // 3 sharp double-beeps for HIGH severity
      for (let i = 0; i < 3; i++) {
        const start = now + i * 0.22;
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(780, start);
        gain.gain.setValueAtTime(0.001, start);
        gain.gain.exponentialRampToValueAtTime(0.22, start + 0.02);
        gain.gain.exponentialRampToValueAtTime(0.001, start + 0.16);
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start(start);
        osc.stop(start + 0.17);
      }
    }
  } catch (_) {}
}

function fireBrowserNotification(alertObj) {
  document.body.classList.remove('alert-flash');
  void document.body.offsetWidth;
  document.body.classList.add('alert-flash');
  setTimeout(() => document.body.classList.remove('alert-flash'), 2500);

  if (!alarmEnabled || !('Notification' in window)) return;
  if (Notification.permission === 'granted') {
    try {
      new Notification(`🚨 SERENITY GUARD [${alertObj.severity}]`, {
        body: `${alertObj.rule_id}: ${alertObj.summary}`,
        tag: 'serenity-guard-' + alertObj.id,
        requireInteraction: alertObj.severity === 'CRITICAL'
      });
    } catch (_) {}
  }
}

function toggleSirenAndNoti() {
  alarmEnabled = !alarmEnabled;
  if (alarmEnabled) ensureAudioAndNotiPermission();
  const btn = document.getElementById('btn-siren');
  btn.textContent = alarmEnabled ? '🔔 Siren & Noti: ON' : '🔕 Siren & Noti: OFF';
  btn.className = alarmEnabled ? 'btn-ok' : 'btn-warn';
  showToast('Audio Siren & Chrome Notifications ' + (alarmEnabled ? 'ENABLED' : 'MUTED'), !alarmEnabled);
}

function testSirenAndNoti() {
  alarmEnabled = true;
  const btn = document.getElementById('btn-siren');
  btn.textContent = '🔔 Siren & Noti: ON';
  btn.className = 'btn-ok';
  ensureAudioAndNotiPermission();
  playSiren('CRITICAL');
  const sendTestNoti = () => {
    fireBrowserNotification({
      id: 'test-' + Date.now(),
      severity: 'CRITICAL',
      rule_id: 'TEST_ALARM',
      summary: 'Serenity Guard siren & Chrome notification alarm active!'
    });
  };
  if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission().then(sendTestNoti).catch(() => {});
  } else {
    sendTestNoti();
  }
  showToast('Testing SOC Siren & Chrome Desktop Notification...', false);
}

function showToast(msg, isErr) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.borderColor = isErr ? 'var(--crit)' : 'var(--accent)';
  t.style.display = 'block';
  setTimeout(() => { t.style.display = 'none'; }, 3800);
}

function fmtTime(epoch) {
  if (!epoch) return '--:--:--';
  const d = new Date(epoch * 1000);
  return d.toTimeString().split(' ')[0];
}

function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

async function apiAction(payload) {
  try {
    const res = await fetch('/api/action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    showToast(data.message || (data.ok ? 'Action executed' : 'Action failed'), !data.ok);
    await refreshStatus();
  } catch (e) {
    showToast('Request error: ' + e, true);
  }
}

function blockIp(ip) {
  if (!ip) return;
  apiAction({ action: 'block_ip', ip });
}
function unblockIp(ip) {
  if (!ip) return;
  apiAction({ action: 'unblock_ip', ip });
}
function blockIpFromInput() {
  const el = document.getElementById('block-ip-input');
  const ip = el.value.trim();
  if (!ip) return;
  el.value = '';
  blockIp(ip);
}
function killSocket(local_addr, remote_addr) {
  apiAction({ action: 'kill_socket', local_addr, remote_addr });
}
function freezePid(pid) {
  apiAction({ action: 'freeze_pid', pid: Number(pid) });
}
function resumePid(pid) {
  apiAction({ action: 'resume_pid', pid: Number(pid) });
}
function killPid(pid) {
  apiAction({ action: 'kill_pid', pid: Number(pid) });
}
function toggleAutoDefend() {
  const next = !(currentState && currentState.auto_defend);
  apiAction({ action: 'set_auto_defend', enabled: next });
}
function clearAlerts() {
  apiAction({ action: 'clear_alerts' });
}
function rebaselineFim() {
  apiAction({ action: 'rebaseline_fim' });
}
function simulateDrill() {
  ensureAudioAndNotiPermission();
  apiAction({ action: 'simulate_alert' });
}

async function inspectPid(pid) {
  if (!pid) return;
  const modal = document.getElementById('inspect-modal');
  const content = document.getElementById('modal-content');
  const title = document.getElementById('modal-title');
  const actions = document.getElementById('modal-actions');
  title.textContent = 'Forensic Process Report // PID ' + pid;
  content.textContent = 'Collecting /proc/' + pid + ' forensic snapshot...';
  actions.innerHTML = `
    <button class="btn-xs btn-warn" onclick="freezePid(${pid})">Freeze (SIGSTOP)</button>
    <button class="btn-xs btn-ok" onclick="resumePid(${pid})">Resume (SIGCONT)</button>
    <button class="btn-xs btn-crit" onclick="killPid(${pid})">Kill (SIGKILL)</button>
    <button class="btn-xs" onclick="closeModal()">Close</button>
  `;
  modal.style.display = 'flex';
  try {
    const res = await fetch('/api/inspect?pid=' + encodeURIComponent(pid));
    const rep = await res.json();
    content.textContent = JSON.stringify(rep, null, 2);
  } catch (e) {
    content.textContent = 'Error inspecting PID ' + pid + ': ' + e;
  }
}

function closeModal() {
  document.getElementById('inspect-modal').style.display = 'none';
}

function renderSnapshot(st) {
  currentState = st;

  const btnAuto = document.getElementById('btn-autodefend');
  btnAuto.textContent = 'Auto-Defend: ' + (st.auto_defend ? 'ON' : 'OFF');
  btnAuto.className = st.auto_defend ? 'btn-ok' : 'btn-warn';

  // KPI: Alerts
  const alerts = st.alerts || [];
  const maxId = alerts.reduce((m, a) => Math.max(m, Number(a.id) || 0), 0);
  if (lastMaxAlertId === null) {
    lastMaxAlertId = maxId;
  } else if (maxId > lastMaxAlertId) {
    const newAlerts = alerts.filter(a => (Number(a.id) || 0) > lastMaxAlertId);
    lastMaxAlertId = maxId;
    const urgent = newAlerts.filter(a => a.severity === 'CRITICAL' || a.severity === 'HIGH');
    if (urgent.length > 0) {
      const hasCrit = urgent.some(a => a.severity === 'CRITICAL');
      playSiren(hasCrit ? 'CRITICAL' : 'HIGH');
      fireBrowserNotification(urgent[0]);
    }
  }
  const critCount = alerts.filter(a => a.severity === 'CRITICAL').length;
  const highCount = alerts.filter(a => a.severity === 'HIGH').length;
  const defCount = alerts.filter(a => a.severity === 'DEFENSE').length;
  document.getElementById('kpi-alerts-total').textContent = alerts.length;
  document.getElementById('kpi-alert-crit').textContent = critCount + ' CRIT';
  document.getElementById('kpi-alerts-sub').textContent = `${highCount} High • ${defCount} Active Responses`;

  // KPI: Sockets
  const conns = st.connections || [];
  const suspConns = conns.filter(c => c.suspicious).length;
  const estConns = conns.filter(c => c.state === 'ESTABLISHED').length;
  const lisConns = conns.filter(c => c.state === 'LISTEN').length;
  document.getElementById('kpi-conns-total').textContent = conns.length;
  const connBadge = document.getElementById('kpi-conn-susp');
  connBadge.textContent = suspConns + ' SUSPICIOUS';
  connBadge.className = 'badge ' + (suspConns > 0 ? 'badge-CRITICAL' : 'badge-OK');
  document.getElementById('kpi-conns-sub').textContent = `${estConns} ESTABLISHED • ${lisConns} LISTEN`;

  // KPI: FIM
  const fim = st.fim_entries || [];
  const fimOk = fim.filter(f => f.status === 'OK').length;
  const fimMod = fim.filter(f => f.status !== 'OK' && f.status !== 'MISSING').length;
  document.getElementById('kpi-fim-val').textContent = `${fimOk} / ${fim.length}`;
  const fimBadge = document.getElementById('kpi-fim-badge');
  fimBadge.textContent = fimMod > 0 ? `${fimMod} TAMPERED` : 'ALL INTACT';
  fimBadge.className = 'badge ' + (fimMod > 0 ? 'badge-CRITICAL' : 'badge-OK');

  // KPI: Blocked IPs
  const chips = document.getElementById('blocked-ips-chips');
  const blocked = st.blocked_ips || [];
  if (blocked.length === 0) {
    chips.innerHTML = '<span class="mono" style="color:var(--muted);font-size:11px">No blocked IPs</span>';
  } else {
    chips.innerHTML = blocked.map(ip => `
      <span class="ip-chip">${esc(ip)}
        <button title="Unblock ${esc(ip)}" onclick="unblockIp('${esc(ip)}')">×</button>
      </span>
    `).join('');
  }

  // Alerts table
  document.getElementById('alerts-count-label').textContent = alerts.length + ' events';
  const aTbody = document.getElementById('alerts-tbody');
  if (alerts.length === 0) {
    aTbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:24px">No security alerts recorded. System clean.</td></tr>';
  } else {
    aTbody.innerHTML = alerts.map(a => {
      let btns = [];
      if (a.pid) {
        btns.push(`<button class="btn-xs btn-info" onclick="inspectPid(${a.pid})">Inspect ${a.pid}</button>`);
        btns.push(`<button class="btn-xs btn-warn" onclick="freezePid(${a.pid})">Freeze</button>`);
        btns.push(`<button class="btn-xs btn-ok" onclick="resumePid(${a.pid})">Resume</button>`);
        btns.push(`<button class="btn-xs btn-crit" onclick="killPid(${a.pid})">Kill</button>`);
      }
      if (a.local_addr && a.remote_addr && a.remote_addr !== '0.0.0.0:0') {
        btns.push(`<button class="btn-xs btn-warn" onclick="killSocket('${esc(a.local_addr)}','${esc(a.remote_addr)}')">Cut TCP</button>`);
      }
      if (a.remote_ip && a.remote_ip !== '127.0.0.1' && a.remote_ip !== '0.0.0.0') {
        btns.push(`<button class="btn-xs btn-crit" onclick="blockIp('${esc(a.remote_ip)}')">Block ${esc(a.remote_ip)}</button>`);
      }
      return `
        <tr>
          <td class="mono">${fmtTime(a.timestamp_epoch)}</td>
          <td><span class="badge badge-${esc(a.severity)}">${esc(a.severity)}</span></td>
          <td class="mono">${esc(a.rule_id)}</td>
          <td>${esc(a.summary)}</td>
          <td><div class="action-bar">${btns.join('')}</div></td>
        </tr>
      `;
    }).join('');
  }

  // Connections table
  document.getElementById('conns-count-label').textContent = conns.length + ' sockets';
  const cTbody = document.getElementById('conns-tbody');
  cTbody.innerHTML = conns.map(c => {
    const localAddr = `${c.local_ip}:${c.local_port}`;
    const remoteAddr = `${c.remote_ip}:${c.remote_port}`;
    let btns = [];
    if (c.proto === 'tcp' && c.state === 'ESTABLISHED') {
      btns.push(`<button class="btn-xs btn-warn" onclick="killSocket('${esc(localAddr)}','${esc(remoteAddr)}')">Cut TCP</button>`);
    }
    if (c.remote_ip && c.remote_ip !== '0.0.0.0' && c.remote_ip !== '127.0.0.1' && c.remote_ip !== '::' && c.remote_ip !== '::1' && !c.remote_ip.includes(':')) {
      btns.push(`<button class="btn-xs btn-crit" onclick="blockIp('${esc(c.remote_ip)}')">Block IP</button>`);
    }
    if (c.pid) {
      btns.push(`<button class="btn-xs btn-info" onclick="inspectPid(${c.pid})">Inspect</button>`);
      btns.push(`<button class="btn-xs btn-warn" onclick="freezePid(${c.pid})">Freeze</button>`);
    }
    return `
      <tr class="${c.suspicious ? 'row-suspicious' : ''}">
        <td class="mono">${esc(c.proto)}</td>
        <td class="mono">${esc(localAddr)}</td>
        <td class="mono">${esc(remoteAddr)}</td>
        <td><span class="badge ${c.suspicious ? 'badge-CRITICAL' : 'badge-INFO'}">${esc(c.state)}</span></td>
        <td class="mono" title="${esc(c.exe)}">${esc(c.comm || '-')} ${c.pid ? '(' + c.pid + ')' : ''}</td>
        <td><div class="action-bar">${btns.join('')}</div></td>
      </tr>
    `;
  }).join('');

  // FIM table
  const fTbody = document.getElementById('fim-tbody');
  fTbody.innerHTML = fim.map(f => {
    const writer = f.last_modified_by_pid ? `PID ${f.last_modified_by_pid} (${f.last_modified_by_exe || ''})` : '-';
    return `
      <tr>
        <td class="mono">${esc(f.path)}</td>
        <td><span class="badge badge-${esc(f.status)}">${esc(f.status)}</span></td>
        <td class="mono">${esc(f.mode_octal || '-')}</td>
        <td class="mono">${esc((f.baseline_sha256 || '').slice(0, 16))}</td>
        <td class="mono">${esc((f.current_sha256 || '').slice(0, 16))}</td>
        <td class="mono">${esc(writer)}</td>
      </tr>
    `;
  }).join('');

  // Process stream table
  const procs = st.recent_procs || [];
  document.getElementById('procs-count-label').textContent = procs.length + ' recent';
  const pTbody = document.getElementById('procs-tbody');
  pTbody.innerHTML = procs.map(p => `
    <tr>
      <td class="mono">${p.pid} <span style="color:var(--muted)">← ${p.ppid} (${esc(p.parent_comm)})</span></td>
      <td class="mono">${p.uid}${p.euid !== p.uid ? '→' + p.euid : ''}</td>
      <td class="mono">${esc(p.exe || p.comm)}</td>
      <td class="mono" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(p.cmdline)}">${esc(p.cmdline || p.comm)}</td>
      <td>
        <div class="action-bar">
          <button class="btn-xs btn-info" onclick="inspectPid(${p.pid})">Inspect</button>
          <button class="btn-xs btn-warn" onclick="freezePid(${p.pid})">Freeze</button>
          <button class="btn-xs btn-crit" onclick="killPid(${p.pid})">Kill</button>
        </div>
      </td>
    </tr>
  `).join('');
}

async function refreshStatus() {
  try {
    const res = await fetch('/api/status');
    const st = await res.json();
    renderSnapshot(st);
  } catch (e) {}
}

function connectSse() {
  const es = new EventSource('/api/events');
  const dot = document.getElementById('sse-dot');
  const txt = document.getElementById('sse-text');
  es.addEventListener('snapshot', (e) => {
    try { renderSnapshot(JSON.parse(e.data)); } catch (_) {}
  });
  es.onopen = () => {
    dot.style.background = 'var(--ok)';
    txt.textContent = 'LIVE SSE STREAM';
  };
  es.onerror = () => {
    dot.style.background = 'var(--high)';
    txt.textContent = 'RECONNECTING...';
  };
}

refreshStatus();
connectSse();
</script>
</body>
</html>
"#;
