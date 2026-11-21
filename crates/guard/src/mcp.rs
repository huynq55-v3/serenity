use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn http_get_local(path: &str) -> Result<String, String> {
    let mut stream = TcpStream::connect_timeout(
        &"127.0.0.1:9443".parse().unwrap(),
        Duration::from_millis(800),
    )
    .map_err(|e| format!("serenity-guard daemon not reachable on 127.0.0.1:9443: {}", e))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: 127.0.0.1:9443\r\nConnection: close\r\n\r\n",
        path
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut resp = String::new();
    stream
        .read_to_string(&mut resp)
        .map_err(|e| e.to_string())?;
    let (_, body) = resp
        .split_once("\r\n\r\n")
        .unwrap_or(("", resp.as_str()));
    Ok(body.to_string())
}

pub fn http_post_action(payload: &Value) -> Result<String, String> {
    let body_str = payload.to_string();
    let mut stream = TcpStream::connect_timeout(
        &"127.0.0.1:9443".parse().unwrap(),
        Duration::from_millis(800),
    )
    .map_err(|e| format!("serenity-guard daemon not reachable on 127.0.0.1:9443: {}", e))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let req = format!(
        "POST /api/action HTTP/1.1\r\nHost: 127.0.0.1:9443\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body_str.len(),
        body_str
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut resp = String::new();
    stream
        .read_to_string(&mut resp)
        .map_err(|e| e.to_string())?;
    let (_, body) = resp
        .split_once("\r\n\r\n")
        .unwrap_or(("", resp.as_str()));
    Ok(body.to_string())
}

pub fn run_mcp_stdio() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines().flatten() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(req) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        if let Some(resp) = handle_mcp_message(&req) {
            let _ = writeln!(stdout, "{}", resp);
            let _ = stdout.flush();
        }
    }
}

pub fn handle_mcp_message(req: &Value) -> Option<Value> {
    let method = req.get("method")?.as_str()?;
    let id = req.get("id").cloned();

    // Notifications have no "id" and expect no response
    if id.is_none() {
        return None;
    }
    let id = id.unwrap();

    match method {
        "initialize" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "serenity-guard",
                    "version": "0.1.0"
                }
            }
        })),
        "ping" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {}
        })),
        "tools/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "tools": mcp_tool_definitions()
            }
        })),
        "tools/call" => {
            let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
            let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            let (is_error, text) = dispatch_mcp_tool(tool_name, &args);
            Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": text
                        }
                    ],
                    "isError": is_error
                }
            }))
        }
        _ => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32601,
                "message": format!("Method not found: {}", method)
            }
        })),
    }
}

fn mcp_tool_definitions() -> Value {
    json!([
        {
            "name": "guard_status",
            "description": "Get full real-time Serenity Guard security posture (alerts, active sockets, FIM status, blocked IPs).",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "guard_list_alerts",
            "description": "List recent security alerts and active response events.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "guard_list_connections",
            "description": "List all active TCP/UDP network connections and listeners with owning PID and executable.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "guard_inspect_process",
            "description": "Collect a deep forensic report for a PID (SHA-256 of binary, parent ancestry, open FDs/sockets, rwx memory mappings).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": { "type": "integer", "description": "Process ID to inspect" }
                },
                "required": ["pid"]
            }
        },
        {
            "name": "guard_block_ip",
            "description": "Immediately block an IPv4 address in the kernel nftables firewall (inet serenity_fw) and persist to /etc/serenity/blocked-ips.conf.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ip": { "type": "string", "description": "IPv4 address to block" }
                },
                "required": ["ip"]
            }
        },
        {
            "name": "guard_unblock_ip",
            "description": "Unblock a previously blocked IPv4 address in the kernel nftables firewall.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ip": { "type": "string", "description": "IPv4 address to unblock" }
                },
                "required": ["ip"]
            }
        },
        {
            "name": "guard_kill_connection",
            "description": "Forcibly terminate an active IPv4 TCP connection inside the Linux kernel via NETLINK_SOCK_DIAG SOCK_DESTROY.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "local_addr": { "type": "string", "description": "Local <ipv4>:<port>" },
                    "remote_addr": { "type": "string", "description": "Remote <ipv4>:<port>" }
                },
                "required": ["local_addr", "remote_addr"]
            }
        },
        {
            "name": "guard_freeze_process",
            "description": "Freeze a suspicious process in RAM with SIGSTOP so it cannot execute or erase forensic artifacts.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": { "type": "integer", "description": "Target PID to freeze" }
                },
                "required": ["pid"]
            }
        },
        {
            "name": "guard_resume_process",
            "description": "Resume a frozen process with SIGCONT.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": { "type": "integer", "description": "Target PID to resume" }
                },
                "required": ["pid"]
            }
        },
        {
            "name": "guard_kill_process",
            "description": "Immediately terminate a malicious process with SIGKILL.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": { "type": "integer", "description": "Target PID to terminate" }
                },
                "required": ["pid"]
            }
        }
    ])
}

fn dispatch_mcp_tool(name: &str, args: &Value) -> (bool, String) {
    match name {
        "guard_status" => match http_get_local("/api/status") {
            Ok(body) => (false, body),
            Err(_) => {
                if let Ok(disk) = std::fs::read_to_string("/run/serenity-guard/status.json") {
                    (false, disk)
                } else {
                    (true, "serenity-guard daemon is not running".to_string())
                }
            }
        },
        "guard_list_alerts" => match http_get_local("/api/alerts") {
            Ok(body) => (false, body),
            Err(e) => (true, e),
        },
        "guard_list_connections" => match http_get_local("/api/connections") {
            Ok(body) => (false, body),
            Err(e) => (true, e),
        },
        "guard_inspect_process" => {
            let pid = args.get("pid").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            match http_get_local(&format!("/api/inspect?pid={}", pid)) {
                Ok(body) => {
                    if let Ok(val) = serde_json::from_str::<Value>(&body) {
                        (
                            false,
                            serde_json::to_string_pretty(&val).unwrap_or(body),
                        )
                    } else {
                        (false, body)
                    }
                }
                Err(_) => {
                    let report = crate::actions::inspect_process(pid);
                    (
                        false,
                        serde_json::to_string_pretty(&report).unwrap_or_default(),
                    )
                }
            }
        }
        "guard_block_ip" => {
            let ip = args.get("ip").and_then(|v| v.as_str()).unwrap_or("");
            match http_post_action(&json!({ "action": "block_ip", "ip": ip })) {
                Ok(b) => (false, b),
                Err(_) => match crate::actions::block_ip(ip) {
                    Ok(m) => (false, m),
                    Err(e) => (true, e),
                },
            }
        }
        "guard_unblock_ip" => {
            let ip = args.get("ip").and_then(|v| v.as_str()).unwrap_or("");
            match http_post_action(&json!({ "action": "unblock_ip", "ip": ip })) {
                Ok(b) => (false, b),
                Err(_) => match crate::actions::unblock_ip(ip) {
                    Ok(m) => (false, m),
                    Err(e) => (true, e),
                },
            }
        }
        "guard_kill_connection" => {
            let local_addr = args
                .get("local_addr")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let remote_addr = args
                .get("remote_addr")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match http_post_action(&json!({
                "action": "kill_socket",
                "local_addr": local_addr,
                "remote_addr": remote_addr
            })) {
                Ok(b) => (false, b),
                Err(_) => match crate::actions::kill_tcp_connection(local_addr, remote_addr) {
                    Ok(m) => (false, m),
                    Err(e) => (true, e),
                },
            }
        }
        "guard_freeze_process" => {
            let pid = args.get("pid").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            match http_post_action(&json!({ "action": "freeze_pid", "pid": pid })) {
                Ok(b) => (false, b),
                Err(_) => match crate::actions::freeze_process(pid) {
                    Ok(m) => (false, m),
                    Err(e) => (true, e),
                },
            }
        }
        "guard_resume_process" => {
            let pid = args.get("pid").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            match http_post_action(&json!({ "action": "resume_pid", "pid": pid })) {
                Ok(b) => (false, b),
                Err(_) => match crate::actions::resume_process(pid) {
                    Ok(m) => (false, m),
                    Err(e) => (true, e),
                },
            }
        }
        "guard_kill_process" => {
            let pid = args.get("pid").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            match http_post_action(&json!({ "action": "kill_pid", "pid": pid })) {
                Ok(b) => (false, b),
                Err(_) => match crate::actions::kill_process(pid) {
                    Ok(m) => (false, m),
                    Err(e) => (true, e),
                },
            }
        }
        _ => (true, format!("Unknown MCP tool: {}", name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_initialize_and_tools_list() {
        let init_req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });
        let init_resp = handle_mcp_message(&init_req).unwrap();
        assert_eq!(init_resp["result"]["serverInfo"]["name"], "serenity-guard");

        let list_req = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        });
        let list_resp = handle_mcp_message(&list_req).unwrap();
        let tools = list_resp["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 10);
    }
}
