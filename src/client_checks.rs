use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use ureq::serde_json::{json, Value};

/// How recent the tower file must be to consider the node as voting.
const MASTER_WINDOW: Duration = Duration::from_millis(1000);

/* --------------------------- Tower / vote_state --------------------------- */

pub fn find_latest_tower(ledger_dir: &Path, pubkey: &str) -> Option<PathBuf> {
    let needle = format!("-{}.bin", pubkey);
    let mut best: Option<(SystemTime, PathBuf)> = None;
    let rd = std::fs::read_dir(ledger_dir).ok()?;
    for entry in rd.flatten() {
        let p = entry.path();
        if !p.is_file() { continue; }
        let name = match p.file_name().and_then(|s| s.to_str()) { Some(s) => s, None => continue };
        if !name.starts_with("tower-") || !name.ends_with(&needle) { continue; }
        if let Ok(meta) = entry.metadata() {
            if let Ok(mtime) = meta.modified() {
                match &best {
                    Some((best_time, _)) if mtime <= *best_time => {}
                    _ => best = Some((mtime, p.clone())),
                }
            }
        }
    }
    best.map(|(_, p)| p)
}

/// Voting state detection via tower file age based on MASTER_WINDOW limit.
pub fn vote_state_from_tower(ledger: Option<&str>, pubkey: Option<&str>) -> &'static str {
    let (Some(ledger_dir), Some(pk)) = (ledger, pubkey) else { return "unknown"; };
    let p = Path::new(ledger_dir);
    if !p.is_dir() { return "unknown"; }
    let Some(tower_path) = find_latest_tower(p, pk) else { return "non-voting"; };
    let Ok(meta) = std::fs::metadata(&tower_path) else { return "non-voting"; };
    let Ok(mtime) = meta.modified() else { return "non-voting"; };
    let Ok(age) = SystemTime::now().duration_since(mtime) else { return "voting"; };
    if age <= MASTER_WINDOW { "voting" } else { "non-voting" }
}

/* --------------------------- Local RPC identity -------------------------- */

/// Query local RPC getIdentity (default http://127.0.0.1:8899).
/// Returns Some(pubkey) on success, None otherwise.
pub fn local_identity(rpc_url: &str) -> Option<String> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getIdentity"
    });

    // Short timeout so a 500ms tick isn’t blocked.
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_millis(400))
        .build();

    let resp = agent
        .post(rpc_url)
        .set("Content-Type", "application/json")
        .send_json(body)
        .ok()?;

    let v: Value = resp.into_json().ok()?;
    v.get("result")
        .and_then(|r| r.get("identity"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
}

/* ----------------------------- Role derivation --------------------------- */

/// Decide role using identity if available; otherwise map from vote_state.
/// - If `client_running` and identity == pubkey -> "master", else "backup".
/// - Else: "voting" -> "master", "non-voting" -> "backup", else "unknown".
pub fn derive_role(
    client_running: bool,
    local_identity: Option<&str>,
    pubkey: Option<&str>,
    vote_state: &'static str,
) -> &'static str {
    if client_running {
        if let (Some(id), Some(pk)) = (local_identity, pubkey) {
            return if id == pk { "master" } else { "backup" };
        }
    }
    match vote_state {
        "voting" => "master",
        "non-voting" => "backup",
        _ => "unknown",
    }
}

/* --------------------- Process scan & version detection ------------------ */

fn read_cmdline(pid: &str) -> Option<Vec<String>> {
    let path = format!("/proc/{}/cmdline", pid);
    let mut f = File::open(path).ok()?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;
    let parts = buf
        .split(|b| *b == 0)
        .filter_map(|s| if s.is_empty() { None } else { Some(String::from_utf8_lossy(s).to_string()) })
        .collect::<Vec<_>>();
    if parts.is_empty() { None } else { Some(parts) }
}

fn list_processes() -> Vec<(String, Vec<String>)> {
    let mut v = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            let name = e.file_name();
            let pid = match name.to_str() { Some(s) => s, None => continue };
            if !pid.chars().all(|c| c.is_ascii_digit()) { continue; }
            if let Some(cmd) = read_cmdline(pid) {
                v.push((pid.to_string(), cmd));
            }
        }
    }
    v
}

fn exe_of(pid: &str) -> Option<String> {
    let p = format!("/proc/{}/exe", pid);
    std::fs::read_link(p).ok().and_then(|pb| pb.to_str().map(|s| s.to_string()))
}

/// Capture stdout+stderr; some builds print to stderr or return non-zero.
fn run_version(cmd: &str, arg: &str) -> Option<String> {
    let out = Command::new(cmd).arg(arg).output().ok()?;
    let mut s = String::new();
    s.push_str(&String::from_utf8_lossy(&out.stdout));
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    let s = s.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// Extract first dotted numeric (e.g., 3.0.4 or 0.708.20306) from an arbitrary string.
fn first_dotted_version(s: &str) -> Option<String> {
    let mut ver = String::new();
    let mut seen_digit = false;
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            ver.push(ch);
            seen_digit = true;
        } else if ch == '.' && seen_digit {
            ver.push(ch);
        } else if seen_digit {
            break;
        }
    }
    if ver.contains('.') { Some(ver) } else { None }
}

fn parse_agave_version(s: &str) -> (String, String) {
    // Default label for minimal change.
    let mut client = "agave-validator".to_string();

    // If the banner includes "client:XYZ", honor it.
    if let Some(idx) = s.find("client:") {
        let tail = &s[idx + 7..];
        if let Some(end) = tail.find(|c: char| c == ')' || c == ',' || c.is_whitespace()) {
            let extracted = tail[..end].trim();
            if !extracted.is_empty() {
                client = extracted.to_string();
            }
        } else {
            let extracted = tail.trim().trim_end_matches(')');
            if !extracted.is_empty() {
                client = extracted.to_string();
            }
        }
    }

    // Robustly extract dotted version anywhere in output
    let version = first_dotted_version(s).unwrap_or_else(|| "unknown".to_string());
    (client, version)
}

fn parse_fd_version(s: &str) -> (String, String) {
    let version = first_dotted_version(s).unwrap_or_else(|| "unknown".to_string());
    ("Firedancer".to_string(), version)
}

/// Public entry: detect running validator client and its version.
pub fn detect_client_and_version() -> (String, String) {
    let procs = list_processes();

    // 1) Agave (agave-validator)
    for (pid, cmd) in &procs {
        if cmd.iter().any(|p| p.contains("agave-validator")) {
            if let Some(exe) = exe_of(pid) {
                if let Some(s) = run_version(&exe, "--version") {
                    return parse_agave_version(&s);
                }
                return ("agave-validator".to_string(), "unknown".to_string());
            }
        }
    }

    // 2) Firedancer (fdctl)
    for (pid, cmd) in &procs {
        if cmd.iter().any(|p| p.contains("fdctl")) {
            if let Some(exe) = exe_of(pid) {
                if let Some(s) = run_version(&exe, "--version") {
                    return parse_fd_version(&s);
                }
                return ("Firedancer".to_string(), "unknown".to_string());
            }
        }
    }

    // 3) Nothing running
    ("not running".to_string(), "unknown".to_string())
}
