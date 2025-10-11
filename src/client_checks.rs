use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use ureq::serde_json::{json, Value};

// How recent the tower file must be to consider the node as voting.
const MASTER_WINDOW: Duration = Duration::from_millis(1000);

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

// Voting state detection via tower file age based on MASTER_WINDOW limit
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

/// Query local RPC getIdentity (default http://127.0.0.1:8899).
/// Returns Some(pubkey) on success, None otherwise.
pub fn local_identity(rpc_url: &str) -> Option<String> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getIdentity"
    });

    // Small timeout so we don’t block the tick.
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_millis(400))
        .build();

    let resp = agent.post(rpc_url)
        .set("Content-Type", "application/json")
        .send_json(body)
        .ok()?;

    let v: Value = resp.into_json().ok()?;
    v.get("result")
        .and_then(|r| r.get("identity"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
}

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