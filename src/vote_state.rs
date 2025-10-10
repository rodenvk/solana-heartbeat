// Voting state detection via tower file age
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

// How recent the tower file must be to consider the node as voting.
const MASTER_WINDOW: Duration = Duration::from_millis(800);

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