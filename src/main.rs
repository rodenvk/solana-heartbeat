use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use byteorder::{ByteOrder, LittleEndian};
use clap::Parser;
use chrono::Utc;

const MAGIC: u32 = 0x534C_5550; // 'SLUP'
const VERSION: u32 = 2;         // v2 adds role string to packet
// Layout: magic(4) ver(4) seq(8) send_ns(8) host_len(2) host[..] role_len(2) role[..] + padding
const HEADER_BASE: usize = 4 + 4 + 8 + 8 + 2; // 26 before role_len
const HEADER_MIN: usize = HEADER_BASE + 2;    // + role_len
const DEFAULT_PAYLOAD: usize = 1228;
const MAX_UDP_PAYLOAD: usize = 65_507;
const PROBE_SAMPLES: usize = 10; // baseline window size
const MASTER_WINDOW: Duration = Duration::from_millis(500); // tower mtime freshness

#[derive(Parser, Debug)]
#[command(author, version, about="IPv4 UDP heartbeat with Solana-like payload (client/server; mirrored output)")]
enum Mode {
    /// UDP echo server (IPv4) that also monitors incoming heartbeats and logs verdicts
    Server {
        /// Bind address, e.g. 0.0.0.0:7071
        #[arg(long, default_value = "0.0.0.0:7071")]
        bind: String,

        /// Expected client send interval (ms) – used for cadence/timeouts
        #[arg(long, default_value = "500")]
        interval_ms: u64,

        /// Consider a host lost if no packet within this timeout (ms)
        #[arg(long, default_value = "1500")]
        timeout_ms: u64,

        /// ALARM_RTT if measured delay (or timeout) is above this (ms)
        #[arg(long = "rtt-alarm", default_value = "800")]
        rtt_alarm_ms: u64,

        /// ALARM_LOSS after N consecutive ALARM_RTT ticks
        #[arg(long = "loss-alarm", default_value_t = 10)]
        loss_alarm: u64,

        /// Optional log file path; if set, all output is appended there
        #[arg(long)]
        log: Option<String>,
    },

    /// UDP heartbeat client (IPv4)
    Client {
        /// Comma-separated server list (1 or 2), e.g. host1:7071,host2:7072
        #[arg(long)]
        server: String,

        /// Local bind (optional), e.g. 0.0.0.0:0
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: String,

        /// Override detected local hostname
        #[arg(long)]
        hostname: Option<String>,

        /// Send interval (milliseconds)
        #[arg(long, default_value = "500")]
        interval_ms: u64,

        /// Read timeout per tick (milliseconds)
        #[arg(long, default_value = "1500")]
        timeout_ms: u64,

        /// Alarm if RTT above this (milliseconds) for all servers in the tick
        #[arg(long = "rtt-alarm", default_value = "800")]
        rtt_alarm_ms: u64,

        /// Trigger ALARM_LOSS after N consecutive ALARM_RTT ticks
        #[arg(long = "loss-alarm", default_value_t = 10)]
        loss_alarm: u64,

        /// UDP payload size in bytes (default 1228)
        #[arg(long = "payload-size", default_value_t = DEFAULT_PAYLOAD)]
        payload_size: usize,

        /// Optional log file path; if set, all output is appended there
        #[arg(long)]
        log: Option<String>,

        /// Validator identity pubkey used to locate tower file (optional but recommended)
        #[arg(long)]
        pubkey: Option<String>,

        /// Ledger directory containing tower-*.bin files (optional but recommended)
        #[arg(long)]
        ledger: Option<String>,
    },
}

#[derive(Parser, Debug)]
#[command(author, version, about="Solana heartbeat (IPv4, tab output, mirrored client/server)")]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

// -----------------------------------------------------------------------------
// Packet encode/decode (v2 includes role string)
// -----------------------------------------------------------------------------

fn now_unix_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i128 as i64
}

fn encode_packet(buf: &mut [u8], hostname: &str, role: &str, seq: u64) -> usize {
    let host_bytes = hostname.as_bytes();
    let host_len = host_bytes.len().min(255);
    let role_bytes = role.as_bytes();
    let role_len = role_bytes.len().min(255);

    LittleEndian::write_u32(&mut buf[0..4], MAGIC);
    LittleEndian::write_u32(&mut buf[4..8], VERSION);
    LittleEndian::write_u64(&mut buf[8..16], seq);
    LittleEndian::write_i64(&mut buf[16..24], now_unix_ns());
    LittleEndian::write_u16(&mut buf[24..26], host_len as u16);
    let mut off = 26;
    buf[off..off + host_len].copy_from_slice(&host_bytes[..host_len]);
    off += host_len;

    LittleEndian::write_u16(&mut buf[off..off + 2], role_len as u16);
    off += 2;
    buf[off..off + role_len].copy_from_slice(&role_bytes[..role_len]);
    off += role_len;

    // zero padding remainder
    for b in &mut buf[off..] { *b = 0; }
    buf.len()
}

fn decode_packet(buf: &[u8]) -> Option<(u64, i64, String, String)> {
    if buf.len() < HEADER_MIN { return None; }
    if LittleEndian::read_u32(&buf[0..4]) != MAGIC { return None; }
    if LittleEndian::read_u32(&buf[4..8]) != VERSION { return None; }
    let seq = LittleEndian::read_u64(&buf[8..16]);
    let send_ns = LittleEndian::read_i64(&buf[16..24]);

    let host_len = LittleEndian::read_u16(&buf[24..26]) as usize;
    let mut off = 26;
    if off + host_len + 2 > buf.len() { return None; }
    let host = String::from_utf8_lossy(&buf[off..off + host_len]).to_string();
    off += host_len;

    let role_len = LittleEndian::read_u16(&buf[off..off + 2]) as usize;
    off += 2;
    if off + role_len > buf.len() { return None; }
    let role = String::from_utf8_lossy(&buf[off..off + role_len]).to_string();

    Some((seq, send_ns, host, role))
}

// -----------------------------------------------------------------------------
// Shared helpers
// -----------------------------------------------------------------------------

fn resolve_ipv4(addr: &str) -> Result<SocketAddr, String> {
    let addrs = addr
        .to_socket_addrs()
        .map_err(|e| format!("resolve {}: {}", addr, e))?;
    for a in addrs {
        if a.is_ipv4() { return Ok(a); }
    }
    Err(format!("no IPv4 address found for {}", addr))
}

fn diff_ms(recv_ns: i64, send_ns: i64) -> f64 {
    (recv_ns - send_ns) as f64 / 1_000_000.0
}

fn ts_now() -> String {
    Utc::now().format("%Y-%m-%d %H:%M:%S%.f GMT+00").to_string()
}

fn out_line(w: &mut Option<BufWriter<File>>, line: &str) {
    if let Some(writer) = w {
        let _ = writeln!(writer, "{}", line);
        let _ = writer.flush();
    } else {
        println!("{}", line);
    }
}
fn err_line(w: &mut Option<BufWriter<File>>, line: &str) {
    if let Some(writer) = w {
        let _ = writeln!(writer, "{}", line);
        let _ = writer.flush();
    } else {
        eprintln!("{}", line);
    }
}

// --- role detection on client (tower file) ---

fn find_latest_tower(ledger_dir: &Path, pubkey: &str) -> Option<PathBuf> {
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
                    Some((best_time, _)) if mtime <= *best_time => {},
                    _ => best = Some((mtime, p.clone())),
                }
            }
        }
    }
    best.map(|(_, p)| p)
}

fn role_from_tower(ledger: Option<&str>, pubkey: Option<&str>) -> &'static str {
    let (Some(ledger_dir), Some(pk)) = (ledger, pubkey) else { return "unknown"; };
    let p = Path::new(ledger_dir);
    if !p.is_dir() { return "unknown"; }
    let Some(tower_path) = find_latest_tower(p, pk) else { return "backup"; };
    let Ok(meta) = std::fs::metadata(&tower_path) else { return "backup"; };
    let Ok(mtime) = meta.modified() else { return "backup"; };
    let Ok(age) = SystemTime::now().duration_since(mtime) else { return "master"; }; // future mtime => fresh
    if age <= MASTER_WINDOW { "master" } else { "backup" }
}

// -----------------------------------------------------------------------------
// Server with monitoring (mirrors client verdicts per source hostname)
// -----------------------------------------------------------------------------

#[derive(Default)]
struct HostState {
    base_sum: f64,
    base_cnt: usize,
    base_avg: Option<f64>,
    consec_alarm_rtt: u64,
    last_seen: Option<std::time::Instant>,
    last_role: String,
}

fn run_server_monitored(
    bind: &str,
    interval: Duration,
    timeout: Duration,
    rtt_alarm: Duration,
    loss_alarm: u64,
    log_path: Option<String>,
) -> Result<(), String> {
    let bind_addr = resolve_ipv4(bind)?;
    let sock = UdpSocket::bind(bind_addr).map_err(|e| format!("bind {}: {}", bind_addr, e))?;
    sock.set_read_timeout(Some(interval))
        .map_err(|e| format!("set timeout: {}", e))?;

    let mut writer: Option<BufWriter<File>> = if let Some(path) = log_path {
        let file = OpenOptions::new().create(true).append(true).open(&path)
            .map_err(|e| format!("cannot open log file {}: {}", path, e))?;
        Some(BufWriter::new(file))
    } else { None };

    out_line(&mut writer, &format!(
        "[server] listening on {} (UDP/IPv4) interval={}ms timeout={}s rtt_alarm={}ms loss_alarm={}",
        bind_addr, interval.as_millis(), format!("{:.1}", timeout.as_secs_f64()),
        rtt_alarm.as_millis(), loss_alarm
    ));

    // Per-host state keyed by hostname from packet
    let mut states: HashMap<String, HostState> = HashMap::new();
    let mut buf = vec![0u8; 65535];

    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, peer)) => {
                let recv_ns = now_unix_ns();
                if let Some((_seq, send_ns, host, role)) = decode_packet(&buf[..n]) {
                    let st = states.entry(host.clone()).or_default();
                    st.last_seen = Some(std::time::Instant::now());
                    st.last_role = role.clone();

                    // one-way delay (approx) from client timestamp to server receive
                    let delay_ms = diff_ms(recv_ns, send_ns);

                    // baseline: first PROBE_SAMPLES successes
                    if st.base_avg.is_none() && st.base_cnt < PROBE_SAMPLES {
                        st.base_sum += delay_ms;
                        st.base_cnt += 1;
                        if st.base_cnt == PROBE_SAMPLES {
                            st.base_avg = Some(st.base_sum / st.base_cnt as f64);
                        }
                    }

                    // verdict (single incoming stream)
                    let all_missed = false;
                    let all_bad = delay_ms > rtt_alarm.as_secs_f64() * 1000.0;

                    let warn_due_to_baseline = match st.base_avg {
                        Some(avg) => delay_ms >= avg * 1.5,
                        None => false,
                    };
                    let status_label = if all_missed {
                        "[loss]"
                    } else if warn_due_to_baseline {
                        "[warn]"
                    } else {
                        "[ok]"
                    };

                    // alarms (consecutive ALARM_RTT)
                    let mut alarm_suffixes: Vec<&str> = Vec::new();
                    if all_bad {
                        alarm_suffixes.push("ALARM_RTT");
                        st.consec_alarm_rtt += 1;
                    } else {
                        st.consec_alarm_rtt = 0;
                    }
                    if loss_alarm > 0 && st.consec_alarm_rtt >= loss_alarm {
                        alarm_suffixes.push("ALARM_LOSS");
                    }
                    let alarm_str = if alarm_suffixes.is_empty() { String::new() } else {
                        format!("\t{}", alarm_suffixes.join(" "))
                    };

                    out_line(
                        &mut writer,
                        &format!(
                            "{}\t{}\thost={}\trole={}\trtt_ms={:.2}{}",
                            status_label, ts_now(), host, st.last_role, delay_ms, alarm_str
                        ),
                    );
                }
                // Echo packet back as before
                let _ = sock.send_to(&buf[..n], peer);
            }
            Err(_timeout) => {
                // Emit [loss] for hosts not seen within 'timeout'
                let now = std::time::Instant::now();
                for (host, st) in states.iter_mut() {
                    let overdue = match st.last_seen {
                        Some(t) => now.duration_since(t) > timeout,
                        None => true,
                    };
                    if overdue {
                        // timeout -> ALARM_RTT true this tick
                        let mut alarm_suffixes: Vec<&str> = Vec::new();
                        alarm_suffixes.push("ALARM_RTT");
                        st.consec_alarm_rtt += 1;
                        if loss_alarm > 0 && st.consec_alarm_rtt >= loss_alarm {
                            alarm_suffixes.push("ALARM_LOSS");
                        }
                        let alarm_str = if alarm_suffixes.is_empty() { String::new() } else {
                            format!("\t{}", alarm_suffixes.join(" "))
                        };

                        out_line(
                            &mut writer,
                            &format!(
                                "[loss]\t{}\thost={}\trole={}\trtt_ms=timeout{}",
                                ts_now(), host, st.last_role, alarm_str
                            ),
                        );
                    }
                }
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Client
// -----------------------------------------------------------------------------

fn run_client(
    servers_csv: &str,
    bind: &str,
    interval: Duration,
    timeout: Duration,
    rtt_alarm: Duration,
    loss_alarm: u64,
    payload: usize,
    log_path: Option<String>,
    pubkey: Option<String>,
    ledger: Option<String>,
    hostname_override: Option<String>,
) -> Result<(), String> {
    if payload < HEADER_MIN || payload > MAX_UDP_PAYLOAD {
        return Err(format!("payload-size must be between {} and {}", HEADER_MIN, MAX_UDP_PAYLOAD));
    }

    // Parse 1 or 2 servers (comma separated)
    let parts: Vec<&str> = servers_csv
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if parts.is_empty() || parts.len() > 2 {
        return Err("provide 1 or 2 servers separated by a comma".into());
    }

    // Resolve to IPv4 socket addrs, preserving order for output
    let mut servers: Vec<(String, SocketAddr)> = Vec::with_capacity(parts.len());
    for p in &parts {
        let addr = resolve_ipv4(p)?;
        servers.push((p.to_string(), addr));
    }

    // Bind local socket
    let bind_addr = resolve_ipv4(bind)?;
    let sock = UdpSocket::bind(bind_addr).map_err(|e| format!("bind {}: {}", bind_addr, e))?;
    sock.set_read_timeout(Some(timeout))
        .map_err(|e| format!("set timeout: {}", e))?;

    // Hostname (with optional override)
    let hostname = if let Some(hn) = hostname_override {
        hn
    } else {
        hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown-host".to_string())
    };

    // Optional log file
    let mut writer: Option<BufWriter<File>> = if let Some(path) = log_path {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("cannot open log file {}: {}", path, e))?;
        Some(BufWriter::new(file))
    } else { None };

    // Pretty destinations (header)
    let pretty_dests = match servers.len() {
        1 => format!("{}", servers[0].1),
        2 => format!("{} & {}", servers[0].1, servers[1].1),
        _ => unreachable!(),
    };

    out_line(
        &mut writer,
        &format!(
            "[client] host={} -> {} interval={}ms timeout={}s rtt_alarm={}ms loss_alarm={} payload={}B{}{}",
            hostname,
            pretty_dests,
            interval.as_millis(),
            format!("{:.1}", timeout.as_secs_f64()),
            rtt_alarm.as_millis(),
            loss_alarm,
            payload,
            pubkey.as_ref().map(|s| format!(" pubkey={}", s)).unwrap_or_default(),
            ledger.as_ref().map(|s| format!(" ledger={}", s)).unwrap_or_default(),
        ),
    );

    let mut tx = vec![0u8; payload];
    let mut rx = vec![0u8; 65535];
    let mut seq: u64 = 0;

    // Baselines per server
    let mut base_sum: Vec<f64> = vec![0.0; servers.len()];
    let mut base_cnt: Vec<usize> = vec![0; servers.len()];
    let mut base_avg: Vec<Option<f64>> = vec![None; servers.len()];

    // ALARM_LOSS is based on consecutive ALARM_RTT ticks
    let mut consec_alarm_rtt: u64 = 0;

    loop {
        seq += 1;

        // role (computed client-side each tick)
        let role = role_from_tower(ledger.as_deref(), pubkey.as_deref());

        // 1) Send to all servers (packet includes hostname + role)
        let n = encode_packet(&mut tx, &hostname, role, seq);
        for (_, addr) in &servers {
            if let Err(e) = sock.send_to(&tx[..n], addr) {
                err_line(
                    &mut writer,
                    &format!("[send-error]\t{}\thost={}\tdst={}\terr={}", ts_now(), hostname, addr, e),
                );
            }
        }

        // 2) Collect replies until all or timeout
        let mut rtt_map: HashMap<SocketAddr, f64> = HashMap::new();
        let deadline = std::time::Instant::now() + timeout;

        while std::time::Instant::now() < deadline && rtt_map.len() < servers.len() {
            match sock.recv_from(&mut rx) {
                Ok((nr, src)) => {
                    if !servers.iter().any(|(_, a)| *a == src) { continue; }
                    if let Some((rseq, send_ns, _rhost, _rrole)) = decode_packet(&rx[..nr]) {
                        if rseq != seq { continue; } // stale
                        if !rtt_map.contains_key(&src) {
                            let rtt_ms = diff_ms(now_unix_ns(), send_ns);
                            rtt_map.insert(src, rtt_ms);
                        }
                    }
                }
                Err(_) => break,
            }
        }

        // 3) Build outputs
        let mut rtts: Vec<Option<f64>> = Vec::with_capacity(servers.len());
        let mut all_bad = true;
        let mut all_missed = true;

        for (_, addr) in &servers {
            if let Some(ms) = rtt_map.get(addr) {
                rtts.push(Some(*ms));
                all_missed = false;
                if *ms <= rtt_alarm.as_secs_f64() * 1000.0 { all_bad = false; }
            } else {
                rtts.push(None);
            }
        }

        // 4) Update baselines (first PROBE_SAMPLES successful RTTs per server)
        for i in 0..servers.len() {
            if base_avg[i].is_none() {
                if let Some(curr) = rtts[i] {
                    if base_cnt[i] < PROBE_SAMPLES {
                        base_sum[i] += curr;
                        base_cnt[i] += 1;
                        if base_cnt[i] == PROBE_SAMPLES {
                            base_avg[i] = Some(base_sum[i] / base_cnt[i] as f64);
                        }
                    }
                }
            }
        }

        // 5) Verdict label [ok]/[warn]/[loss]
        let status_label = if all_missed {
            "[loss]"
        } else {
            // partial-timeout policy
            let timeouts = rtts.iter().filter(|o| o.is_none()).count();
            if timeouts == 1 {
                let mut warn_pt = false;
                for i in 0..servers.len() {
                    if rtts[i].is_some() {
                        if let (Some(avg), Some(curr)) = (base_avg[i], rtts[i]) {
                            if curr >= avg * 1.5 { warn_pt = true; }
                        }
                        break;
                    }
                }
                if warn_pt { "[warn]" } else { "[ok]" }
            } else {
                // no timeouts or both present
                let warn_due_to_baseline = if servers.len() == 1 {
                    if let (Some(avg), Some(curr)) = (base_avg[0], rtts[0]) {
                        curr >= avg * 1.5
                    } else { false }
                } else {
                    let mut ready = true;
                    for i in 0..servers.len() {
                        if base_avg[i].is_none() || rtts[i].is_none() { ready = false; break; }
                    }
                    if ready {
                        (0..servers.len()).all(|i| rtts[i].unwrap() >= base_avg[i].unwrap() * 1.5)
                    } else { false }
                };
                if warn_due_to_baseline { "[warn]" } else { "[ok]" }
            }
        };

        // 6) Alarms (consecutive ALARM_RTT)
        let mut alarm_suffixes: Vec<&str> = Vec::new();
        if all_bad {
            alarm_suffixes.push("ALARM_RTT");
            consec_alarm_rtt += 1;
        } else {
            consec_alarm_rtt = 0;
        }
        if loss_alarm > 0 && consec_alarm_rtt >= loss_alarm {
            alarm_suffixes.push("ALARM_LOSS");
        }
        let alarm_str = if alarm_suffixes.is_empty() {
            String::new()
        } else {
            format!("\t{}", alarm_suffixes.join(" "))
        };

        // 7) Print consolidated line
        let rtt_str = rtts
            .iter()
            .map(|opt| match opt {
                Some(v) => format!("{:.2}", v),
                None => "timeout".to_string(),
            })
            .collect::<Vec<_>>()
            .join(",");

        out_line(
            &mut writer,
            &format!(
                "{}\t{}\thost={}\trole={}\trtt_ms={}{}",
                status_label, ts_now(), hostname, role, rtt_str, alarm_str
            ),
        );

        std::thread::sleep(interval);
    }
}

// -----------------------------------------------------------------------------
// main
// -----------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();
    match cli.mode {
        Mode::Server {
            bind,
            interval_ms,
            timeout_ms,
            rtt_alarm_ms,
            loss_alarm,
            log,
        } => {
            if let Err(e) = run_server_monitored(
                &bind,
                Duration::from_millis(interval_ms),
                Duration::from_millis(timeout_ms),
                Duration::from_millis(rtt_alarm_ms),
                loss_alarm,
                log,
            ) {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
        Mode::Client {
            server,
            bind,
            hostname,
            interval_ms,
            timeout_ms,
            rtt_alarm_ms,
            loss_alarm,
            payload_size,
            log,
            pubkey,
            ledger,
        } => {
            if let Err(e) = run_client(
                &server,
                &bind,
                Duration::from_millis(interval_ms),
                Duration::from_millis(timeout_ms),
                Duration::from_millis(rtt_alarm_ms),
                loss_alarm,
                payload_size,
                log,
                pubkey,
                ledger,
                hostname,
            ) {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
    }
}
