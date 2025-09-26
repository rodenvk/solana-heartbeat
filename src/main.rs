use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use byteorder::{ByteOrder, LittleEndian};
use clap::Parser;
use chrono::Utc;

const MAGIC: u32 = 0x534C_5550; // 'SLUP'
const VERSION: u32 = 1;
const HEADER_MIN: usize = 26;
const DEFAULT_PAYLOAD: usize = 1228;
const MAX_UDP_PAYLOAD: usize = 65_507;
const PROBE_SAMPLES: usize = 10; // baseline window size

#[derive(Parser, Debug)]
#[command(author, version, about="IPv4 UDP heartbeat with Solana-like payload (multi-server)")]
enum Mode {
    /// UDP echo server (IPv4)
    Server {
        /// Bind address, e.g. 0.0.0.0:7071
        #[arg(long, default_value = "0.0.0.0:7071")]
        bind: String,
    },
    /// UDP heartbeat client (IPv4)
    Client {
        /// Comma-separated server list (1 or 2), e.g. host1:7071,host2:7072
        #[arg(long)]
        server: String,

        /// Local bind (optional), e.g. 0.0.0.0:0
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: String,

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
    },
}

#[derive(Parser, Debug)]
#[command(author, version, about="Solana heartbeat (IPv4, multi-server, tab output)")]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

// -----------------------------------------------------------------------------
// Packet encode/decode
// -----------------------------------------------------------------------------

fn now_unix_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i128 as i64
}

fn encode_packet(buf: &mut [u8], hostname: &str, seq: u64) -> usize {
    let host_bytes = hostname.as_bytes();
    let host_len = host_bytes.len().min(255);
    LittleEndian::write_u32(&mut buf[0..4], MAGIC);
    LittleEndian::write_u32(&mut buf[4..8], VERSION);
    LittleEndian::write_u64(&mut buf[8..16], seq);
    LittleEndian::write_i64(&mut buf[16..24], now_unix_ns());
    LittleEndian::write_u16(&mut buf[24..26], host_len as u16);
    buf[26..26 + host_len].copy_from_slice(&host_bytes[..host_len]);
    for b in &mut buf[26 + host_len..] { *b = 0; }
    buf.len()
}

fn decode_packet(buf: &[u8]) -> Option<(u64, i64, String)> {
    if buf.len() < HEADER_MIN { return None; }
    if LittleEndian::read_u32(&buf[0..4]) != MAGIC { return None; }
    if LittleEndian::read_u32(&buf[4..8]) != VERSION { return None; }
    let seq = LittleEndian::read_u64(&buf[8..16]);
    let send_ns = LittleEndian::read_i64(&buf[16..24]);
    let host_len = LittleEndian::read_u16(&buf[24..26]) as usize;
    if HEADER_MIN + host_len > buf.len() { return None; }
    let host = String::from_utf8_lossy(&buf[26..26 + host_len]).to_string();
    Some((seq, send_ns, host))
}

// -----------------------------------------------------------------------------
// Helpers
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
    // Example: 2025-09-21 15:13:03.521033811 GMT+00
    Utc::now().format("%Y-%m-%d %H:%M:%S%.f GMT+00").to_string()
}

// unified output writer (file if provided; otherwise stdout/stderr)
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

// -----------------------------------------------------------------------------
// Server
// -----------------------------------------------------------------------------

fn run_server(bind: &str) -> Result<(), String> {
    let bind_addr = resolve_ipv4(bind)?;
    let sock = UdpSocket::bind(bind_addr).map_err(|e| format!("bind {}: {}", bind_addr, e))?;
    println!("[server] listening on {} (UDP/IPv4)", bind_addr);

    let mut buf = vec![0u8; 65535];
    loop {
        if let Ok((n, peer)) = sock.recv_from(&mut buf) {
            let _ = sock.send_to(&buf[..n], peer);
        }
    }
}

// -----------------------------------------------------------------------------
// Client (multi-server, tab-delimited output, optional file logging)
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

    // Bind local socket (unconnected; we use send_to/recv_from)
    let bind_addr = resolve_ipv4(bind)?;
    let sock = UdpSocket::bind(bind_addr).map_err(|e| format!("bind {}: {}", bind_addr, e))?;
    sock.set_read_timeout(Some(timeout))
        .map_err(|e| format!("set timeout: {}", e))?;

    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown-host".to_string());

    // Optional log file
    let mut writer: Option<BufWriter<File>> = if let Some(path) = log_path {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("cannot open log file {}: {}", path, e))?;
        Some(BufWriter::new(file))
    } else {
        None
    };

    // Pretty print destinations (header stays space-formatted as requested)
    let pretty_dests = match servers.len() {
        1 => format!("{}", servers[0].1),
        2 => format!("{} & {}", servers[0].1, servers[1].1),
        _ => unreachable!(),
    };

    // Header line (written to file if --log is set)
    out_line(
        &mut writer,
        &format!(
            "[client] host={} -> {} interval={}ms timeout={}s rtt_alarm={}ms loss_alarm={} payload={}B",
            hostname,
            pretty_dests,
            interval.as_millis(),
            format!("{:.1}", timeout.as_secs_f64()),
            rtt_alarm.as_millis(),
            loss_alarm,
            payload
        ),
    );

    let mut tx = vec![0u8; payload];
    let mut rx = vec![0u8; 65535];
    let mut seq: u64 = 0;

    // Baseline state (per server)
    let mut base_sum: Vec<f64> = vec![0.0; servers.len()];
    let mut base_cnt: Vec<usize> = vec![0; servers.len()];
    let mut base_avg: Vec<Option<f64>> = vec![None; servers.len()];

    // NEW: Count consecutive ALARM_RTT ticks (all_bad == true)
    let mut consec_alarm_rtt: u64 = 0;

    loop {
        seq += 1;

        // 1) Send to all servers
        let n = encode_packet(&mut tx, &hostname, seq);
        for (_, addr) in &servers {
            if let Err(e) = sock.send_to(&tx[..n], addr) {
                err_line(
                    &mut writer,
                    &format!("[send-error]\t{}\thost={}\tdst={}\terr={}", ts_now(), hostname, addr, e),
                );
            }
        }

        // 2) Collect replies until we either have them all, or we hit timeout
        let mut rtt_map: HashMap<SocketAddr, f64> = HashMap::new();
        let deadline = std::time::Instant::now() + timeout;

        while std::time::Instant::now() < deadline && rtt_map.len() < servers.len() {
            match sock.recv_from(&mut rx) {
                Ok((nr, src)) => {
                    if !servers.iter().any(|(_, a)| *a == src) { continue; }
                    if let Some((rseq, send_ns, _rhost)) = decode_packet(&rx[..nr]) {
                        if rseq != seq { continue; } // stale/other seq
                        if !rtt_map.contains_key(&src) {
                            let rtt_ms = diff_ms(now_unix_ns(), send_ns);
                            rtt_map.insert(src, rtt_ms);
                        }
                    }
                }
                Err(_) => break, // timed out waiting
            }
        }

        // 3) Build outputs in same order as servers
        let mut rtts: Vec<Option<f64>> = Vec::with_capacity(servers.len());
        let mut all_bad = true;    // becomes false if ANY reply is <= rtt_alarm
        let mut all_missed = true; // true only if NONE replied

        for (_, addr) in &servers {
            if let Some(ms) = rtt_map.get(addr) {
                rtts.push(Some(*ms));
                all_missed = false;
                if *ms <= rtt_alarm.as_secs_f64() * 1000.0 { all_bad = false; }
            } else {
                rtts.push(None); // timeout counts as "bad" for ALARM_RTT purposes
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

        // 5) Decide consolidated status: [ok] / [warn] / [loss]
        let status_label = if all_missed {
            "[loss]"
        } else {
            // Partial-timeout policy:
            // - If exactly one timeout:
            //     * [warn] ONLY if the other present RTT >= 1.5x its baseline (when baseline ready)
            //     * Else [ok]
            let timeouts = rtts.iter().filter(|o| o.is_none()).count();
            if timeouts == 1 {
                let mut warn_pt = false;
                for i in 0..servers.len() {
                    if rtts[i].is_some() {
                        if let (Some(avg), Some(curr)) = (base_avg[i], rtts[i]) {
                            if curr >= avg * 1.5 {
                                warn_pt = true;
                            }
                        }
                        break; // only one present in partial-timeout case
                    }
                }
                if warn_pt { "[warn]" } else { "[ok]" }
            } else {
                // No timeouts (or both present)
                // Baseline-based warn:
                // - 1 server: curr >= 1.5x baseline
                // - 2 servers: all curr present AND each >= 1.5x its baseline
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

        // 6) Build alarm suffixes and maintain ALARM_RTT consecutive counter
        // - ALARM_RTT if "all_bad" (all replies above --rtt-alarm or timeouts)
        // - ALARM_LOSS if ALARM_RTT has held for --loss-alarm consecutive ticks
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

        // 7) Print per-tick consolidated line (tab-delimited; timestamp, host, rtt_ms, alarms)
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
            &format!("{}\t{}\thost={}\trtt_ms={}{}", status_label, ts_now(), hostname, rtt_str, alarm_str),
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
        Mode::Server { bind } => {
            if let Err(e) = run_server(&bind) {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
        Mode::Client {
            server,
            bind,
            interval_ms,
            timeout_ms,
            rtt_alarm_ms,
            loss_alarm,
            payload_size,
            log,
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
            ) {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
    }
}
