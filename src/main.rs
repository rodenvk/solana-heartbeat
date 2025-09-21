use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use byteorder::{ByteOrder, LittleEndian};
use clap::{Parser, Subcommand};
use chrono::Utc;

const MAGIC: u32 = 0x534C_5550; // 'SLUP'
const VERSION: u32 = 1;
const HEADER_MIN: usize = 26;
const DEFAULT_PAYLOAD: usize = 1228;
const MAX_UDP_PAYLOAD: usize = 65_507;

#[derive(Parser, Debug)]
#[command(author, version, about="IPv4 UDP heartbeat with Solana-like payload (multi-server)")]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand, Debug)]
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

        /// Alarm on N consecutive full misses (no server responds)
        #[arg(long = "loss-alarm", default_value_t = 10)]
        loss_alarm: u64,

        /// UDP payload size in bytes (default 1228)
        #[arg(long = "payload-size", default_value_t = DEFAULT_PAYLOAD)]
        payload_size: usize,
    },
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
    for b in &mut buf[26 + host_len..] {
        *b = 0;
    }
    buf.len()
}

fn decode_packet(buf: &[u8]) -> Option<(u64, i64, String)> {
    if buf.len() < HEADER_MIN {
        return None;
    }
    if LittleEndian::read_u32(&buf[0..4]) != MAGIC {
        return None;
    }
    if LittleEndian::read_u32(&buf[4..8]) != VERSION {
        return None;
    }
    let seq = LittleEndian::read_u64(&buf[8..16]);
    let send_ns = LittleEndian::read_i64(&buf[16..24]);
    let host_len = LittleEndian::read_u16(&buf[24..26]) as usize;
    if HEADER_MIN + host_len > buf.len() {
        return None;
    }
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
        if a.is_ipv4() {
            return Ok(a);
        }
    }
    Err(format!("no IPv4 address found for {}", addr))
}

fn diff_ms(recv_ns: i64, send_ns: i64) -> f64 {
    (recv_ns - send_ns) as f64 / 1_000_000.0
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
// Client (multi-server)
// -----------------------------------------------------------------------------

fn run_client(
    servers_csv: &str,
    bind: &str,
    interval: Duration,
    timeout: Duration,
    rtt_alarm: Duration,
    loss_alarm: u64,
    payload: usize,
) -> Result<(), String> {
    if payload < HEADER_MIN || payload > MAX_UDP_PAYLOAD {
        return Err(format!(
            "payload-size must be between {} and {}",
            HEADER_MIN, MAX_UDP_PAYLOAD
        ));
    }

    // Parse 1 or 2 servers (comma separated)
    let parts: Vec<&str> = servers_csv.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
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

    // Pretty print destinations
    let pretty_dests = match servers.len() {
        1 => format!("{}", servers[0].1),
        2 => format!("{} & {}", servers[0].1, servers[1].1),
        _ => unreachable!(),
    };

    println!(
        "[client] host={} -> {} interval={}ms timeout={}s rtt_alarm={}ms loss_alarm={} payload={}B",
        hostname,
        pretty_dests,
        interval.as_millis(),
        format!("{:.1}", timeout.as_secs_f64()),
        rtt_alarm.as_millis(),
        loss_alarm,
        payload
    );

    let mut tx = vec![0u8; payload];
    let mut rx = vec![0u8; 65535];
    let mut seq: u64 = 0;
    let mut consec_full_miss: u64 = 0;

    loop {
        seq += 1;

        // 1) Send to all servers
        let n = encode_packet(&mut tx, &hostname, seq);
        for (_, addr) in &servers {
            if let Err(e) = sock.send_to(&tx[..n], addr) {
                eprintln!("[send-error] seq={} dst={} err={}", seq, addr, e);
            }
        }

        // 2) Collect replies until we either have them all, or we hit timeout
        let mut rtt_map: HashMap<SocketAddr, f64> = HashMap::new();
        let deadline = std::time::Instant::now() + timeout;

        while std::time::Instant::now() < deadline && rtt_map.len() < servers.len() {
            match sock.recv_from(&mut rx) {
                Ok((nr, src)) => {
                    // Only care about our known servers
                    if !servers.iter().any(|(_, a)| *a == src) {
                        continue;
                    }
                    if let Some((rseq, send_ns, _rhost)) = decode_packet(&rx[..nr]) {
                        if rseq != seq {
                            continue; // stale/other seq
                        }
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
        let mut all_bad = true;   // false if ANY reply is <= rtt_alarm
        let mut all_missed = true; // true only if NONE replied

        for (_, addr) in &servers {
            if let Some(ms) = rtt_map.get(addr) {
                rtts.push(Some(*ms));
                all_missed = false;
                if *ms <= rtt_alarm.as_secs_f64() * 1000.0 {
                    all_bad = false;
                }
            } else {
                rtts.push(None); // timeout
            }
        }

        // 4) Update full-miss counter & alarms
        if all_missed {
            consec_full_miss += 1;
            eprintln!("[loss] seq={} timeout after {:?}", seq, timeout);
            if loss_alarm > 0 && consec_full_miss >= loss_alarm {
                let ts = Utc::now().format("%Y-%m-%d %H:%M:%S%.f GMT+00");
                println!("[ALARM_LOSS]\t{}\thost={}\tconsec_lost={}", ts, hostname, consec_full_miss);
            }
        } else {
            consec_full_miss = 0; // any reply resets
        }

        // 5) Print per-seq line (ordered RTTs, timeout if missing)      
        let rtt_str = rtts
            .iter()
            .map(|opt| match opt {
                Some(v) => format!("{:.2}", v),
                None => "timeout".to_string(),
            })
            .collect::<Vec<_>>()
            .join(",");

        // Current system timestamp in UTC with nanoseconds
        let ts = Utc::now().format("%Y-%m-%d %H:%M:%S%.f GMT+00");

        if all_bad {
            println!("[ok]\t{}\thost={}\trtt_ms={}\tALARM_RTT", ts, hostname, rtt_str);
        } else {
            println!("[ok]\t{}\thost={}\trtt_ms={}", ts, hostname, rtt_str);
        }

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
        } => {
            if let Err(e) = run_client(
                &server,
                &bind,
                Duration::from_millis(interval_ms),
                Duration::from_millis(timeout_ms),
                Duration::from_millis(rtt_alarm_ms),
                loss_alarm,
                payload_size,
            ) {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
    }
}
