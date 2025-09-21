use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use byteorder::{ByteOrder, LittleEndian};
use clap::{Parser, Subcommand};

const MAGIC: u32 = 0x534C_5550; // 'SLUP'
const VERSION: u32 = 1;
const HEADER_MIN: usize = 26;
const DEFAULT_PAYLOAD: usize = 1228;
const MAX_UDP_PAYLOAD: usize = 65_507;

#[derive(Parser, Debug)]
#[command(author, version, about="IPv4 UDP heartbeat with Solana-like payload")]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand, Debug)]
enum Mode {
    /// UDP echo server
    Server {
        #[arg(long, default_value = "0.0.0.0:7071")]
        bind: String,
    },
    /// UDP heartbeat client
    Client {
        #[arg(long)]
        server: String,
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: String,
        #[arg(long, default_value = "500")]
        interval_ms: u64,
        #[arg(long, default_value = "1500")]
        timeout_ms: u64,
        #[arg(long = "rtt-alarm", default_value = "800")]
        rtt_alarm_ms: u64,
        #[arg(long = "loss-alarm", default_value_t = 10)]
        loss_alarm: u64,
        #[arg(long = "payload-size", default_value_t = DEFAULT_PAYLOAD)]
        payload_size: usize,
    },
}

// ---- Packet encode/decode --------------------------------------------------

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

// ---- Server ----------------------------------------------------------------

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

// ---- Client ----------------------------------------------------------------

fn run_client(
    server: &str,
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
    let server_addr = resolve_ipv4(server)?;
    let bind_addr = resolve_ipv4(bind)?;

    let sock = UdpSocket::bind(bind_addr).map_err(|e| format!("bind {}: {}", bind_addr, e))?;
    sock.connect(server_addr)
        .map_err(|e| format!("connect {}: {}", server_addr, e))?;
    sock.set_read_timeout(Some(timeout))
        .map_err(|e| format!("set timeout: {}", e))?;

    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown-host".to_string());

    println!(
        "[client] host={} -> {} interval={:?} timeout={:?} rtt_alarm={:?} loss_alarm={} payload={}B",
        hostname, server_addr, interval, timeout, rtt_alarm, loss_alarm, payload
    );

    let mut tx = vec![0u8; payload];
    let mut rx = vec![0u8; 65535];
    let mut seq: u64 = 0;
    let mut consec_loss: u64 = 0;

    loop {
        seq += 1;

        // send
        let n = encode_packet(&mut tx, &hostname, seq);
        if let Err(e) = sock.send(&tx[..n]) {
            eprintln!("[send-error] seq={} err={}", seq, e);
            consec_loss += 1;
            continue;
        }

        match sock.recv(&mut rx) {
            Ok(nr) => {
                if let Some((rseq, send_ns, rhost)) = decode_packet(&rx[..nr]) {
                    if rseq != seq {
                        eprintln!("[corrupt] expected seq={} got={}", seq, rseq);
                        consec_loss += 1;
                    } else {
                        let rtt_ms = diff_ms(now_unix_ns(), send_ns);
                        consec_loss = 0;
                        if rtt_ms > rtt_alarm.as_secs_f64() * 1000.0 {
                            println!(
                                "[ok] seq={} rtt_ms={:.2} host={} ALARM_RTT",
                                seq, rtt_ms, rhost
                            );
                        } else {
                            println!("[ok] seq={} rtt_ms={:.2} host={}", seq, rtt_ms, rhost);
                        }
                    }
                } else {
                    eprintln!("[corrupt] decode failed for seq={}", seq);
                    consec_loss += 1;
                }
            }
            Err(_) => {
                eprintln!("[loss] seq={} timeout after {:?}", seq, timeout);
                consec_loss += 1;
                if loss_alarm > 0 && consec_loss >= loss_alarm {
                    println!("[ALARM_LOSS] consec_lost={}", consec_loss);
                }
            }
        }

        std::thread::sleep(interval);
    }
}

// ---- main ------------------------------------------------------------------

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
