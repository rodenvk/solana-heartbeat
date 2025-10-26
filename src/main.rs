use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH, Instant};

use byteorder::{ByteOrder, LittleEndian};
use clap::Parser;
use chrono::Utc;

mod client_checks;

/* -------------------------------------------------------------------------- */
/*                              Protocol / packet                              */
/* -------------------------------------------------------------------------- */

const MAGIC: u32 = 0x534C_5550; // 'SLUP'
// v4 adds prev_recv_ns (client wallclock of previous echo receive) so the server
// can compute the full RTT for seq-1 as (prev_recv_ns - prev_send_ns).
const VERSION: u32 = 4;

// v4 layout (little endian):
// magic(4) ver(4) seq(8) send_ns(8) prev_recv_ns(8)
// host_len(2) host[..] role_len(2) role[..] client_len(2) client[..] ver_len(2) ver[..]
const HEADER_MIN: usize = 4 + 4 + 8 + 8 + 8 + 2 + 0 + 2 + 0 + 2 + 0 + 2 + 0;
const MAX_UDP_PAYLOAD: usize = 1228;
const PROBE_SAMPLES: usize = 10;

// Warn requires BOTH: absolute +20ms AND >= 1.5x baseline
const WARN_ABS_MARGIN_MS: f64 = 20.0;

/* -------------------------------------------------------------------------- */
/*                                   CLI                                       */
/* -------------------------------------------------------------------------- */

#[derive(Parser, Debug)]
#[command(author, version, about="solana-heartbeat (client/server)")]
enum Mode {
    /// Client: send heartbeats to one or more servers
    Client {
        /// Comma-separated list of <ip:port> servers (1 or 2 recommended)
        #[arg(long)]
        server: String,

        /// Bind address for the client UDP socket (e.g. 0.0.0.0:0)
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: String,

        /// Send interval in ms
        #[arg(long = "interval-ms", default_value = "500")]
        interval_ms: u64,

        /// Read timeout in ms (max wait per seq, but never past the next tick)
        #[arg(long = "timeout-ms", default_value = "1500")]
        timeout_ms: u64,

        /// RTT alarm threshold in ms (ALARM_RTT if a numeric RTT exceeds this)
        #[arg(long = "rtt-alarm-ms", default_value = "400")]
        rtt_alarm_ms: u64,

        /// Raise LOSS after this many consecutive alarm ticks
        #[arg(long = "loss-alarm", default_value = "10")]
        loss_alarm: u64,

        /// UDP payload size (bytes)
        #[arg(long = "payload-size", default_value = "512")]
        payload: usize,

        /// Validator identity pubkey (optional)
        #[arg(long)]
        pubkey: Option<String>,

        /// Ledger path (optional)
        #[arg(long)]
        ledger: Option<String>,

        /// Override hostname
        #[arg(long)]
        hostname: Option<String>,

        /// Optional log file path (append)
        #[arg(long)]
        log: Option<String>,
    },

    /// Server: listen for heartbeats and echo packets back
    Server {
        /// Bind address for the server (e.g. 0.0.0.0:7000)
        #[arg(long, default_value = "0.0.0.0:7000")]
        bind: String,

        /// Expected send interval from clients in ms (for information)
        #[arg(long = "interval-ms", default_value = "500")]
        interval_ms: u64,

        /// Consider a host lost if no packet within this timeout (ms)
        #[arg(long = "timeout-ms", default_value = "1500")]
        timeout_ms: u64,

        /// ALARM_RTT if derived full RTT (prev_recv_ns - prev_send_ns) is above this (ms)
        #[arg(long = "rtt-alarm-ms", default_value = "400")]
        rtt_alarm_ms: u64,

        /// After this many consecutive alarm ticks, emit loss
        #[arg(long = "loss-alarm", default_value = "10")]
        loss_alarm: u64,

        /// Log file path (optional)
        #[arg(long)]
        log: Option<String>,
    },
}

#[derive(Parser, Debug)]
#[command(author, version, about="solana-heartbeat wrapper")]
struct Args {
    #[command(subcommand)]
    mode: Mode,
}

/* -------------------------------------------------------------------------- */
/*                                   State                                     */
/* -------------------------------------------------------------------------- */

#[derive(Default, Clone)]
struct UpstreamState {
    // last recv for echo (numeric RTT reference for next packet)
    last_recv_ns: i64,

    // Consecutive per-upstream ALARM_RTT counter
    consec_alarm_rtt: u64,
}

struct HostState {
    // Baseline probe
    base_sum: f64,
    base_cnt: usize,
    base_avg: Option<f64>,

    // For seq-1 RTT: prev_send_ns from the last packet
    prev_send_ns: Option<i64>,
    prev_recv_ns_seen: Option<i64>,

    // Consecutive ALARM_RTT counter
    consec_alarm_rtt: u64,

    // Last metadata
    last_role: String,
    last_client: String,
    last_version: String,

    // Housekeeping
    last_seen: Instant,
    last_seq: u64,
}
impl Default for HostState {
    fn default() -> Self {
        Self {
            base_sum: 0.0,
            base_cnt: 0,
            base_avg: None,
            prev_send_ns: None,
            prev_recv_ns_seen: None,
            consec_alarm_rtt: 0,
            last_role: String::new(),
            last_client: String::new(),
            last_version: String::new(),
            last_seen: Instant::now(),
            last_seq: 0,
        }
    }
}

/* -------------------------------------------------------------------------- */
/*                               Helpers / utils                               */
/* -------------------------------------------------------------------------- */

fn now_unix_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i128 as i64
}

fn diff_ms(a_ns: i64, b_ns: i64) -> f64 {
    let d = (a_ns as i128) - (b_ns as i128);
    (if d < 0 { 0 } else { d } as f64) / 1_000_000.0
}

fn resolve_ipv4<A: ToSocketAddrs>(addr: A) -> Result<SocketAddr, String> {
    let addrs: Vec<_> = addr.to_socket_addrs()
        .map_err(|e| format!("resolve: {}", e))?
        .collect();
    for a in addrs {
        if a.is_ipv4() { return Ok(a); }
    }
    Err("no IPv4 address found".into())
}

fn ts_now() -> String {
    Utc::now().format("%Y-%m-%d %H:%M:%S%.f GMT+00").to_string()
}

fn out_line(w: &mut Option<BufWriter<File>>, s: &str) {
    if let Some(writer) = w.as_mut() {
        let _ = writeln!(writer, "{}", s);
        let _ = writer.flush();
    } else {
        println!("{}", s);
    }
}

fn put_str(buf: &mut [u8], off: &mut usize, s: &str) {
    let b = s.as_bytes();
    LittleEndian::write_u16(&mut buf[*off..*off + 2], b.len() as u16);
    *off += 2;
    buf[*off..*off + b.len()].copy_from_slice(b);
    *off += b.len();
}

fn get_str<'a>(buf: &'a [u8], off: &mut usize) -> Option<&'a str> {
    if *off + 2 > buf.len() { return None; }
    let len = LittleEndian::read_u16(&buf[*off..*off + 2]) as usize;
    *off += 2;
    if *off + len > buf.len() { return None; }
    std::str::from_utf8(&buf[*off..*off + len]).ok().map(|s| { *off += len; s })
}

fn encode_packet(
    seq: u64,
    send_ns: i64,
    prev_recv_ns: i64,
    host: &str,
    role: &str,
    client: &str,
    version_str: &str,
    payload: usize,
    buf: &mut [u8],
) -> usize {
    let mut off = 0;
    LittleEndian::write_u32(&mut buf[off..off + 4], MAGIC); off += 4;
    LittleEndian::write_u32(&mut buf[off..off + 4], VERSION); off += 4;
    LittleEndian::write_u64(&mut buf[off..off + 8], seq); off += 8;
    LittleEndian::write_i64(&mut buf[off..off + 8], send_ns); off += 8;
    LittleEndian::write_i64(&mut buf[off..off + 8], prev_recv_ns); off += 8;

    let pkt_min = HEADER_MIN + payload;
    if buf.len() < pkt_min { panic!("payload too big (max {})", MAX_UDP_PAYLOAD - HEADER_MIN); }

    put_str(buf, &mut off, host);
    put_str(buf, &mut off, role);
    put_str(buf, &mut off, client);
    put_str(buf, &mut off, version_str);

    for b in &mut buf[off..] { *b = 0; }
    off
}

fn decode_packet(buf: &[u8]) -> Option<(u32, u64, i64, i64, String, String, String, String)> {
    if buf.len() < HEADER_MIN { return None; }
    let mut off = 0;
    if LittleEndian::read_u32(&buf[off..off + 4]) != MAGIC { return None; }
    off += 4;
    let ver = LittleEndian::read_u32(&buf[off..off + 4]); off += 4;
    if ver < 3 || ver > VERSION { return None; } // accept v3..v4
    let seq = LittleEndian::read_u64(&buf[off..off + 8]); off += 8;
    let send_ns = LittleEndian::read_i64(&buf[off..off + 8]); off += 8;
    let prev_recv_ns = if ver >= 4 {
        let v = LittleEndian::read_i64(&buf[off..off + 8]); off += 8;
        v
    } else { 0 };

    let host = get_str(buf, &mut off)?.to_string();
    let role = get_str(buf, &mut off)?.to_string();
    let client = get_str(buf, &mut off)?.to_string();
    let verstr = get_str(buf, &mut off)?.to_string();

    Some((ver, seq, send_ns, prev_recv_ns, host, role, client, verstr))
}

/* -------------------------------------------------------------------------- */
/*                                   Client                                    */
/* -------------------------------------------------------------------------- */

fn run_client(
    servers_csv: &str,
    bind: &str,
    interval: Duration,
    timeout: Duration,
    rtt_alarm: Duration,
    loss_alarm: u64,
    payload: usize,
    pubkey: Option<String>,
    ledger: Option<String>,
    hostname_override: Option<String>,
    log_path: Option<String>,
) -> Result<(), String> {
    // Resolve servers
    let parts: Vec<_> = servers_csv.split(',').map(|s| s.trim()).collect();
    if parts.is_empty() { return Err("no servers provided".into()); }
    let servers: Vec<SocketAddr> = parts.iter().map(|p| resolve_ipv4(*p)).collect::<Result<_,_>>()?;

    let bind_addr = resolve_ipv4(bind)?;
    let sock = UdpSocket::bind(bind_addr).map_err(|e| format!("bind {}: {}", bind_addr, e))?;
    sock.set_nonblocking(true).map_err(|e| format!("set nonblocking: {}", e))?;

    // Node role/client/version via client_checks.rs
    let (client_name, client_ver) = client_checks::detect_client_and_version();
    let vote_state = client_checks::vote_state_from_tower(ledger.as_deref(), pubkey.as_deref());
    let id = client_checks::local_identity("http://127.0.0.1:8899");
    let role = client_checks::derive_role(
        client_name != "not running",
        id.as_deref(),
        pubkey.as_deref(),
        &vote_state,
    );

    let hostname = if let Some(h) = hostname_override {
        h
    } else {
        hostname::get().unwrap_or_default().to_string_lossy().to_string()
    };

    let mut writer: Option<BufWriter<File>> = if let Some(path) = log_path {
        let file = OpenOptions::new().create(true).append(true).open(&path)
            .map_err(|e| format!("cannot open log file {}: {}", path, e))?;
        Some(BufWriter::new(file))
    } else { None };

    let mut states = vec![UpstreamState::default(); servers.len()];
    let mut base_sum = vec![0.0f64; servers.len()];
    let mut base_cnt = vec![0usize; servers.len()];
    let mut base_avg = vec![None::<f64>; servers.len()];

    let mut tx = vec![0u8; HEADER_MIN + payload.min(MAX_UDP_PAYLOAD - HEADER_MIN)];
    let mut rx = vec![0u8; 2048];

    // Strict cadence: schedule sends and never block past next tick
    let mut next_send = Instant::now();
    let mut seq: u64 = 0;
    let mut current_rtts: HashMap<SocketAddr, f64> = HashMap::new();

    loop {
        // (1) Drain any available replies (non-blocking) for the *current* seq
        loop {
            match sock.recv_from(&mut rx) {
                Ok((nr, src)) => {
                    if let Some((_ver, rseq, send_ns_echo, _prev_recv_unused, _h, _r, _c, _v)) =
                        decode_packet(&rx[..nr])
                    {
                        // Count replies for current sequence only; ignore late ones
                        if rseq == seq && !current_rtts.contains_key(&src) {
                            let recv_ns = now_unix_ns();
                            let rtt = diff_ms(recv_ns, send_ns_echo);
                            current_rtts.insert(src, rtt);
                            if let Some(pos) = servers.iter().position(|a| *a == src) {
                                states[pos].last_recv_ns = recv_ns; // for next packet's prev_recv_ns
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break, // drained
                Err(_) => break,
            }
        }

        // (2) Exactly on schedule: finalize previous tick and send next
        let now = Instant::now();
        if now >= next_send {
            // Finalize previous tick (if we already sent at least once)
            if seq > 0 {
                // Build ordered RTTs and decide status with unified WARN grace
                let mut rtts: Vec<Option<f64>> = Vec::with_capacity(servers.len());
                for addr in &servers {
                    rtts.push(current_rtts.get(addr).cloned());
                }

                // Update baselines with successful samples
                for i in 0..servers.len() {
                    if base_avg[i].is_none() {
                        if let Some(ms) = rtts[i] {
                            base_sum[i] += ms;
                            base_cnt[i] += 1;
                            if base_cnt[i] == PROBE_SAMPLES {
                                base_avg[i] = Some(base_sum[i] / PROBE_SAMPLES as f64);
                            }
                        }
                    }
                }

                // WARN grace check per server
                let mut warn_flags = vec![false; servers.len()];
                for i in 0..servers.len() {
                    if let (Some(avg), Some(curr)) = (base_avg[i], rtts[i]) {
                        if (curr - avg) >= WARN_ABS_MARGIN_MS && curr >= avg * 1.5 {
                            warn_flags[i] = true;
                        }
                    }
                }

                // Status
                let status = if servers.len() == 1 {
                    if rtts[0].is_none() {
                        "loss"
                    } else if warn_flags[0] {
                        "warn"
                    } else {
                        "ok"
                    }
                } else {
                    let mut bads = 0usize;
                    for i in 0..servers.len() {
                        if rtts[i].is_none() || warn_flags[i] { bads += 1; }
                    }
                    match bads {
                        0 => "ok",
                        1 => "warn",
                        _ => "loss",
                    }
                };

                // ALARM_RTT: only when *all* servers are bad this tick
                let mut per_bad = vec![false; servers.len()];
                let mut all_bad = !servers.is_empty();
                for (i, v) in rtts.iter().enumerate() {
                    per_bad[i] = match v {
                        None => true,
                        Some(ms) => *ms > rtt_alarm.as_millis() as f64,
                    };
                    if !per_bad[i] { all_bad = false; }
                }
                let alarm_rtt = all_bad;
                if alarm_rtt {
                    for (i, bad) in per_bad.iter().enumerate() {
                        if *bad { states[i].consec_alarm_rtt += 1; } else { states[i].consec_alarm_rtt = 0; }
                    }
                } else {
                    for s in &mut states { s.consec_alarm_rtt = 0; }
                }
                let loss_escalated = states.iter().all(|s| s.consec_alarm_rtt >= loss_alarm);

                // Print consolidated line
                let mut line = format!(
                    "[{}]\t{}\thost={}\trole={}\tclient=\"{}\"\tversion=\"{}\"\trtt_ms=",
                    status, ts_now(), hostname, role, client_name, client_ver
                );
                for (i, v) in rtts.iter().enumerate() {
                    if i > 0 { line.push(','); }
                    match v {
                        Some(ms) => line.push_str(&format!("{:.2}", ms)),
                        None => line.push_str("timeout"),
                    }
                }
                if alarm_rtt { line.push_str("  ALARM_RTT"); }
                if loss_escalated { line.push_str(" ALARM_LOSS"); }
                out_line(&mut writer, &line);
            }

            // Send NEXT packet exactly on schedule
            seq = seq.wrapping_add(1);
            let send_ns = now_unix_ns();
            // IMPORTANT: encode per server so each gets its own prev_recv_ns
            let payload_len = payload.min(MAX_UDP_PAYLOAD - HEADER_MIN);
            for (i, addr) in servers.iter().enumerate() {
                // timestamp for THIS server
                let per_server_prev_recv_ns = states[i].last_recv_ns;

                let n = encode_packet(
                    seq,
                    send_ns,
                    per_server_prev_recv_ns,
                    &hostname,
                    &role,
                    &client_name,
                    &client_ver,
                    payload_len,
                    &mut tx,
                );

                let _ = sock.send_to(&tx[..n], addr);
            }
            current_rtts.clear();

            // Maintain a steady cadence (avoid drift if we were late)
            next_send += interval;
            if Instant::now() > next_send + interval {
                next_send = Instant::now() + interval;
            }

            // Receive for *this seq* up to min(timeout, time until next tick).
            // We always report missing replies as "timeout"
            let send_instant = Instant::now();
            let full_timeout_deadline = send_instant + timeout;
            let recv_deadline = if full_timeout_deadline < next_send {
                full_timeout_deadline
            } else {
                next_send
            };
            while Instant::now() < recv_deadline {
                match sock.recv_from(&mut rx) {
                    Ok((nr, src)) => {
                        if let Some((_ver, rseq, send_ns_echo, _prev_recv_unused, _h, _r, _c, _v)) =
                            decode_packet(&rx[..nr])
                        {
                            if rseq == seq && !current_rtts.contains_key(&src) {
                                let recv_ns = now_unix_ns();
                                let rtt = diff_ms(recv_ns, send_ns_echo);
                                current_rtts.insert(src, rtt);
                                if let Some(pos) = servers.iter().position(|a| *a == src) {
                                    states[pos].last_recv_ns = recv_ns;
                                }
                            }
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(_e) => break,
                }
            }
        }

        // (3) Tiny sleep prevents a tight spin
        std::thread::sleep(Duration::from_millis(1));
    }
}

/* -------------------------------------------------------------------------- */
/*                                   Server                                    */
/* -------------------------------------------------------------------------- */

fn run_server(
    bind: &str,
    _interval: Duration,
    timeout: Duration,
    rtt_alarm: Duration,
    loss_alarm: u64,
    log_path: Option<String>,
) -> Result<(), String> {
    let bind_addr = resolve_ipv4(bind)?;
    let sock = UdpSocket::bind(bind_addr).map_err(|e| format!("bind {}: {}", bind_addr, e))?;
    sock.set_nonblocking(true).map_err(|e| format!("set nonblocking: {}", e))?;

    let mut writer: Option<BufWriter<File>> = if let Some(path) = log_path {
        let file = OpenOptions::new().create(true).append(true).open(&path)
            .map_err(|e| format!("cannot open log file {}: {}", path, e))?;
        Some(BufWriter::new(file))
    } else { None };

    out_line(&mut writer, &format!(
        "[server]\t{}\tbind={}\trtt_alarm_ms={}\tloss_alarm={}\ttimeout_ms={}",
        ts_now(), bind, rtt_alarm.as_millis(), loss_alarm, timeout.as_millis()
    ));

    let mut hosts: HashMap<SocketAddr, HostState> = HashMap::new();
    let mut buf = vec![0u8; 2048];

    loop {
        match sock.recv_from(&mut buf) {
            Ok((nr, peer)) => {
                if let Some((_ver, seq, send_ns, prev_recv_ns, host, role, client, verstr)) = decode_packet(&buf[..nr]) {
                    let st = hosts.entry(peer).or_default();

                    // Enforce monotonic sequence numbers: ignore out-of-order/duplicate packets
                    if seq <= st.last_seq {
                        // still echo back so client can progress its RTT
                        let _ = sock.send_to(&buf[..nr], peer);
                        // cheap log
                        let line = format!(
                            "[ok]\t{}\thost={}\trole={}\tclient=\"{}\"\tversion=\"{}\"\trtt_ms=out_of_order",
                            ts_now(), host, st.last_role, st.last_client, st.last_version
                        );
                        out_line(&mut writer, &line);
                        continue;
                    }

                    // Housekeeping
                    st.last_role = role;
                    st.last_client = client;
                    st.last_version = verstr;
                    st.last_seen = Instant::now();

                    // Compute RTT for seq-1 using client wallclock: prev_recv_ns - prev_send_ns
                    let mut rtt_ms = 0.0f64;
                    let mut have_prev = false;
                    let mut alarm = false;

                    if let Some(prev_send) = st.prev_send_ns {
                        if prev_recv_ns > 0 && st.prev_recv_ns_seen.map_or(true, |p| prev_recv_ns > p) {
                            rtt_ms = diff_ms(prev_recv_ns, prev_send);
                            have_prev = true;

                            // Update baseline on successes
                            if st.base_avg.is_none() && st.base_cnt < PROBE_SAMPLES {
                                st.base_sum += rtt_ms;
                                st.base_cnt += 1;
                                if st.base_cnt == PROBE_SAMPLES {
                                    st.base_avg = Some(st.base_sum / PROBE_SAMPLES as f64);
                                }
                            }

                            // Immediate alarm if above rtt_alarm
                            if rtt_ms > rtt_alarm.as_millis() as f64 {
                                alarm = true;
                            }

                            st.prev_recv_ns_seen = Some(prev_recv_ns);
                        } else {
                            // no progress for previous tick: only alarm if past timeout
                            if st.last_seen.elapsed() >= timeout { alarm = true; }
                        }
                    } // else bootstrap, no RTT yet

                    if alarm { st.consec_alarm_rtt += 1; } else { st.consec_alarm_rtt = 0; }
                    let is_loss = st.consec_alarm_rtt >= loss_alarm;

                    // Decide status label using baseline grace if we have rtt
                    let status = if is_loss {
                        "loss"
                    } else if have_prev {
                        if let Some(avg) = st.base_avg {
                            if (rtt_ms - avg) >= WARN_ABS_MARGIN_MS && rtt_ms >= avg * 1.5 { "warn" } else { "ok" }
                        } else {
                            "ok"
                        }
                    } else if st.prev_send_ns.is_some() {
                        "ok" // no progress yet within timeout window
                    } else {
                        "ok" // bootstrap
                    };

                    // Log (numeric RTT if available; else 'timeout' once we have prev_send_ns; else 'bootstrap')
                    let rtt_field = if have_prev {
                        format!("{:.2}", rtt_ms)
                    } else if st.prev_send_ns.is_some() {
                        "timeout".to_string()
                    } else {
                        "bootstrap".to_string()
                    };

                    let mut line = format!(
                        "[{}]\t{}\thost={}\trole={}\tclient=\"{}\"\tversion=\"{}\"\trtt_ms={}",
                        status, ts_now(), host, st.last_role, st.last_client, st.last_version, rtt_field
                    );
                    if alarm { line.push_str("  ALARM_RTT"); }
                    out_line(&mut writer, &line);

                    // Echo back packet so client can measure its RTT
                    let _ = sock.send_to(&buf[..nr], peer);

                    // Update prev_send_ns with this packet's send_ns for next tick and seq
                    st.prev_send_ns = Some(send_ns);
                    st.last_seq = seq;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(format!("recv: {}", e)),
        }
    }
}

/* -------------------------------------------------------------------------- */
/*                                     main                                    */
/* -------------------------------------------------------------------------- */

fn main() {
    let args = Args::parse();
    match args.mode {
        Mode::Client {
            server, bind, interval_ms, timeout_ms, rtt_alarm_ms, loss_alarm, payload,
            pubkey, ledger, hostname, log
        } => {
            let interval = Duration::from_millis(interval_ms);
            let timeout = Duration::from_millis(timeout_ms);
            let rtt_alarm = Duration::from_millis(rtt_alarm_ms);
            if let Err(e) = run_client(
                &server, &bind, interval, timeout, rtt_alarm, loss_alarm, payload,
                pubkey, ledger, hostname, log
            ) {
                eprintln!("client error: {}", e);
                std::process::exit(1);
            }
        }
        Mode::Server { bind, interval_ms, timeout_ms, rtt_alarm_ms, loss_alarm, log } => {
            let interval = Duration::from_millis(interval_ms);
            let timeout = Duration::from_millis(timeout_ms);
            let rtt_alarm = Duration::from_millis(rtt_alarm_ms);
            if let Err(e) = run_server(&bind, interval, timeout, rtt_alarm, loss_alarm, log) {
                eprintln!("server error: {}", e);
                std::process::exit(1);
            }
        }
    }
}
