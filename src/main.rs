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

// Grace thresholds (aligned client/server): warn requires BOTH
//  - absolute +20ms over baseline AND
//  - >= 1.5x baseline
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

        /// Local bind address (e.g. 0.0.0.0:0)
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: String,

        /// Send interval in ms
        #[arg(long = "interval-ms", default_value = "500")]
        interval_ms: u64,

        /// Read timeout in ms
        #[arg(long = "timeout-ms", default_value = "1500")]
        timeout_ms: u64,

        /// RTT alarm threshold in ms (ALARM_RTT if a numeric RTT exceeds this)
        #[arg(long = "rtt-alarm-ms", default_value = "150")]
        rtt_alarm_ms: u64,

        /// Raise LOSS after this many consecutive alarm ticks
        #[arg(long = "loss-alarm", default_value = "5")]
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

        /// Log file path (optional)
        #[arg(long)]
        log: Option<String>,
    },

    /// Server: receive heartbeats and assess health
    Server {
        /// Bind address, e.g. 0.0.0.0:7071
        #[arg(long, default_value = "0.0.0.0:7071")]
        bind: String,

        /// Expected client send interval (ms) – informational
        #[arg(long = "interval-ms", default_value = "500")]
        interval_ms: u64,

        /// Consider a host lost if no packet within this timeout (ms)
        #[arg(long = "timeout-ms", default_value = "1500")]
        timeout_ms: u64,

        /// ALARM_RTT if derived full RTT (prev_recv_ns - prev_send_ns) is above this (ms)
        #[arg(long = "rtt-alarm-ms", default_value = "150")]
        rtt_alarm_ms: u64,

        /// After this many consecutive alarm ticks, emit loss
        #[arg(long = "loss-alarm", default_value = "5")]
        loss_alarm: u64,

        /// Log file path (optional)
        #[arg(long)]
        log: Option<String>,
    },
}

#[derive(Parser, Debug)]
#[command(author, version, about="solana-heartbeat (client/server)")]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

/* -------------------------------------------------------------------------- */
/*                               Small utilities                               */
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

/* -------------------------------------------------------------------------- */
/*                             Encode / decode v4                              */
/* -------------------------------------------------------------------------- */

fn put_str(buf: &mut [u8], off: &mut usize, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(65535);
    LittleEndian::write_u16(&mut buf[*off..*off + 2], len as u16);
    *off += 2;
    buf[*off..*off + len].copy_from_slice(&bytes[..len]);
    *off += len;
}

fn get_str<'a>(buf: &'a [u8], off: &mut usize) -> Option<&'a str> {
    if *off + 2 > buf.len() { return None; }
    let len = LittleEndian::read_u16(&buf[*off..*off + 2]) as usize;
    *off += 2;
    if *off + len > buf.len() { return None; }
    let s = std::str::from_utf8(&buf[*off..*off + len]).ok()?;
    *off += len;
    Some(s)
}

fn encode_packet(
    buf: &mut [u8],
    hostname: &str,
    role: &str,
    client: &str,
    version_str: &str,
    seq: u64,
    send_ns: i64,
    prev_recv_ns: i64,
) -> usize {
    let mut off = 0;
    LittleEndian::write_u32(&mut buf[off..off + 4], MAGIC); off += 4;
    LittleEndian::write_u32(&mut buf[off..off + 4], VERSION); off += 4;
    LittleEndian::write_u64(&mut buf[off..off + 8], seq); off += 8;
    LittleEndian::write_i64(&mut buf[off..off + 8], send_ns); off += 8;
    LittleEndian::write_i64(&mut buf[off..off + 8], prev_recv_ns); off += 8;

    put_str(buf, &mut off, hostname);
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
/*                                    Client                                   */
/* -------------------------------------------------------------------------- */

#[derive(Default, Clone)]
struct UpstreamState {
    last_recv_ns: i64, // 0 when none yet
    consec_alarm_rtt: u64,
}

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
    _ledger: Option<String>,
    hostname_override: Option<String>,
) -> Result<(), String> {
    if payload < HEADER_MIN || payload > MAX_UDP_PAYLOAD {
        return Err(format!("payload-size must be between {} and {}", HEADER_MIN, MAX_UDP_PAYLOAD));
    }

    let parts: Vec<&str> = servers_csv.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    if parts.is_empty() || parts.len() > 2 {
        return Err("provide 1 or 2 servers separated by a comma".into());
    }
    let servers: Vec<SocketAddr> = parts.iter().map(|p| resolve_ipv4(*p)).collect::<Result<_,_>>()?;

    let bind_addr = resolve_ipv4(bind)?;
    let sock = UdpSocket::bind(bind_addr).map_err(|e| format!("bind {}: {}", bind_addr, e))?;
    sock.set_nonblocking(true).map_err(|e| format!("set nonblocking: {}", e))?;

    // Node role/client/version via client_checks.rs
    let (client_name, client_ver) = client_checks::detect_client_and_version();
    let vote_state = client_checks::vote_state_from_tower(None, pubkey.as_deref());
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
    let mut seq: u64 = 1;
    let mut buf = vec![0u8; payload];
    let mut rx = [0u8; 2048];
    let mut current_rtts: HashMap<SocketAddr, f64> = HashMap::new();

    // Baseline per server
    let mut base_sum: Vec<f64> = vec![0.0; servers.len()];
    let mut base_cnt: Vec<usize> = vec![0; servers.len()];
    let mut base_avg: Vec<Option<f64>> = vec![None; servers.len()];

    out_line(
        &mut writer,
        &format!(
            "[client]\t{}\thost={}\trole={}\tclient=\"{}\"\tversion=\"{}\"\tdests={}",
            ts_now(),
            hostname,
            role,
            client_name,
            client_ver,
            servers.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(",")
        ),
    );

    loop {
        let send_ns = now_unix_ns();

        // Send one probe to each server, carrying prev_recv_ns for that server
        for (i, addr) in servers.iter().enumerate() {
            let prev_recv_ns = states[i].last_recv_ns;
            let n = encode_packet(&mut buf, &hostname, &role, &client_name, &client_ver, seq, send_ns, prev_recv_ns);
            let _ = sock.send_to(&buf[..n], addr);
        }

        // Receive echoes until timeout expires (nonblocking, soft loop)
        current_rtts.clear();
        let deadline = SystemTime::now() + timeout;
        while SystemTime::now() < deadline {
            match sock.recv_from(&mut rx) {
                Ok((nr, src)) => {
                    if let Some((_ver, rseq, send_ns_echo, _prev_recv_unused, _h, _r, _c, _v)) = decode_packet(&rx[..nr]) {
                        if rseq == seq && !current_rtts.contains_key(&src) {
                            // Log local recv_ns and RTT (timeout fix: numeric always if reply arrived)
                            let recv_ns = now_unix_ns();
                            let rtt = diff_ms(recv_ns, send_ns_echo);
                            current_rtts.insert(src, rtt);
                            // will ship recv_ns as prev_recv_ns on next tick
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

        // Build ordered RTTs and decide status with unified WARN grace
        let mut rtts: Vec<Option<f64>> = Vec::with_capacity(servers.len());
        let mut any_timeout = false;
        for addr in &servers {
            if let Some(ms) = current_rtts.get(addr) {
                rtts.push(Some(*ms));
            } else {
                rtts.push(None);
                any_timeout = true;
            }
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
        let status = if any_timeout {
            "loss"
        } else if warn_flags.iter().any(|b| *b) {
            "warn"
        } else {
            "ok"
        };

        // ALARM_RTT: any timeout OR any numeric rtt > rtt_alarm_ms
        let mut alarm_rtt = false;
        for v in &rtts {
            match v {
                None => { alarm_rtt = true; }
                Some(ms) if *ms > rtt_alarm.as_millis() as f64 => { alarm_rtt = true; }
                _ => {}
            }
        }
        if alarm_rtt {
            for (i, v) in rtts.iter().enumerate() {
                let this_alarm = match v { None => true, Some(ms) => *ms > rtt_alarm.as_millis() as f64 };
                if this_alarm { states[i].consec_alarm_rtt += 1; } else { states[i].consec_alarm_rtt = 0; }
            }
        } else {
            for s in &mut states { s.consec_alarm_rtt = 0; }
        }
        let loss_escalated = states.iter().all(|s| s.consec_alarm_rtt >= loss_alarm);

        // Print line (timeout only if truly no reply)
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

        seq = seq.wrapping_add(1);
        std::thread::sleep(interval);
    }
}

/* -------------------------------------------------------------------------- */
/*                                    Server                                   */
/* -------------------------------------------------------------------------- */

struct HostState {
    // Rolling baseline for derived RTT
    base_sum: f64,
    base_cnt: usize,
    base_avg: Option<f64>,

    // previous client's send_ns (for seq-1); used with next packet's prev_recv_ns
    prev_send_ns: Option<i64>,
    prev_recv_ns_seen: Option<i64>,

    // Consecutive alarm ticks
    consec_alarm_rtt: u64,

    // Meta
    last_role: String,
    last_client: String,
    last_version: String,

    // Housekeeping
    last_seen: Instant,
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
        }
    }
}

fn run_server(
    bind: &str,
    _interval: Duration,
    _timeout: Duration,
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
        "[server]\t{}\tbind={}\trtt_alarm={}ms\tloss_alarm={}",
        ts_now(), bind_addr, rtt_alarm.as_millis(), loss_alarm
    ));

    let mut states: HashMap<String, HostState> = HashMap::new();
    let mut buf = vec![0u8; 4096];

    loop {
        match sock.recv_from(&mut buf) {
            Ok((nr, peer)) => {
                if let Some((_ver, _seq, send_ns, prev_recv_ns, host, role, client, verstr)) = decode_packet(&buf[..nr]) {
                    let st = states.entry(host.clone()).or_insert_with(HostState::default);

                    st.last_role = role;
                    st.last_client = client;
                    st.last_version = verstr;
                    st.last_seen = Instant::now();

                    // Compute RTT for seq-1 using client wallclock: prev_recv_ns - prev_send_ns
                    let mut have_prev = false;
                    let mut rtt_ms = 0.0;
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
                            // no progress -> treat as timeout for the previous tick
                            alarm = true;
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
                        "loss" // expected a prev_recv_ns and didn't get one -> timeout
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

                    // Update prev_send_ns with this packet's send_ns for next tick
                    st.prev_send_ns = Some(send_ns);
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
    let args = Cli::parse();
    match args.mode {
        Mode::Client {
            server, bind, interval_ms, timeout_ms, rtt_alarm_ms, loss_alarm, payload, log, pubkey, ledger, hostname
        } => {
            let interval = Duration::from_millis(interval_ms);
            let timeout = Duration::from_millis(timeout_ms);
            let rtt_alarm = Duration::from_millis(rtt_alarm_ms);
            if let Err(e) = run_client(
                &server, &bind, interval, timeout, rtt_alarm, loss_alarm, payload, log, pubkey, ledger, hostname
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
