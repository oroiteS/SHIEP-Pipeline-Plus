use crate::endpoint::parse_server;
use crate::error::{EcError, EcResult};
use crate::output::{self, Scope};
use crate::protocol_wire::{
    HEARTBEAT_OPAQUE_TAIL_LEN, HEARTBEAT_SESSION_LEN, NativeControlType, PROTOCOL_TOKEN_LEN,
    TX_HEARTBEAT_DEFAULT_DST, build_query_ip_message, build_stream_handshake_message,
    build_tx_heartbeat_packet, is_tx_heartbeat_echo_reply, parse_native_control_frame,
    parse_protocol_token,
};
use openssl::ssl::SslStream;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::{Condvar, Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const STREAM_RETRY_LIMIT: usize = 5;
const STREAM_RETRY_DELAY: Duration = Duration::from_secs(1);
const QUERY_IP_REPLY_TIMEOUT: Duration = Duration::from_secs(10);
const STREAM_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const TX_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(12);
const RUNTIME_ALREADY_STARTED: &str = "tunnel runtime already started in this process";

#[derive(Clone, Copy)]
enum StreamProfile {
    Rx,
    Tx,
}

#[derive(Clone, Copy)]
enum StreamOpenKind {
    First,
    Resume,
}

#[derive(Clone, Copy)]
struct StreamOpenRetry {
    first_attempt: usize,
    delay_first_attempt: bool,
    phase: &'static str,
}

impl StreamProfile {
    fn first_op_code(self) -> u8 {
        match self {
            Self::Rx => 0x06,
            Self::Tx => 0x05,
        }
    }

    fn resume_op_code(self) -> u8 {
        match self {
            Self::Rx => 0x07,
            Self::Tx => 0x08,
        }
    }

    fn op_code(self, kind: StreamOpenKind) -> u8 {
        match kind {
            StreamOpenKind::First => self.first_op_code(),
            StreamOpenKind::Resume => self.resume_op_code(),
        }
    }

    fn expected_ack(self) -> NativeControlType {
        match self {
            Self::Rx => NativeControlType::RxAck,
            Self::Tx => NativeControlType::TxAck,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Rx => "rx",
            Self::Tx => "tx",
        }
    }
}

impl StreamOpenRetry {
    fn first_open() -> Self {
        Self {
            first_attempt: 0,
            delay_first_attempt: false,
            phase: "open",
        }
    }

    fn reconnect(first_attempt: usize) -> Self {
        Self {
            first_attempt,
            delay_first_attempt: true,
            phase: "reconnect",
        }
    }
}

#[derive(Clone)]
struct TunnelRuntimeParams {
    authority: String,
    host: String,
    token: [u8; PROTOCOL_TOKEN_LEN],
    assigned_ip: [u8; 4],
    ip_rev: [u8; 4],
    heartbeat_dst: [u8; 4],
    heartbeat_tail: [u8; HEARTBEAT_OPAQUE_TAIL_LEN],
}

impl TunnelRuntimeParams {
    fn new(
        authority: String,
        host: String,
        token: [u8; PROTOCOL_TOKEN_LEN],
        assigned_ip: [u8; 4],
    ) -> Self {
        let heartbeat_tail = new_heartbeat_tail(&token, assigned_ip);
        Self {
            authority,
            host,
            token,
            assigned_ip,
            ip_rev: [
                assigned_ip[3],
                assigned_ip[2],
                assigned_ip[1],
                assigned_ip[0],
            ],
            heartbeat_dst: TX_HEARTBEAT_DEFAULT_DST,
            heartbeat_tail,
        }
    }

    fn open_stream(&self, profile: StreamProfile) -> EcResult<SslStream<TcpStream>> {
        open_data_stream_with_retries(
            &self.authority,
            &self.host,
            &self.token,
            &self.ip_rev,
            profile,
            StreamOpenKind::First,
            StreamOpenRetry::first_open(),
        )
    }

    fn reopen_stream(
        &self,
        profile: StreamProfile,
        retries: usize,
    ) -> EcResult<SslStream<TcpStream>> {
        open_data_stream_with_retries(
            &self.authority,
            &self.host,
            &self.token,
            &self.ip_rev,
            profile,
            StreamOpenKind::Resume,
            StreamOpenRetry::reconnect(retries),
        )
    }

    fn tx_heartbeat_packet(&self) -> [u8; 0x4c] {
        build_tx_heartbeat_packet(
            self.assigned_ip,
            self.heartbeat_dst,
            self.heartbeat_session(),
            &self.heartbeat_tail,
        )
    }

    fn is_tx_heartbeat_echo_reply(&self, data: &[u8]) -> bool {
        is_tx_heartbeat_echo_reply(
            data,
            self.assigned_ip,
            self.heartbeat_dst,
            self.heartbeat_session(),
            &self.heartbeat_tail,
        )
    }

    fn heartbeat_session(&self) -> &[u8; HEARTBEAT_SESSION_LEN] {
        self.token[32..48]
            .try_into()
            .expect("protocol token must contain a 16-byte session suffix")
    }
}

static TX_PACKET_SENDER: OnceLock<mpsc::Sender<Vec<u8>>> = OnceLock::new();
static QUERY_IP_STREAM_HOLDER: OnceLock<Mutex<Option<SslStream<TcpStream>>>> = OnceLock::new();
static RX_PACKET_RECEIVER: OnceLock<Mutex<Option<mpsc::Receiver<Vec<u8>>>>> = OnceLock::new();
static TUNNEL_FATAL_STATE: OnceLock<TunnelFatalState> = OnceLock::new();

struct TunnelFatalState {
    reason: Mutex<Option<String>>,
    cv: Condvar,
}

pub fn query_assigned_ip(server: &str, token: &str) -> EcResult<[u8; 4]> {
    let (authority, host) = parse_server(server)?;
    let token_bytes = parse_protocol_token(token)?;

    query_assigned_ip_once(&authority, &host, &token_bytes)
}

pub fn start_tunnel_runtime(server: &str, token: &str, assigned_ip: [u8; 4]) -> EcResult<()> {
    clear_tunnel_fatal_reason();

    let (authority, host) = parse_server(server)?;
    let runtime =
        TunnelRuntimeParams::new(authority, host, parse_protocol_token(token)?, assigned_ip);

    let rx_stream = runtime.open_stream(StreamProfile::Rx)?;
    output::success(Scope::Protocol, "RX handshake successful");
    let tx_stream = runtime.open_stream(StreamProfile::Tx)?;
    output::success(Scope::Protocol, "TX handshake successful");

    let (tx_sender, tx_receiver) = mpsc::channel::<Vec<u8>>();
    let (rx_sender, rx_receiver) = mpsc::channel::<Vec<u8>>();
    install_runtime_channels(tx_sender, rx_receiver)?;

    let rx_runtime = runtime.clone();
    thread::spawn(move || {
        let result = rx_worker_loop(rx_runtime, rx_stream, rx_sender);
        handle_worker_exit(StreamProfile::Rx, result);
    });

    thread::spawn(move || {
        let result = tx_worker_loop(runtime, tx_stream, tx_receiver);
        handle_worker_exit(StreamProfile::Tx, result);
    });

    Ok(())
}

fn install_runtime_channels(
    tx_sender: mpsc::Sender<Vec<u8>>,
    rx_receiver: mpsc::Receiver<Vec<u8>>,
) -> EcResult<()> {
    let rx_holder = RX_PACKET_RECEIVER.get_or_init(|| Mutex::new(None));
    let mut guard = rx_holder
        .lock()
        .map_err(|_| EcError::Runtime("rx packet receiver mutex poisoned".to_string()))?;
    if guard.is_some() || TX_PACKET_SENDER.get().is_some() {
        return Err(runtime_already_started_err());
    }
    TX_PACKET_SENDER
        .set(tx_sender)
        .map_err(|_| runtime_already_started_err())?;
    *guard = Some(rx_receiver);
    Ok(())
}

fn runtime_already_started_err() -> EcError {
    EcError::Runtime(RUNTIME_ALREADY_STARTED.to_string())
}

pub fn send_tunnel_packet(packet: Vec<u8>) -> EcResult<()> {
    let sender = TX_PACKET_SENDER
        .get()
        .ok_or_else(|| EcError::Runtime("tunnel runtime is not started".to_string()))?;
    sender
        .send(packet)
        .map_err(|e| EcError::Runtime(format!("send tunnel packet failed: {e}")))
}

pub fn take_tunnel_packet_receiver() -> EcResult<mpsc::Receiver<Vec<u8>>> {
    let holder = RX_PACKET_RECEIVER
        .get()
        .ok_or_else(|| EcError::Runtime("tunnel runtime is not started".to_string()))?;
    let mut guard = holder
        .lock()
        .map_err(|_| EcError::Runtime("rx packet receiver mutex poisoned".to_string()))?;
    guard.take().ok_or_else(|| {
        EcError::Runtime("tunnel packet receiver was already taken or not initialized".to_string())
    })
}

pub(crate) fn tunnel_fatal_reason() -> Option<String> {
    let state = tunnel_fatal_state();
    match state.reason.lock() {
        Ok(guard) => guard.clone(),
        Err(_) => Some("tunnel fatal reason mutex poisoned".to_string()),
    }
}

pub(crate) fn wait_tunnel_fatal_reason() -> String {
    let state = tunnel_fatal_state();
    let mut guard = match state.reason.lock() {
        Ok(guard) => guard,
        Err(_) => return "tunnel fatal reason mutex poisoned".to_string(),
    };
    loop {
        if let Some(reason) = guard.as_ref() {
            return reason.clone();
        }
        guard = match state.cv.wait(guard) {
            Ok(guard) => guard,
            Err(_) => return "tunnel fatal reason condvar wait poisoned".to_string(),
        };
    }
}

fn clear_tunnel_fatal_reason() {
    let state = tunnel_fatal_state();
    if let Ok(mut guard) = state.reason.lock() {
        *guard = None;
    }
}

fn record_tunnel_fatal_reason(reason: String) {
    let state = tunnel_fatal_state();
    if let Ok(mut guard) = state.reason.lock()
        && guard.is_none()
    {
        *guard = Some(reason);
        state.cv.notify_all();
    }
}

fn worker_exit_detail(profile: StreamProfile, result: EcResult<()>) -> String {
    match result {
        Ok(()) => format!("{} worker exited unexpectedly", profile.label()),
        Err(err) => format!(
            "{} worker stopped: {}",
            profile.label(),
            crate::error::concise_error(err)
        ),
    }
}

fn handle_worker_exit(profile: StreamProfile, result: EcResult<()>) {
    let detail = worker_exit_detail(profile, result);
    output::warn(Scope::Protocol, &detail);
    record_tunnel_fatal_reason(detail);
}

fn tunnel_fatal_state() -> &'static TunnelFatalState {
    TUNNEL_FATAL_STATE.get_or_init(|| TunnelFatalState {
        reason: Mutex::new(None),
        cv: Condvar::new(),
    })
}

fn query_assigned_ip_once(
    authority: &str,
    host: &str,
    token_bytes: &[u8; PROTOCOL_TOKEN_LEN],
) -> EcResult<[u8; 4]> {
    let mut stream = connect_vpn_tls(authority, host)?;

    let message = build_query_ip_message(token_bytes);
    stream
        .write_all(&message)
        .map_err(|e| EcError::Runtime(format!("query-ip write failed: {e}")))?;

    let mut reply = [0u8; 0x80];
    let mut total = 0usize;
    let deadline = Instant::now() + QUERY_IP_REPLY_TIMEOUT;
    while total < reply.len() && Instant::now() < deadline {
        match stream.read(&mut reply[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if total >= 8 {
                    break;
                }
            }
            Err(e) if is_wouldblock_or_timeout(&e) => continue,
            Err(e) => return Err(EcError::Runtime(format!("query-ip read failed: {e}"))),
        }
    }

    if total < 8 {
        return Err(EcError::Runtime(format!(
            "query-ip reply too short or timeout: {total} bytes"
        )));
    }
    if reply[0] != 0x00 {
        return Err(EcError::Runtime(format!(
            "unexpected query-ip reply marker: 0x{:02x}",
            reply[0]
        )));
    }

    let assigned_ip = [reply[4], reply[5], reply[6], reply[7]];
    hold_query_ip_stream(stream)?;
    Ok(assigned_ip)
}

fn rx_worker_loop(
    runtime: TunnelRuntimeParams,
    mut stream: SslStream<TcpStream>,
    tx: mpsc::Sender<Vec<u8>>,
) -> EcResult<()> {
    let mut retries = 0usize;
    let mut heartbeat_reply_count = 0u64;
    let mut buf = [0u8; 4096];

    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                retries += 1;
                stream = runtime.reopen_stream(StreamProfile::Rx, retries)?;
                retries = 0;
            }
            Ok(n) => {
                retries = 0;
                if !should_forward_rx_payload(&buf[..n])? {
                    continue;
                }
                if runtime.is_tx_heartbeat_echo_reply(&buf[..n]) {
                    heartbeat_reply_count += 1;
                    log_rx_heartbeat_if_sampled(heartbeat_reply_count, n);
                }
                if tx.send(buf[..n].to_vec()).is_err() {
                    return Ok(());
                }
            }
            Err(e) if is_wouldblock_or_timeout(&e) => continue,
            Err(_) => {
                retries += 1;
                stream = runtime.reopen_stream(StreamProfile::Rx, retries)?;
                retries = 0;
            }
        }
    }
}

fn should_forward_rx_payload(data: &[u8]) -> EcResult<bool> {
    match parse_native_control_frame(data) {
        Some(NativeControlType::RxAck) => Ok(false),
        Some(control) => Err(EcError::Runtime(format!(
            "unexpected rx control frame: {}({})",
            control.label(),
            control.code()
        ))),
        None => Ok(true),
    }
}

fn tx_worker_loop(
    runtime: TunnelRuntimeParams,
    mut stream: SslStream<TcpStream>,
    rx: mpsc::Receiver<Vec<u8>>,
) -> EcResult<()> {
    let mut retries = 0usize;
    let mut next_heartbeat = Instant::now() + TX_HEARTBEAT_INTERVAL;
    let mut heartbeat_count = 0u64;
    loop {
        let now = Instant::now();
        let (packet, heartbeat_seq) = if now >= next_heartbeat {
            next_heartbeat = now + TX_HEARTBEAT_INTERVAL;
            heartbeat_count += 1;
            (
                runtime.tx_heartbeat_packet().to_vec(),
                Some(heartbeat_count),
            )
        } else {
            match rx.recv_timeout(next_heartbeat - now) {
                Ok(packet) => (packet, None),
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            }
        };

        if stream.write_all(&packet).is_ok() {
            retries = 0;
            log_tx_heartbeat_if_sampled(heartbeat_seq, packet.len());
            continue;
        }

        retries += 1;
        stream = runtime.reopen_stream(StreamProfile::Tx, retries)?;
        stream.write_all(&packet).map_err(|e| {
            EcError::Runtime(format!("tx stream write failed after reconnect: {e}"))
        })?;
        retries = 0;
        log_tx_heartbeat_if_sampled(heartbeat_seq, packet.len());
    }
}

fn log_tx_heartbeat_if_sampled(seq: Option<u64>, len: usize) {
    let Some(seq) = seq else {
        return;
    };
    if !should_log_heartbeat_sample(seq) {
        return;
    }
    output::info(
        Scope::Protocol,
        format_args!(
            "TX heartbeat #{} sent: len {}",
            output::value(seq),
            output::value(len)
        ),
    );
}

fn log_rx_heartbeat_if_sampled(seq: u64, len: usize) {
    if !should_log_heartbeat_sample(seq) {
        return;
    }
    output::info(
        Scope::Protocol,
        format_args!(
            "RX heartbeat #{} received: len {}",
            output::value(seq),
            output::value(len)
        ),
    );
}

fn should_log_heartbeat_sample(seq: u64) -> bool {
    seq.is_power_of_two()
}

fn open_data_stream_with_retries(
    authority: &str,
    host: &str,
    token: &[u8; PROTOCOL_TOKEN_LEN],
    ip_rev: &[u8; 4],
    profile: StreamProfile,
    kind: StreamOpenKind,
    retry: StreamOpenRetry,
) -> EcResult<SslStream<TcpStream>> {
    let mut attempt = retry.first_attempt;
    let mut last_error = None;
    while attempt <= STREAM_RETRY_LIMIT {
        if retry.delay_first_attempt || attempt > retry.first_attempt {
            thread::sleep(STREAM_RETRY_DELAY);
        }
        match open_data_stream(authority, host, token, ip_rev, profile, kind) {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                last_error = Some(crate::error::concise_error(&err));
                attempt += 1;
            }
        }
    }

    let detail = last_error
        .map(|err| format!("; last error: {err}"))
        .unwrap_or_default();
    Err(EcError::Runtime(format!(
        "{} stream reached retry limit during {}{}",
        profile.label(),
        retry.phase,
        detail
    )))
}

fn open_data_stream(
    authority: &str,
    host: &str,
    token: &[u8; PROTOCOL_TOKEN_LEN],
    ip_rev: &[u8; 4],
    profile: StreamProfile,
    kind: StreamOpenKind,
) -> EcResult<SslStream<TcpStream>> {
    let mut stream = connect_vpn_tls(authority, host)?;
    let op_code = profile.op_code(kind);
    let expected_ack = profile.expected_ack();

    let message = build_stream_handshake_message(op_code, token, ip_rev);
    stream
        .write_all(&message)
        .map_err(|e| EcError::Runtime(format!("stream handshake write failed: {e}")))?;

    let mut reply = [0u8; 1500];
    let n = read_stream_once(&mut stream, &mut reply, STREAM_HANDSHAKE_TIMEOUT)?;
    if n == 0 {
        let op = format!("0x{op_code:02x}");
        return Err(EcError::Runtime(format!(
            "{} stream handshake reply is empty or timed out; op: {}",
            profile.label(),
            op,
        )));
    }
    validate_stream_ack(profile, op_code, expected_ack, &reply[..n])?;

    clear_data_stream_read_timeout(&stream, profile)?;
    Ok(stream)
}

fn validate_stream_ack(
    profile: StreamProfile,
    op_code: u8,
    expected_ack: NativeControlType,
    reply: &[u8],
) -> EcResult<()> {
    match parse_native_control_frame(reply) {
        Some(control) if control == expected_ack => Ok(()),
        Some(control) => Err(unexpected_stream_ack_err(
            profile,
            op_code,
            expected_ack,
            format_args!("{}({})", control.label(), control.code()),
        )),
        None if legacy_stream_ack_matches(reply, expected_ack) => Ok(()),
        None => Err(unexpected_stream_ack_err(
            profile,
            op_code,
            expected_ack,
            format_args!("non-control-frame len={}", reply.len()),
        )),
    }
}

fn legacy_stream_ack_matches(reply: &[u8], expected_ack: NativeControlType) -> bool {
    reply.first().copied() == u8::try_from(expected_ack.code()).ok()
}

fn unexpected_stream_ack_err(
    profile: StreamProfile,
    op_code: u8,
    expected_ack: NativeControlType,
    got: std::fmt::Arguments<'_>,
) -> EcError {
    EcError::Runtime(format!(
        "unexpected {} stream handshake ack; expected: {}({}); got: {}; op: 0x{op_code:02x}",
        profile.label(),
        expected_ack.label(),
        expected_ack.code(),
        got,
    ))
}

fn clear_data_stream_read_timeout(
    stream: &SslStream<TcpStream>,
    profile: StreamProfile,
) -> EcResult<()> {
    stream.get_ref().set_read_timeout(None).map_err(|e| {
        EcError::Runtime(format!(
            "clear {} stream read timeout failed: {e}",
            profile.label()
        ))
    })
}

fn connect_vpn_tls(authority: &str, host: &str) -> EcResult<SslStream<TcpStream>> {
    let tcp = crate::tls::connect_vpn_tcp(authority, Duration::from_secs(5))?;
    let mut builder = crate::tls::new_insecure_connector_builder("vpn")?;
    builder.set_security_level(0);
    builder
        .set_cipher_list("RC4-SHA:AES128-SHA:AES256-SHA")
        .map_err(|e| EcError::Runtime(format!("set cipher list failed: {e}")))?;

    let connector = builder.build();
    let mut ssl = crate::tls::into_insecure_ssl_with(&connector, host, "vpn", |config| {
        config.set_use_server_name_indication(false);
    })?;
    crate::protocol_session::apply_l3ip_session_id(&mut ssl, 0x0303)?;

    crate::tls::handshake(ssl, tcp, "vpn")
}

fn hold_query_ip_stream(stream: SslStream<TcpStream>) -> EcResult<()> {
    let holder = QUERY_IP_STREAM_HOLDER.get_or_init(|| Mutex::new(None));
    let mut guard = holder
        .lock()
        .map_err(|_| EcError::Runtime("query-ip stream holder mutex poisoned".to_string()))?;
    *guard = Some(stream);
    Ok(())
}

fn read_stream_once<S: Read + Write>(
    stream: &mut SslStream<S>,
    buf: &mut [u8],
    timeout: Duration,
) -> EcResult<usize> {
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            return Ok(0);
        }
        match stream.read(buf) {
            Ok(0) => return Ok(0),
            Ok(n) => return Ok(n),
            Err(e) if is_wouldblock_or_timeout(&e) => continue,
            Err(e) => return Err(EcError::Runtime(format!("stream read failed: {e}"))),
        }
    }
}

fn is_wouldblock_or_timeout(err: &std::io::Error) -> bool {
    matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

fn new_heartbeat_tail(
    token: &[u8; PROTOCOL_TOKEN_LEN],
    assigned_ip: [u8; 4],
) -> [u8; HEARTBEAT_OPAQUE_TAIL_LEN] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_nanos() as u64)
        .unwrap_or_default();
    let mut seed =
        now ^ (u64::from(std::process::id()) << 32) ^ u64::from(u32::from_be_bytes(assigned_ip));
    for chunk in token.chunks(8) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        seed ^= u64::from_le_bytes(buf).rotate_left(13);
        seed = splitmix64(seed);
    }
    splitmix64(seed).to_le_bytes()
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

#[cfg(test)]
mod tests {
    use super::{
        NativeControlType, StreamOpenKind, StreamProfile, TunnelRuntimeParams,
        should_forward_rx_payload, should_log_heartbeat_sample, validate_stream_ack,
    };

    #[test]
    fn stream_profiles_use_official_first_and_resume_ops() {
        assert_eq!(StreamProfile::Rx.op_code(StreamOpenKind::First), 0x06);
        assert_eq!(StreamProfile::Rx.op_code(StreamOpenKind::Resume), 0x07);
        assert_eq!(StreamProfile::Tx.op_code(StreamOpenKind::First), 0x05);
        assert_eq!(StreamProfile::Tx.op_code(StreamOpenKind::Resume), 0x08);
    }

    #[test]
    fn stream_ack_accepts_matching_aabb_control_frame() {
        let mut frame = [0u8; 0x28];
        frame[0..4].copy_from_slice(b"AABB");
        frame[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert!(
            validate_stream_ack(StreamProfile::Rx, 0x06, NativeControlType::RxAck, &frame).is_ok()
        );

        frame[4..8].copy_from_slice(&2u32.to_le_bytes());
        assert!(
            validate_stream_ack(StreamProfile::Tx, 0x05, NativeControlType::TxAck, &frame).is_ok()
        );
    }

    #[test]
    fn stream_ack_rejects_wrong_type_and_accepts_legacy_marker() {
        let mut frame = [0u8; 0x28];
        frame[0..4].copy_from_slice(b"AABB");
        frame[4..8].copy_from_slice(&2u32.to_le_bytes());
        assert!(
            validate_stream_ack(StreamProfile::Rx, 0x06, NativeControlType::RxAck, &frame).is_err()
        );

        let legacy_marker_reply = [0x01u8, 0, 0, 0, 0, 0, 0, 0];
        assert!(
            validate_stream_ack(
                StreamProfile::Rx,
                0x06,
                NativeControlType::RxAck,
                &legacy_marker_reply
            )
            .is_ok()
        );
    }

    #[test]
    fn rx_payload_filter_consumes_rx_ack_only() {
        let mut frame = [0u8; 0x28];
        frame[0..4].copy_from_slice(b"AABB");
        frame[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert!(!should_forward_rx_payload(&frame).unwrap());

        frame[4..8].copy_from_slice(&15u32.to_le_bytes());
        assert!(should_forward_rx_payload(&frame).is_err());

        let ipv4_packet = [0x45u8, 0, 0, 20, 0, 0, 0, 0];
        assert!(should_forward_rx_payload(&ipv4_packet).unwrap());
    }

    #[test]
    fn tunnel_runtime_builds_tx_heartbeat_from_assigned_ip_and_session_suffix() {
        let mut token = [b'a'; 48];
        token[32..48].copy_from_slice(b"eab27cdf7c24a40f");
        let runtime = TunnelRuntimeParams::new(
            "vpn.example:443".to_string(),
            "vpn.example".to_string(),
            token,
            [10, 166, 80, 12],
        );

        let packet = runtime.tx_heartbeat_packet();
        assert_eq!(&packet[12..16], &[10, 166, 80, 12]);
        assert_eq!(&packet[16..20], &[10, 166, 64, 3]);
        assert_eq!(&packet[46..62], b"eab27cdf7c24a40f");
        assert_eq!(&packet[70..76], b"L3VPN\0");
    }

    #[test]
    fn tx_heartbeat_log_sampling_uses_powers_of_two() {
        let sampled: Vec<u64> = (1..=16)
            .filter(|v| should_log_heartbeat_sample(*v))
            .collect();
        assert_eq!(sampled, vec![1, 2, 4, 8, 16]);
        assert!(!should_log_heartbeat_sample(0));
        assert!(!should_log_heartbeat_sample(3));
        assert!(!should_log_heartbeat_sample(12));
    }
}
