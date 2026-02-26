use crate::endpoint::parse_server;
use crate::error::{EcError, EcResult};
use crate::output::{self, Scope};
use foreign_types::ForeignType;
use openssl::error::ErrorStack;
use openssl::ssl::{Ssl, SslStream};
use openssl_sys as ffi;
use std::ffi::c_uint;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::{Condvar, Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

const STREAM_RETRY_LIMIT: usize = 5;
const STREAM_RETRY_DELAY: Duration = Duration::from_secs(1);
const QUERY_IP_REPLY_TIMEOUT: Duration = Duration::from_secs(10);
const STREAM_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const PROTOCOL_TOKEN_LEN: usize = 48;
const RUNTIME_ALREADY_STARTED: &str = "tunnel runtime already started in this process";

#[derive(Clone, Copy)]
enum StreamProfile {
    Rx,
    Tx,
}

impl StreamProfile {
    fn op_code(self) -> u8 {
        match self {
            Self::Rx => 0x06,
            Self::Tx => 0x05,
        }
    }

    fn expected_reply(self) -> u8 {
        match self {
            Self::Rx => 0x01,
            Self::Tx => 0x02,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Rx => "rx",
            Self::Tx => "tx",
        }
    }
}

#[derive(Clone)]
struct TunnelRuntimeParams {
    authority: String,
    host: String,
    token: [u8; PROTOCOL_TOKEN_LEN],
    ip_rev: [u8; 4],
}

impl TunnelRuntimeParams {
    fn new(
        authority: String,
        host: String,
        token: [u8; PROTOCOL_TOKEN_LEN],
        assigned_ip: [u8; 4],
    ) -> Self {
        Self {
            authority,
            host,
            token,
            ip_rev: [
                assigned_ip[3],
                assigned_ip[2],
                assigned_ip[1],
                assigned_ip[0],
            ],
        }
    }

    fn open_stream(&self, profile: StreamProfile) -> EcResult<SslStream<TcpStream>> {
        open_data_stream(
            &self.authority,
            &self.host,
            &self.token,
            &self.ip_rev,
            profile,
        )
    }

    fn reopen_stream(
        &self,
        profile: StreamProfile,
        retries: usize,
    ) -> EcResult<SslStream<TcpStream>> {
        reopen_data_stream(
            &self.authority,
            &self.host,
            &self.token,
            &self.ip_rev,
            profile,
            retries,
        )
    }
}

static TX_PACKET_SENDER: OnceLock<mpsc::Sender<Vec<u8>>> = OnceLock::new();
static QUERY_KEEPALIVE: OnceLock<Mutex<Option<SslStream<TcpStream>>>> = OnceLock::new();
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

fn parse_protocol_token(token: &str) -> EcResult<[u8; PROTOCOL_TOKEN_LEN]> {
    let token_bytes = token.as_bytes();
    if token_bytes.len() != PROTOCOL_TOKEN_LEN {
        return Err(EcError::Runtime(format!(
            "invalid protocol token length: expected {PROTOCOL_TOKEN_LEN}, got {}",
            token_bytes.len()
        )));
    }

    token_bytes.try_into().map_err(|_| {
        EcError::Runtime(format!(
            "failed to convert protocol token into fixed {PROTOCOL_TOKEN_LEN}-byte array"
        ))
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
    keep_query_stream_alive(stream)?;
    Ok(assigned_ip)
}

fn rx_worker_loop(
    runtime: TunnelRuntimeParams,
    mut stream: SslStream<TcpStream>,
    tx: mpsc::Sender<Vec<u8>>,
) -> EcResult<()> {
    let mut retries = 0usize;
    let mut buf = [0u8; 4096];

    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                retries += 1;
                stream = runtime.reopen_stream(StreamProfile::Rx, retries)?;
            }
            Ok(n) => {
                retries = 0;
                if tx.send(buf[..n].to_vec()).is_err() {
                    return Ok(());
                }
            }
            Err(e) if is_wouldblock_or_timeout(&e) => continue,
            Err(_) => {
                retries += 1;
                stream = runtime.reopen_stream(StreamProfile::Rx, retries)?;
            }
        }
    }
}

fn tx_worker_loop(
    runtime: TunnelRuntimeParams,
    mut stream: SslStream<TcpStream>,
    rx: mpsc::Receiver<Vec<u8>>,
) -> EcResult<()> {
    let mut retries = 0usize;
    loop {
        let packet = match rx.recv() {
            Ok(packet) => packet,
            Err(_) => return Ok(()),
        };

        if stream.write_all(&packet).is_ok() {
            retries = 0;
            continue;
        }

        retries += 1;
        stream = runtime.reopen_stream(StreamProfile::Tx, retries)?;
        stream.write_all(&packet).map_err(|e| {
            EcError::Runtime(format!("tx stream write failed after reconnect: {e}"))
        })?;
    }
}

fn reopen_data_stream(
    authority: &str,
    host: &str,
    token: &[u8; PROTOCOL_TOKEN_LEN],
    ip_rev: &[u8; 4],
    profile: StreamProfile,
    retries: usize,
) -> EcResult<SslStream<TcpStream>> {
    if retries > STREAM_RETRY_LIMIT {
        return Err(EcError::Runtime(format!(
            "{} stream reached retry limit",
            profile.label()
        )));
    }
    thread::sleep(STREAM_RETRY_DELAY);
    open_data_stream(authority, host, token, ip_rev, profile)
}

fn build_query_ip_message(token: &[u8; PROTOCOL_TOKEN_LEN]) -> [u8; 64] {
    let mut message = [0u8; 64];
    message[4..(4 + PROTOCOL_TOKEN_LEN)].copy_from_slice(token);
    message[60..64].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
    message
}

fn build_stream_handshake_message(
    op_code: u8,
    token: &[u8; PROTOCOL_TOKEN_LEN],
    ip_rev: &[u8; 4],
) -> [u8; 64] {
    let mut message = [0u8; 64];
    message[0] = op_code;
    message[4..(4 + PROTOCOL_TOKEN_LEN)].copy_from_slice(token);
    message[60..64].copy_from_slice(ip_rev);
    message
}

fn open_data_stream(
    authority: &str,
    host: &str,
    token: &[u8; PROTOCOL_TOKEN_LEN],
    ip_rev: &[u8; 4],
    profile: StreamProfile,
) -> EcResult<SslStream<TcpStream>> {
    let mut stream = connect_vpn_tls(authority, host)?;
    let op_code = profile.op_code();
    let expected_reply = profile.expected_reply();

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
            output::value(op),
        )));
    }
    if reply[0] != expected_reply {
        let expected = format!("0x{expected_reply:02x}");
        let got = format!("0x{:02x}", reply[0]);
        let op = format!("0x{op_code:02x}");
        return Err(EcError::Runtime(format!(
            "unexpected {} stream handshake reply marker; expected: {}; got: {}; op: {}",
            profile.label(),
            output::value(expected),
            output::value(got),
            output::value(op),
        )));
    }

    Ok(stream)
}

fn connect_vpn_tls(authority: &str, host: &str) -> EcResult<SslStream<TcpStream>> {
    let tcp = crate::tls::connect_tcp_with_timeout(authority, Duration::from_secs(5), "vpn")?;
    let mut builder = crate::tls::new_insecure_connector_builder("vpn")?;
    builder.set_security_level(0);
    builder
        .set_cipher_list("RC4-SHA:AES128-SHA:AES256-SHA")
        .map_err(|e| EcError::Runtime(format!("set cipher list failed: {e}")))?;

    let connector = builder.build();
    let mut ssl = crate::tls::into_insecure_ssl_with(&connector, host, "vpn", |config| {
        config.set_use_server_name_indication(false);
    })?;
    apply_l3ip_session_id(&mut ssl, 0x0303)?;

    crate::tls::handshake(ssl, tcp, "vpn")
}

fn keep_query_stream_alive(stream: SslStream<TcpStream>) -> EcResult<()> {
    let holder = QUERY_KEEPALIVE.get_or_init(|| Mutex::new(None));
    let mut guard = holder
        .lock()
        .map_err(|_| EcError::Runtime("query keepalive mutex poisoned".to_string()))?;
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

fn apply_l3ip_session_id(ssl: &mut Ssl, session_version: i32) -> EcResult<()> {
    let sid = l3ip_session_id();
    let master_key = l3ip_master_key();
    unsafe {
        let session = ssl_session_new().ok_or_else(|| {
            EcError::Runtime(format!("create SSL_SESSION failed: {}", ErrorStack::get()))
        })?;

        let set_proto_rc = ssl_session_set_protocol_version(session, session_version);
        if set_proto_rc != 1 {
            ffi::SSL_SESSION_free(session);
            return Err(EcError::Runtime(format!(
                "SSL_SESSION_set_protocol_version failed: {}",
                ErrorStack::get()
            )));
        }

        let set_master_rc =
            ssl_session_set1_master_key(session, master_key.as_ptr(), master_key.len() as c_uint);
        if set_master_rc != 1 {
            ffi::SSL_SESSION_free(session);
            return Err(EcError::Runtime(format!(
                "SSL_SESSION_set1_master_key failed: {}",
                ErrorStack::get()
            )));
        }

        let set_id_rc = ssl_session_set1_id(session, sid.as_ptr(), sid.len() as c_uint);
        if set_id_rc != 1 {
            ffi::SSL_SESSION_free(session);
            return Err(EcError::Runtime(format!(
                "SSL_SESSION_set1_id failed: {}",
                ErrorStack::get()
            )));
        }

        let set_session_rc = ffi::SSL_set_session(ssl.as_ptr(), session);
        ffi::SSL_SESSION_free(session);
        if set_session_rc != 1 {
            return Err(EcError::Runtime(format!(
                "SSL_set_session failed: {}",
                ErrorStack::get()
            )));
        }
    }
    Ok(())
}

fn l3ip_session_id() -> [u8; 32] {
    let mut sid = [0u8; 32];
    sid[0] = b'L';
    sid[1] = b'3';
    sid[2] = b'I';
    sid[3] = b'P';
    sid
}

fn l3ip_master_key() -> [u8; 48] {
    let mut key = [0u8; 48];
    for (i, v) in key.iter_mut().enumerate() {
        *v = ((i as u8) ^ 0x5a).wrapping_add(0x11);
    }
    key
}

unsafe fn ssl_session_new() -> Option<*mut ffi::SSL_SESSION> {
    unsafe extern "C" {
        fn SSL_SESSION_new() -> *mut ffi::SSL_SESSION;
    }
    let ptr = unsafe { SSL_SESSION_new() };
    if ptr.is_null() { None } else { Some(ptr) }
}

unsafe fn ssl_session_set1_id(session: *mut ffi::SSL_SESSION, sid: *const u8, len: c_uint) -> i32 {
    unsafe extern "C" {
        fn SSL_SESSION_set1_id(s: *mut ffi::SSL_SESSION, sid: *const u8, sid_len: c_uint) -> i32;
    }
    if session.is_null() || sid.is_null() {
        return 0;
    }
    unsafe { SSL_SESSION_set1_id(session, sid, len) }
}

unsafe fn ssl_session_set_protocol_version(session: *mut ffi::SSL_SESSION, version: i32) -> i32 {
    unsafe extern "C" {
        fn SSL_SESSION_set_protocol_version(s: *mut ffi::SSL_SESSION, version: i32) -> i32;
    }
    if session.is_null() {
        return 0;
    }
    unsafe { SSL_SESSION_set_protocol_version(session, version) }
}

unsafe fn ssl_session_set1_master_key(
    session: *mut ffi::SSL_SESSION,
    key: *const u8,
    len: c_uint,
) -> i32 {
    unsafe extern "C" {
        fn SSL_SESSION_set1_master_key(
            sess: *mut ffi::SSL_SESSION,
            key: *const u8,
            len: c_uint,
        ) -> i32;
    }
    if session.is_null() || key.is_null() {
        return 0;
    }
    unsafe { SSL_SESSION_set1_master_key(session, key, len) }
}

#[cfg(test)]
mod tests {
    use super::{
        PROTOCOL_TOKEN_LEN, build_query_ip_message, build_stream_handshake_message,
        parse_protocol_token,
    };

    #[test]
    fn parse_protocol_token_accepts_48_bytes() {
        let token = "a".repeat(PROTOCOL_TOKEN_LEN);
        let parsed = parse_protocol_token(&token).unwrap();
        assert_eq!(parsed.len(), PROTOCOL_TOKEN_LEN);
        assert_eq!(parsed[0], b'a');
    }

    #[test]
    fn parse_protocol_token_rejects_other_lengths() {
        let token = "a".repeat(PROTOCOL_TOKEN_LEN - 1);
        assert!(parse_protocol_token(&token).is_err());
    }

    #[test]
    fn query_ip_message_has_expected_layout() {
        let token = [0x11u8; PROTOCOL_TOKEN_LEN];
        let message = build_query_ip_message(&token);
        assert_eq!(message.len(), 64);
        assert_eq!(message[0], 0x00);
        assert!(
            message[4..(4 + PROTOCOL_TOKEN_LEN)]
                .iter()
                .all(|v| *v == 0x11)
        );
        assert_eq!(&message[60..64], &[0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn stream_message_has_expected_layout() {
        let token = [0x22u8; PROTOCOL_TOKEN_LEN];
        let ip_rev = [4u8, 3, 2, 1];
        let message = build_stream_handshake_message(0x06, &token, &ip_rev);
        assert_eq!(message.len(), 64);
        assert_eq!(message[0], 0x06);
        assert!(
            message[4..(4 + PROTOCOL_TOKEN_LEN)]
                .iter()
                .all(|v| *v == 0x22)
        );
        assert_eq!(&message[60..64], &ip_rev);
    }
}
