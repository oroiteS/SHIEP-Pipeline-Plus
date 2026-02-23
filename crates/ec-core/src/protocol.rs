use crate::error::{EcError, EcResult};
use foreign_types::ForeignType;
use openssl::error::ErrorStack;
use openssl::ssl::{Ssl, SslConnector, SslMethod, SslOptions, SslVerifyMode};
use openssl_sys as ffi;
use std::ffi::c_uint;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub fn query_assigned_ip(server: &str, token: &str) -> EcResult<[u8; 4]> {
    let (authority, host) = parse_server(server)?;
    let token_bytes = token.as_bytes();
    if token_bytes.len() != 48 {
        return Err(EcError::Runtime(format!(
            "invalid protocol token length: expected 48, got {}",
            token_bytes.len()
        )));
    }

    query_assigned_ip_once(&authority, &host, token_bytes)
}

pub fn start_tunnel_runtime(_server: &str, _token: &str, _assigned_ip: [u8; 4]) -> EcResult<()> {
    Err(EcError::NotImplemented("protocol.start_tunnel_runtime"))
}

fn query_assigned_ip_once(authority: &str, host: &str, token_bytes: &[u8]) -> EcResult<[u8; 4]> {
    let tcp = TcpStream::connect(authority)
        .map_err(|e| EcError::Runtime(format!("vpn tcp connect failed: {e}")))?;
    tcp.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| EcError::Runtime(format!("set read timeout failed: {e}")))?;
    tcp.set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| EcError::Runtime(format!("set write timeout failed: {e}")))?;

    let mut builder = SslConnector::builder(SslMethod::tls_client())
        .map_err(|e| EcError::Runtime(format!("vpn tls builder create failed: {e}")))?;
    builder.set_verify(SslVerifyMode::NONE);
    builder.set_options(SslOptions::NO_TICKET);
    builder.set_security_level(0);
    builder
        .set_cipher_list("RC4-SHA:AES128-SHA:AES256-SHA")
        .map_err(|e| EcError::Runtime(format!("set cipher list failed: {e}")))?;

    let connector = builder.build();
    let mut config = connector
        .configure()
        .map_err(|e| EcError::Runtime(format!("vpn tls configure failed: {e}")))?;
    config.set_use_server_name_indication(false);
    config.set_verify_hostname(false);
    let mut ssl = config
        .into_ssl(host)
        .map_err(|e| EcError::Runtime(format!("vpn tls prepare failed: {e}")))?;
    apply_l3ip_session_id(&mut ssl, 0x0303)?;

    let mut stream = ssl
        .connect(tcp)
        .map_err(|e| EcError::Runtime(format!("vpn tls handshake failed: {e}")))?;

    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    message.extend_from_slice(token_bytes);
    message.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    ]);
    stream
        .write_all(&message)
        .map_err(|e| EcError::Runtime(format!("query-ip write failed: {e}")))?;

    let mut reply = [0u8; 0x80];
    let mut total = 0usize;
    let deadline = Instant::now() + Duration::from_secs(10);
    while total < reply.len() && Instant::now() < deadline {
        match stream.read(&mut reply[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if total >= 8 {
                    break;
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                continue;
            }
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

    Ok([reply[4], reply[5], reply[6], reply[7]])
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

fn parse_server(server: &str) -> EcResult<(String, String)> {
    let trimmed = server.trim();
    if trimmed.is_empty() {
        return Err(EcError::InvalidConfig("server is required"));
    }
    let no_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let authority_raw = no_scheme
        .split('/')
        .next()
        .ok_or_else(|| EcError::Runtime("invalid server address".to_string()))?;
    if authority_raw.is_empty() {
        return Err(EcError::Runtime("invalid server authority".to_string()));
    }
    let authority = if has_explicit_port(authority_raw) {
        authority_raw.to_string()
    } else {
        format!("{authority_raw}:443")
    };
    let host = extract_host(&authority)?;
    Ok((authority, host))
}

fn has_explicit_port(authority: &str) -> bool {
    if authority.starts_with('[') {
        authority.contains("]:")
    } else {
        authority.rsplit_once(':').is_some()
    }
}

fn extract_host(authority: &str) -> EcResult<String> {
    if authority.starts_with('[') {
        let end = authority
            .find(']')
            .ok_or_else(|| EcError::Runtime("invalid ipv6 authority format".to_string()))?;
        return Ok(authority[1..end].to_string());
    }

    if let Some((host, _)) = authority.rsplit_once(':') {
        if host.is_empty() {
            return Err(EcError::Runtime(
                "invalid host in server authority".to_string(),
            ));
        }
        return Ok(host.to_string());
    }

    Ok(authority.to_string())
}

#[cfg(test)]
mod tests {
    use super::parse_server;

    #[test]
    fn parse_server_appends_default_port() {
        let (authority, host) = parse_server("vpn.example.com").unwrap();
        assert_eq!(authority, "vpn.example.com:443");
        assert_eq!(host, "vpn.example.com");
    }
}
