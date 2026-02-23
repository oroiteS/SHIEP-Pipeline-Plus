use crate::error::{EcError, EcResult};
use openssl::ssl::{SslConnector, SslMethod, SslOptions, SslVerifyMode};
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub fn fetch_agent_token(server: &str, twf_id: &str) -> EcResult<String> {
    let (authority, host) = parse_server(server)?;

    let tcp = TcpStream::connect(&authority)
        .map_err(|e| EcError::Runtime(format!("token tcp connect failed: {e}")))?;
    tcp.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| EcError::Runtime(format!("set read timeout failed: {e}")))?;
    tcp.set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| EcError::Runtime(format!("set write timeout failed: {e}")))?;

    let mut builder = SslConnector::builder(SslMethod::tls_client())
        .map_err(|e| EcError::Runtime(format!("token tls builder create failed: {e}")))?;
    builder.set_verify(SslVerifyMode::NONE);
    builder.set_options(SslOptions::NO_TICKET);
    let connector = builder.build();

    let mut config = connector
        .configure()
        .map_err(|e| EcError::Runtime(format!("token tls configure failed: {e}")))?;
    config.set_verify_hostname(false);
    let ssl = config
        .into_ssl(&host)
        .map_err(|e| EcError::Runtime(format!("token tls prepare failed: {e}")))?;
    let mut stream = ssl
        .connect(tcp)
        .map_err(|e| EcError::Runtime(format!("token tls handshake failed: {e}")))?;

    let request = format!(
        "GET /por/conf.csp HTTP/1.1\r\nHost: {authority}\r\nCookie: TWFID={twf_id}\r\nConnection: keep-alive\r\n\r\n\
         GET /por/rclist.csp HTTP/1.1\r\nHost: {authority}\r\nCookie: TWFID={twf_id}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| EcError::Runtime(format!("token request write failed: {e}")))?;

    let mut sink = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => sink.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock => {
                break;
            }
            Err(e) => return Err(EcError::Runtime(format!("token response read failed: {e}"))),
        }
    }
    if sink.is_empty() {
        return Err(EcError::Runtime(
            "token response is empty or timed out".to_string(),
        ));
    }

    let session = stream
        .ssl()
        .session()
        .ok_or_else(|| EcError::Runtime("missing server tls session".to_string()))?;
    if session.id().is_empty() {
        return Err(EcError::Runtime("server tls session id is empty".to_string()));
    }
    let session_id_hex = hex::encode(session.id());
    if session_id_hex.len() < 31 {
        return Err(EcError::Runtime(format!(
            "server session id hex too short: {}",
            session_id_hex.len()
        )));
    }

    let mut token = session_id_hex[..31].to_string();
    token.push('\0');
    Ok(token)
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
    use super::{extract_host, has_explicit_port, parse_server};

    #[test]
    fn parse_server_defaults_to_443() {
        let (authority, host) = parse_server("vpn.example.com").unwrap();
        assert_eq!(authority, "vpn.example.com:443");
        assert_eq!(host, "vpn.example.com");
    }

    #[test]
    fn parse_server_keeps_explicit_port() {
        let (authority, host) = parse_server("https://vpn.example.com:8443").unwrap();
        assert_eq!(authority, "vpn.example.com:8443");
        assert_eq!(host, "vpn.example.com");
    }

    #[test]
    fn parse_server_ipv6_with_port() {
        let (authority, host) = parse_server("https://[2001:db8::1]:443").unwrap();
        assert_eq!(authority, "[2001:db8::1]:443");
        assert_eq!(host, "2001:db8::1");
    }

    #[test]
    fn host_and_port_helpers() {
        assert!(has_explicit_port("vpn.example.com:443"));
        assert!(!has_explicit_port("vpn.example.com"));
        assert_eq!(extract_host("vpn.example.com:443").unwrap(), "vpn.example.com");
    }
}
