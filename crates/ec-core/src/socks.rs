use crate::error::{EcError, EcResult};
use crate::output::{self, RouteKind, Scope};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, TcpListener, TcpStream};
use std::thread;

const RELAY_BUFFER_SIZE: usize = 4096;
const HTTP_PROXY_HEAD_MAX_SIZE: usize = 16 * 1024;
const SOCKS_VERSION_5: u8 = 0x05;
const SOCKS_METHOD_NO_AUTH: u8 = 0x00;
const SOCKS_METHOD_NOT_ACCEPTABLE: u8 = 0xff;
const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_RSV: u8 = 0x00;
const SOCKS_ATYP_IPV4: u8 = 0x01;
const SOCKS_ATYP_DOMAIN: u8 = 0x03;
const SOCKS_ATYP_IPV6: u8 = 0x04;
const SOCKS_REP_GENERAL_FAILURE: u8 = 0x01;
const SOCKS_REP_SUCCEEDED: u8 = 0x00;
const SOCKS_REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const SOCKS_REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

pub fn serve(bind_addr: &str, fallback_proxy: Option<&str>) -> EcResult<()> {
    let normalized = normalize_bind_addr(bind_addr);
    let fallback_proxy = parse_fallback_proxy(fallback_proxy)?;
    let listener = TcpListener::bind(&normalized)
        .map_err(|e| EcError::Runtime(format!("socks bind failed on {bind_addr}: {e}")))?;
    if let Some(proxy) = fallback_proxy.as_ref() {
        output::info(
            Scope::App,
            format_args!("fallback: proxy to {}", output::value(proxy.url.as_str())),
        );
    } else {
        output::info(Scope::App, "fallback: direct");
    }
    output::info(
        Scope::App,
        format_args!("socks listening on {}", output::value(normalized.as_str())),
    );

    let accept_fallback = fallback_proxy.clone();
    thread::spawn(move || {
        loop {
            let (stream, _peer) = match listener.accept() {
                Ok(v) => v,
                Err(err) => {
                    output::warn(Scope::Socks, format_args!("accept failed: {err}"));
                    continue;
                }
            };
            let fallback_proxy = accept_fallback.clone();
            thread::spawn(move || {
                if let Err(err) = handle_client(stream, fallback_proxy.as_ref()) {
                    output::error(Scope::Socks, err.to_string());
                }
            });
        }
    });

    let reason = crate::protocol::wait_tunnel_fatal_reason();
    Err(EcError::Runtime(format!("tunnel terminated: {reason}")))
}

fn normalize_bind_addr(bind_addr: &str) -> String {
    if bind_addr.starts_with(':') {
        format!("0.0.0.0{bind_addr}")
    } else {
        bind_addr.to_string()
    }
}

fn handle_client(mut client: TcpStream, fallback_proxy: Option<&FallbackProxy>) -> EcResult<()> {
    negotiate_method(&mut client)?;
    let target = read_connect_request(&mut client)?;
    let target_display = target.to_string();
    let target_is_ip = is_ip_host(target.host());
    let arrow = output::weak(" -> ");
    let lparen = output::weak("(");
    let rparen = output::weak(")");

    let route = match crate::routing::plan_target(target.host(), target.port()) {
        Ok(crate::routing::RoutePlan::Remote {
            dial,
            rc_id: _rc_id,
            rc_name,
            source: _source,
        }) => {
            let name = if rc_name.trim().is_empty() {
                "unknown".to_string()
            } else {
                rc_name
            };
            let line = if target_is_ip {
                format!(
                    "{target_display}{arrow}{}{arrow}{name}",
                    output::route_label(RouteKind::Remote),
                )
            } else {
                format!(
                    "{target_display}{arrow}{}{arrow}{name}{lparen}{dial}{rparen}",
                    output::route_label(RouteKind::Remote),
                )
            };
            RouteDecision {
                line,
                path: format!("remote -> {name}({dial})"),
                transport: RouteTransport::Tunnel(dial),
            }
        }
        Ok(crate::routing::RoutePlan::Fallback {
            target: planned_target,
            reason,
        }) => {
            let dial = target_addr(&planned_target);
            if let Some(proxy) = fallback_proxy {
                RouteDecision {
                    line: format!(
                        "{target_display}{arrow}{}{arrow}{}",
                        output::route_label(RouteKind::Fallback),
                        output::value(proxy.url.as_str()),
                    ),
                    path: format!("fallback -> {} reason={reason}", proxy.url),
                    transport: RouteTransport::Proxy(proxy.clone(), target.clone()),
                }
            } else {
                RouteDecision {
                    line: format!(
                        "{target_display}{arrow}{}{arrow}{}",
                        output::route_label(RouteKind::Fallback),
                        output::route_label(RouteKind::Direct),
                    ),
                    path: format!("fallback -> direct dial={dial} reason={reason}"),
                    transport: RouteTransport::Direct(dial),
                }
            }
        }
        Err(err) => {
            let legacy = target.to_socket_target();
            RouteDecision {
                line: format!(
                    "{target_display}{arrow}{}{arrow}legacy{lparen}{legacy}{rparen}",
                    output::route_label(RouteKind::Remote),
                ),
                path: format!("remote -> legacy({legacy}) planner-unavailable={err}"),
                transport: RouteTransport::Tunnel(legacy),
            }
        }
    };
    output::info(Scope::Socks, &route.line);

    let route_path = route.path.as_str();
    match route.transport {
        RouteTransport::Tunnel(dial_target) => {
            let conn = crate::netstack::open_tcp_connection(&dial_target)
                .map_err(|e| route_runtime_error(target_display.as_str(), route_path, e))?;
            write_connect_ok_reply(&mut client, target_display.as_str(), route_path)?;
            relay_tunnel(client, conn)
                .map_err(|e| route_runtime_error(target_display.as_str(), route_path, e))
        }
        RouteTransport::Direct(dial_target) => {
            let conn = TcpStream::connect(&dial_target)
                .map_err(|e| route_runtime_error(target_display.as_str(), route_path, e))?;
            relay_direct_with_reply(client, conn, target_display.as_str(), route_path)
        }
        RouteTransport::Proxy(proxy, target) => {
            let conn = connect_via_proxy(&proxy, &target)
                .map_err(|e| route_runtime_error(target_display.as_str(), route_path, e))?;
            relay_direct_with_reply(client, conn, target_display.as_str(), route_path)
        }
    }
}

fn route_runtime_error(
    target_display: &str,
    route_path: &str,
    err: impl std::fmt::Display,
) -> EcError {
    EcError::Runtime(format!("{target_display} -> {route_path} failed: {err}"))
}

fn write_connect_ok_reply(
    client: &mut TcpStream,
    target_display: &str,
    route_path: &str,
) -> EcResult<()> {
    write_reply(client, SOCKS_REP_SUCCEEDED)
        .map_err(|e| route_runtime_error(target_display, route_path, e))
}

fn relay_direct_with_reply(
    mut client: TcpStream,
    conn: TcpStream,
    target_display: &str,
    route_path: &str,
) -> EcResult<()> {
    write_connect_ok_reply(&mut client, target_display, route_path)?;
    relay_direct(client, conn).map_err(|e| route_runtime_error(target_display, route_path, e))
}

fn connect_via_proxy(proxy: &FallbackProxy, target: &ConnectTarget) -> EcResult<TcpStream> {
    match proxy.kind {
        FallbackProxyKind::Socks5 => connect_via_socks5_proxy(&proxy.addr, target),
        FallbackProxyKind::Http => connect_via_http_connect_proxy(&proxy.addr, target),
    }
}

fn negotiate_method(client: &mut TcpStream) -> EcResult<()> {
    let mut head = [0u8; 2];
    client
        .read_exact(&mut head)
        .map_err(|e| EcError::Runtime(format!("socks hello read failed: {e}")))?;
    if head[0] != SOCKS_VERSION_5 {
        return Err(EcError::Runtime("unsupported socks version".to_string()));
    }

    let n_methods = head[1] as usize;
    let mut methods = vec![0u8; n_methods];
    client
        .read_exact(&mut methods)
        .map_err(|e| EcError::Runtime(format!("socks methods read failed: {e}")))?;

    if methods.contains(&SOCKS_METHOD_NO_AUTH) {
        client
            .write_all(&[SOCKS_VERSION_5, SOCKS_METHOD_NO_AUTH])
            .map_err(|e| EcError::Runtime(format!("socks method reply failed: {e}")))?;
        return Ok(());
    }

    client
        .write_all(&[SOCKS_VERSION_5, SOCKS_METHOD_NOT_ACCEPTABLE])
        .map_err(|e| EcError::Runtime(format!("socks method reject reply failed: {e}")))?;
    Err(EcError::Runtime(
        "client does not support no-auth method".to_string(),
    ))
}

fn read_connect_request(client: &mut TcpStream) -> EcResult<ConnectTarget> {
    let mut req = [0u8; 4];
    client
        .read_exact(&mut req)
        .map_err(|e| EcError::Runtime(format!("socks request head read failed: {e}")))?;

    if req[0] != SOCKS_VERSION_5 {
        return Err(EcError::Runtime(
            "invalid socks request version".to_string(),
        ));
    }
    if req[1] != SOCKS_CMD_CONNECT {
        let _ = write_reply(client, SOCKS_REP_CMD_NOT_SUPPORTED);
        return Err(EcError::Runtime(
            "only CONNECT command is supported".to_string(),
        ));
    }
    if req[2] != SOCKS_RSV {
        let _ = write_reply(client, SOCKS_REP_GENERAL_FAILURE);
        return Err(EcError::Runtime("invalid socks reserved byte".to_string()));
    }

    let host = match req[3] {
        SOCKS_ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            client
                .read_exact(&mut ip)
                .map_err(|e| EcError::Runtime(format!("read ipv4 failed: {e}")))?;
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        SOCKS_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            client
                .read_exact(&mut len)
                .map_err(|e| EcError::Runtime(format!("read domain length failed: {e}")))?;
            let mut domain = vec![0u8; len[0] as usize];
            client
                .read_exact(&mut domain)
                .map_err(|e| EcError::Runtime(format!("read domain failed: {e}")))?;
            String::from_utf8(domain)
                .map_err(|e| EcError::Runtime(format!("invalid domain utf8: {e}")))?
        }
        SOCKS_ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            client
                .read_exact(&mut ip)
                .map_err(|e| EcError::Runtime(format!("read ipv6 failed: {e}")))?;
            Ipv6Addr::from(ip).to_string()
        }
        atyp => {
            let _ = write_reply(client, SOCKS_REP_ATYP_NOT_SUPPORTED);
            return Err(EcError::Runtime(format!(
                "unsupported socks atyp: 0x{atyp:02x}"
            )));
        }
    };

    let mut port_buf = [0u8; 2];
    client
        .read_exact(&mut port_buf)
        .map_err(|e| EcError::Runtime(format!("read target port failed: {e}")))?;
    let port = u16::from_be_bytes(port_buf);
    Ok(ConnectTarget { host, port })
}

fn write_reply(client: &mut TcpStream, rep: u8) -> EcResult<()> {
    let reply = [
        SOCKS_VERSION_5,
        rep,
        SOCKS_RSV,
        SOCKS_ATYP_IPV4,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    client
        .write_all(&reply)
        .map_err(|e| EcError::Runtime(format!("socks reply write failed: {e}")))
}

fn relay_tunnel(mut client: TcpStream, conn: crate::netstack::TunnelTcpConnection) -> EcResult<()> {
    let sender = conn.sender();
    let rx = conn.into_receiver();
    let mut c_to_r_src = client
        .try_clone()
        .map_err(|e| EcError::Runtime(format!("clone client stream failed: {e}")))?;

    let t1 = thread::spawn(move || {
        let mut buf = [0u8; RELAY_BUFFER_SIZE];
        loop {
            match c_to_r_src.read(&mut buf) {
                Ok(0) => {
                    let _ = sender.close();
                    break;
                }
                Ok(n) => {
                    if sender.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => {
                    let _ = sender.close();
                    break;
                }
            }
        }
    });
    let t2 = thread::spawn(move || {
        while let Ok(chunk) = rx.recv() {
            if chunk.is_empty() {
                continue;
            }
            if client.write_all(&chunk).is_err() {
                break;
            }
        }
        let _ = client.shutdown(Shutdown::Write);
    });

    let _ = t1.join();
    let _ = t2.join();
    Ok(())
}

fn relay_direct(client: TcpStream, upstream: TcpStream) -> EcResult<()> {
    let client_reader = client
        .try_clone()
        .map_err(|e| EcError::Runtime(format!("clone client stream failed: {e}")))?;
    let upstream_reader = upstream
        .try_clone()
        .map_err(|e| EcError::Runtime(format!("clone upstream stream failed: {e}")))?;

    let t1 = thread::spawn(move || {
        pump_stream(client_reader, upstream);
    });
    let t2 = thread::spawn(move || {
        pump_stream(upstream_reader, client);
    });

    let _ = t1.join();
    let _ = t2.join();
    Ok(())
}

fn pump_stream(mut src: TcpStream, mut dst: TcpStream) {
    let mut buf = [0u8; RELAY_BUFFER_SIZE];
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if dst.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = dst.shutdown(Shutdown::Write);
}

enum RouteTransport {
    Tunnel(String),
    Direct(String),
    Proxy(FallbackProxy, ConnectTarget),
}

struct RouteDecision {
    line: String,
    path: String,
    transport: RouteTransport,
}

#[derive(Clone)]
struct FallbackProxy {
    addr: String,
    url: String,
    kind: FallbackProxyKind,
}

#[derive(Clone, Copy)]
enum FallbackProxyKind {
    Socks5,
    Http,
}

fn target_addr(target: &str) -> String {
    if let Some((host, port)) = target.rsplit_once(':') {
        return format_socket_target(host, port);
    }
    target.to_string()
}

fn format_socket_target(host: &str, port: impl std::fmt::Display) -> String {
    let h = host.trim();
    if h.parse::<Ipv6Addr>().is_ok() {
        format!("[{h}]:{port}")
    } else {
        format!("{h}:{port}")
    }
}

fn parse_fallback_proxy(raw: Option<&str>) -> EcResult<Option<FallbackProxy>> {
    let Some(raw) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let (addr, url, kind) = if let Some(stripped) = raw.strip_prefix("socks5://") {
        (stripped.trim(), raw.to_string(), FallbackProxyKind::Socks5)
    } else if let Some(stripped) = raw.strip_prefix("socks5h://") {
        (stripped.trim(), raw.to_string(), FallbackProxyKind::Socks5)
    } else if let Some(stripped) = raw.strip_prefix("http://") {
        (stripped.trim(), raw.to_string(), FallbackProxyKind::Http)
    } else if raw.contains("://") {
        return Err(EcError::InvalidConfig(
            "fallback is invalid: only socks5://, socks5h:// and http:// are supported",
        ));
    } else {
        (
            raw.trim(),
            format!("socks5h://{}", raw.trim()),
            FallbackProxyKind::Socks5,
        )
    };
    if addr.is_empty() {
        return Err(EcError::InvalidConfig(
            "fallback is invalid: empty proxy address",
        ));
    }
    Ok(Some(FallbackProxy {
        addr: addr.to_string(),
        url,
        kind,
    }))
}

fn is_ip_host(host: &str) -> bool {
    host.trim().parse::<Ipv4Addr>().is_ok() || host.trim().parse::<Ipv6Addr>().is_ok()
}

fn connect_via_socks5_proxy(proxy_addr: &str, target: &ConnectTarget) -> EcResult<TcpStream> {
    let mut stream = TcpStream::connect(proxy_addr).map_err(|e| {
        EcError::Runtime(format!("connect fallback proxy {proxy_addr} failed: {e}"))
    })?;

    stream
        .write_all(&[SOCKS_VERSION_5, 0x01, SOCKS_METHOD_NO_AUTH])
        .map_err(|e| EcError::Runtime(format!("proxy greeting write failed: {e}")))?;

    let mut method_resp = [0u8; 2];
    stream
        .read_exact(&mut method_resp)
        .map_err(|e| EcError::Runtime(format!("proxy greeting read failed: {e}")))?;
    if method_resp != [SOCKS_VERSION_5, SOCKS_METHOD_NO_AUTH] {
        return Err(EcError::Runtime(format!(
            "fallback proxy auth method unsupported: version=0x{:02x} method=0x{:02x}",
            method_resp[0], method_resp[1]
        )));
    }

    let mut req = Vec::with_capacity(300);
    req.push(SOCKS_VERSION_5);
    req.push(SOCKS_CMD_CONNECT);
    req.push(SOCKS_RSV);
    append_socks5_addr(&mut req, target.host())?;
    req.extend_from_slice(&target.port().to_be_bytes());
    stream
        .write_all(&req)
        .map_err(|e| EcError::Runtime(format!("proxy connect request write failed: {e}")))?;

    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .map_err(|e| EcError::Runtime(format!("proxy connect reply read failed: {e}")))?;
    if head[0] != SOCKS_VERSION_5 {
        return Err(EcError::Runtime(format!(
            "invalid fallback proxy reply version: 0x{:02x}",
            head[0]
        )));
    }
    if head[1] != SOCKS_REP_SUCCEEDED {
        return Err(EcError::Runtime(format!(
            "fallback proxy connect rejected with code: 0x{:02x}",
            head[1]
        )));
    }

    consume_socks5_addr_and_port(&mut stream, head[3])?;
    Ok(stream)
}

fn connect_via_http_connect_proxy(proxy_addr: &str, target: &ConnectTarget) -> EcResult<TcpStream> {
    let mut stream = TcpStream::connect(proxy_addr).map_err(|e| {
        EcError::Runtime(format!(
            "connect fallback http proxy {proxy_addr} failed: {e}"
        ))
    })?;
    let authority = target.to_socket_target();
    let request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nConnection: keep-alive\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| EcError::Runtime(format!("http proxy connect request write failed: {e}")))?;
    let reply_head = read_http_proxy_head(&mut stream)?;
    ensure_http_connect_success(reply_head.as_str())?;
    Ok(stream)
}

fn read_http_proxy_head(stream: &mut TcpStream) -> EcResult<String> {
    let mut buf = Vec::with_capacity(256);
    loop {
        // Read one byte at a time deliberately: over-reading here could consume
        // tunneled bytes that should be forwarded to the client after CONNECT.
        let mut one = [0u8; 1];
        let n = stream
            .read(&mut one)
            .map_err(|e| EcError::Runtime(format!("http proxy connect reply read failed: {e}")))?;
        if n == 0 {
            return Err(EcError::Runtime(
                "http proxy connect reply is empty".to_string(),
            ));
        }
        buf.push(one[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > HTTP_PROXY_HEAD_MAX_SIZE {
            return Err(EcError::Runtime(
                "http proxy connect reply header is too large".to_string(),
            ));
        }
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

fn ensure_http_connect_success(reply_head: &str) -> EcResult<()> {
    let status_line = reply_head.lines().next().unwrap_or_default().trim();
    if !status_line.starts_with("HTTP/") {
        return Err(EcError::Runtime(format!(
            "invalid http proxy connect reply: {status_line}"
        )));
    }
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse::<u16>().ok())
        .ok_or_else(|| {
            EcError::Runtime(format!(
                "invalid http proxy connect status line: {status_line}"
            ))
        })?;
    if code != 200 {
        return Err(EcError::Runtime(format!(
            "http proxy connect rejected: {status_line}"
        )));
    }
    Ok(())
}

fn append_socks5_addr(buf: &mut Vec<u8>, host: &str) -> EcResult<()> {
    let host = host.trim();
    if let Ok(ipv4) = host.parse::<std::net::Ipv4Addr>() {
        buf.push(SOCKS_ATYP_IPV4);
        buf.extend_from_slice(&ipv4.octets());
        return Ok(());
    }
    if let Ok(ipv6) = host.parse::<Ipv6Addr>() {
        buf.push(SOCKS_ATYP_IPV6);
        buf.extend_from_slice(&ipv6.octets());
        return Ok(());
    }
    if host.is_empty() || host.len() > 255 {
        return Err(EcError::Runtime(
            "fallback proxy target domain is empty or too long".to_string(),
        ));
    }
    buf.push(SOCKS_ATYP_DOMAIN);
    buf.push(host.len() as u8);
    buf.extend_from_slice(host.as_bytes());
    Ok(())
}

fn consume_socks5_addr_and_port(stream: &mut TcpStream, atyp: u8) -> EcResult<()> {
    match atyp {
        0x01 => {
            let mut buf = [0u8; 4];
            stream
                .read_exact(&mut buf)
                .map_err(|e| EcError::Runtime(format!("read proxy bind ipv4 failed: {e}")))?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).map_err(|e| {
                EcError::Runtime(format!("read proxy bind domain length failed: {e}"))
            })?;
            let mut buf = vec![0u8; len[0] as usize];
            stream
                .read_exact(&mut buf)
                .map_err(|e| EcError::Runtime(format!("read proxy bind domain failed: {e}")))?;
        }
        0x04 => {
            let mut buf = [0u8; 16];
            stream
                .read_exact(&mut buf)
                .map_err(|e| EcError::Runtime(format!("read proxy bind ipv6 failed: {e}")))?;
        }
        _ => {
            return Err(EcError::Runtime(format!(
                "unsupported fallback proxy bind atyp: 0x{atyp:02x}"
            )));
        }
    }
    let mut port = [0u8; 2];
    stream
        .read_exact(&mut port)
        .map_err(|e| EcError::Runtime(format!("read proxy bind port failed: {e}")))?;
    Ok(())
}

#[derive(Clone)]
struct ConnectTarget {
    host: String,
    port: u16,
}

impl ConnectTarget {
    fn host(&self) -> &str {
        &self.host
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn to_socket_target(&self) -> String {
        format_socket_target(&self.host, self.port)
    }
}

impl std::fmt::Display for ConnectTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConnectTarget, ensure_http_connect_success, normalize_bind_addr, parse_fallback_proxy,
    };

    #[test]
    fn normalize_bind_addr_expands_port_only() {
        assert_eq!(normalize_bind_addr(":1080"), "0.0.0.0:1080");
    }

    #[test]
    fn normalize_bind_addr_keeps_explicit_host() {
        assert_eq!(normalize_bind_addr("127.0.0.1:1080"), "127.0.0.1:1080");
    }

    #[test]
    fn connect_target_formats_socket_target() {
        let target = ConnectTarget {
            host: "10.0.0.1".to_string(),
            port: 80,
        };
        assert_eq!(target.to_socket_target(), "10.0.0.1:80");
        assert_eq!(target.to_string(), "10.0.0.1:80");
    }

    #[test]
    fn connect_target_formats_ipv6_socket_target() {
        let target = ConnectTarget {
            host: "2001:db8::1".to_string(),
            port: 443,
        };
        assert_eq!(target.to_socket_target(), "[2001:db8::1]:443");
        assert_eq!(target.to_string(), "2001:db8::1:443");
    }

    #[test]
    fn parse_fallback_proxy_accepts_socks5_scheme() {
        let parsed = parse_fallback_proxy(Some("socks5://127.0.0.1:7890")).unwrap();
        assert_eq!(parsed.unwrap().addr, "127.0.0.1:7890");
    }

    #[test]
    fn parse_fallback_proxy_accepts_plain_host_port() {
        let parsed = parse_fallback_proxy(Some("127.0.0.1:7890")).unwrap();
        let proxy = parsed.unwrap();
        assert_eq!(proxy.addr, "127.0.0.1:7890");
        assert_eq!(proxy.url, "socks5h://127.0.0.1:7890");
    }

    #[test]
    fn parse_fallback_proxy_accepts_http_scheme() {
        let parsed = parse_fallback_proxy(Some("http://127.0.0.1:8080")).unwrap();
        let proxy = parsed.unwrap();
        assert_eq!(proxy.addr, "127.0.0.1:8080");
        assert_eq!(proxy.url, "http://127.0.0.1:8080");
    }

    #[test]
    fn parse_fallback_proxy_rejects_unsupported_scheme() {
        let err = match parse_fallback_proxy(Some("https://127.0.0.1:8443")) {
            Ok(_) => panic!("expected unsupported fallback scheme to fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("only socks5://, socks5h:// and http:// are supported")
        );
    }

    #[test]
    fn http_connect_success_accepts_200() {
        ensure_http_connect_success("HTTP/1.1 200 Connection Established\r\n\r\n").unwrap();
    }

    #[test]
    fn http_connect_success_rejects_non_200() {
        let err = ensure_http_connect_success("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
            .unwrap_err();
        assert!(err.to_string().contains("http proxy connect rejected"));
    }

    #[test]
    fn http_connect_success_rejects_non_http_response() {
        let err = ensure_http_connect_success("HELLO\r\n\r\n").unwrap_err();
        assert!(err.to_string().contains("invalid http proxy connect reply"));
    }
}
