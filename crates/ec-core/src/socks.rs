use crate::error::{EcError, EcResult};
use crate::output::{self, Scope};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, TcpListener, TcpStream};
use std::thread;

const RELAY_BUFFER_SIZE: usize = 4096;

pub fn serve(bind_addr: &str, fallback_proxy: Option<&str>) -> EcResult<()> {
    let normalized = normalize_bind_addr(bind_addr);
    let fallback_proxy = parse_fallback_proxy(fallback_proxy)?;
    let listener = TcpListener::bind(&normalized)
        .map_err(|e| EcError::Runtime(format!("socks bind failed on {bind_addr}: {e}")))?;
    if let Some(proxy) = fallback_proxy.as_ref() {
        output::info(Scope::App, format!("fallback: proxy to {}", proxy.url));
    } else {
        output::info(Scope::App, "fallback: direct");
    }
    output::info(Scope::App, format!("socks listening on {normalized}"));

    loop {
        let (stream, _peer) = match listener.accept() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let fallback_proxy = fallback_proxy.clone();
        thread::spawn(move || {
            if let Err(err) = handle_client(stream, fallback_proxy.as_ref()) {
                output::error(Scope::Socks, err.to_string());
            }
        });
    }
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
                format!("{target_display} -> remote -> {name}")
            } else {
                format!("{target_display} -> remote -> {name}({dial})")
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
                    line: format!("{target_display} -> fallback -> {}", proxy.url),
                    path: format!("fallback -> {} reason={reason}", proxy.url),
                    transport: RouteTransport::Proxy(proxy.clone(), target.clone()),
                }
            } else {
                RouteDecision {
                    line: format!("{target_display} -> fallback -> direct"),
                    path: format!("fallback -> direct dial={dial} reason={reason}"),
                    transport: RouteTransport::Direct(dial),
                }
            }
        }
        Err(err) => {
            let legacy = target.to_socket_target();
            RouteDecision {
                line: format!("{target_display} -> remote -> legacy({legacy})"),
                path: format!("remote -> legacy({legacy}) planner-unavailable={err}"),
                transport: RouteTransport::Tunnel(legacy),
            }
        }
    };
    output::info(Scope::Socks, &route.line);

    match route.transport {
        RouteTransport::Tunnel(dial_target) => {
            let conn = crate::netstack::open_tcp_connection(&dial_target).map_err(|e| {
                EcError::Runtime(format!("{target_display} -> {} failed: {e}", route.path))
            })?;
            write_reply(&mut client, 0x00).map_err(|e| {
                EcError::Runtime(format!("{target_display} -> {} failed: {e}", route.path))
            })?;
            relay_tunnel(client, conn).map_err(|e| {
                EcError::Runtime(format!("{target_display} -> {} failed: {e}", route.path))
            })
        }
        RouteTransport::Direct(dial_target) => {
            let conn = TcpStream::connect(&dial_target).map_err(|e| {
                EcError::Runtime(format!("{target_display} -> {} failed: {e}", route.path))
            })?;
            write_reply(&mut client, 0x00).map_err(|e| {
                EcError::Runtime(format!("{target_display} -> {} failed: {e}", route.path))
            })?;
            relay_direct(client, conn).map_err(|e| {
                EcError::Runtime(format!("{target_display} -> {} failed: {e}", route.path))
            })
        }
        RouteTransport::Proxy(proxy, target) => {
            let conn = connect_via_socks5_proxy(&proxy.addr, &target).map_err(|e| {
                EcError::Runtime(format!("{target_display} -> {} failed: {e}", route.path))
            })?;
            write_reply(&mut client, 0x00).map_err(|e| {
                EcError::Runtime(format!("{target_display} -> {} failed: {e}", route.path))
            })?;
            relay_direct(client, conn).map_err(|e| {
                EcError::Runtime(format!("{target_display} -> {} failed: {e}", route.path))
            })
        }
    }
}

fn negotiate_method(client: &mut TcpStream) -> EcResult<()> {
    let mut head = [0u8; 2];
    client
        .read_exact(&mut head)
        .map_err(|e| EcError::Runtime(format!("socks hello read failed: {e}")))?;
    if head[0] != 0x05 {
        return Err(EcError::Runtime("unsupported socks version".to_string()));
    }

    let n_methods = head[1] as usize;
    let mut methods = vec![0u8; n_methods];
    client
        .read_exact(&mut methods)
        .map_err(|e| EcError::Runtime(format!("socks methods read failed: {e}")))?;

    if methods.contains(&0x00) {
        client
            .write_all(&[0x05, 0x00])
            .map_err(|e| EcError::Runtime(format!("socks method reply failed: {e}")))?;
        return Ok(());
    }

    client
        .write_all(&[0x05, 0xff])
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

    if req[0] != 0x05 {
        return Err(EcError::Runtime(
            "invalid socks request version".to_string(),
        ));
    }
    if req[1] != 0x01 {
        let _ = write_reply(client, 0x07);
        return Err(EcError::Runtime(
            "only CONNECT command is supported".to_string(),
        ));
    }
    if req[2] != 0x00 {
        let _ = write_reply(client, 0x01);
        return Err(EcError::Runtime("invalid socks reserved byte".to_string()));
    }

    let host = match req[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            client
                .read_exact(&mut ip)
                .map_err(|e| EcError::Runtime(format!("read ipv4 failed: {e}")))?;
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        0x03 => {
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
        0x04 => {
            let mut ip = [0u8; 16];
            client
                .read_exact(&mut ip)
                .map_err(|e| EcError::Runtime(format!("read ipv6 failed: {e}")))?;
            Ipv6Addr::from(ip).to_string()
        }
        atyp => {
            let _ = write_reply(client, 0x08);
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
    let reply = [0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
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
    let (addr, url) = if let Some(stripped) = raw.strip_prefix("socks5://") {
        (stripped.trim(), raw.to_string())
    } else if let Some(stripped) = raw.strip_prefix("socks5h://") {
        (stripped.trim(), raw.to_string())
    } else {
        (raw.trim(), format!("socks5://{}", raw.trim()))
    };
    if addr.is_empty() {
        return Err(EcError::InvalidConfig(
            "fallback-proxy is invalid: empty proxy address",
        ));
    }
    Ok(Some(FallbackProxy {
        addr: addr.to_string(),
        url,
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
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(|e| EcError::Runtime(format!("proxy greeting write failed: {e}")))?;

    let mut method_resp = [0u8; 2];
    stream
        .read_exact(&mut method_resp)
        .map_err(|e| EcError::Runtime(format!("proxy greeting read failed: {e}")))?;
    if method_resp != [0x05, 0x00] {
        return Err(EcError::Runtime(format!(
            "fallback proxy auth method unsupported: version=0x{:02x} method=0x{:02x}",
            method_resp[0], method_resp[1]
        )));
    }

    let mut req = Vec::with_capacity(300);
    req.push(0x05);
    req.push(0x01);
    req.push(0x00);
    append_socks5_addr(&mut req, target.host())?;
    req.extend_from_slice(&target.port().to_be_bytes());
    stream
        .write_all(&req)
        .map_err(|e| EcError::Runtime(format!("proxy connect request write failed: {e}")))?;

    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .map_err(|e| EcError::Runtime(format!("proxy connect reply read failed: {e}")))?;
    if head[0] != 0x05 {
        return Err(EcError::Runtime(format!(
            "invalid fallback proxy reply version: 0x{:02x}",
            head[0]
        )));
    }
    if head[1] != 0x00 {
        return Err(EcError::Runtime(format!(
            "fallback proxy connect rejected with code: 0x{:02x}",
            head[1]
        )));
    }

    consume_socks5_addr_and_port(&mut stream, head[3])?;
    Ok(stream)
}

fn append_socks5_addr(buf: &mut Vec<u8>, host: &str) -> EcResult<()> {
    let host = host.trim();
    if let Ok(ipv4) = host.parse::<std::net::Ipv4Addr>() {
        buf.push(0x01);
        buf.extend_from_slice(&ipv4.octets());
        return Ok(());
    }
    if let Ok(ipv6) = host.parse::<Ipv6Addr>() {
        buf.push(0x04);
        buf.extend_from_slice(&ipv6.octets());
        return Ok(());
    }
    if host.is_empty() || host.len() > 255 {
        return Err(EcError::Runtime(
            "fallback proxy target domain is empty or too long".to_string(),
        ));
    }
    buf.push(0x03);
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
    use super::{ConnectTarget, normalize_bind_addr, parse_fallback_proxy};

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
        assert_eq!(proxy.url, "socks5://127.0.0.1:7890");
    }
}
