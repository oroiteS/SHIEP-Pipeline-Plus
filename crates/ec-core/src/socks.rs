use crate::error::{EcError, EcResult};
use crate::output::{self, RouteKind, Scope};
use crate::socks_proxy::{FallbackProxy, connect_via_proxy, parse_fallback_proxy};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, TcpListener, TcpStream};
use std::thread;

const RELAY_BUFFER_SIZE: usize = 4096;
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
    log_socks_startup(normalized.as_str(), fallback_proxy.as_ref());
    spawn_accept_loop(listener, fallback_proxy.clone());

    let reason = crate::protocol::wait_tunnel_fatal_reason();
    Err(EcError::Runtime(format!(
        "tunnel terminated: {}",
        crate::error::concise_message(reason)
    )))
}

fn normalize_bind_addr(bind_addr: &str) -> String {
    if bind_addr.starts_with(':') {
        format!("0.0.0.0{bind_addr}")
    } else {
        bind_addr.to_string()
    }
}

fn log_socks_startup(bind_addr: &str, fallback_proxy: Option<&FallbackProxy>) {
    if let Some(proxy) = fallback_proxy {
        output::info(
            Scope::App,
            format_args!("fallback: proxy to {}", output::value(proxy.url.as_str())),
        );
    } else {
        output::info(Scope::App, "fallback: direct");
    }
    output::info(
        Scope::App,
        format_args!("socks listening on {}", output::value(bind_addr)),
    );
}

fn spawn_accept_loop(listener: TcpListener, fallback_proxy: Option<FallbackProxy>) {
    thread::spawn(move || {
        loop {
            let (stream, _peer) = match listener.accept() {
                Ok(v) => v,
                Err(err) => {
                    output::warn(Scope::Rx, format_args!("accept failed: {err}"));
                    continue;
                }
            };
            let fallback_proxy = fallback_proxy.clone();
            thread::spawn(move || {
                if let Err(err) = handle_client(stream, fallback_proxy.as_ref()) {
                    output::error(Scope::Upstream, crate::error::concise_error(err));
                }
            });
        }
    });
}

fn handle_client(mut client: TcpStream, fallback_proxy: Option<&FallbackProxy>) -> EcResult<()> {
    negotiate_method(&mut client)?;
    let target = read_connect_request(&mut client)?;
    let target_display = target.to_string();
    let route = decide_route(&target, fallback_proxy);
    output::info(Scope::Rx, &route.line);

    execute_route(client, target_display.as_str(), route)
}

fn decide_route(target: &ConnectTarget, fallback_proxy: Option<&FallbackProxy>) -> RouteDecision {
    let target_display = target.to_string();
    let target_is_ip = is_ip_host(target.host());
    match crate::routing::plan_target(target.host(), target.port()) {
        Ok(crate::routing::RoutePlan::Remote {
            dial,
            rc_id,
            rc_name,
            source,
        }) => {
            let resolved_ip = dial
                .rsplit_once(':')
                .map(|(ip, _)| ip)
                .unwrap_or(dial.as_str());
            let arrow = output::weak(" -> ");
            match source {
                crate::routing::RouteSource::DnsServerQuery(server)
                | crate::routing::RouteSource::CnameDnsServerQuery(server) => {
                    output::info(
                        Scope::Upstream,
                        format_args!(
                            "dnsserver resolved {}{}{} via {} for rc_id={}",
                            output::value(target.host()),
                            arrow,
                            output::value(resolved_ip),
                            output::value(server),
                            output::value(rc_id)
                        ),
                    );
                }
                crate::routing::RouteSource::DnsServerCache
                | crate::routing::RouteSource::CnameDnsServerCache => {
                    output::info(
                        Scope::Upstream,
                        format_args!(
                            "dns cache hit {}{}{} for rc_id={}",
                            output::value(target.host()),
                            arrow,
                            output::value(resolved_ip),
                            output::value(rc_id)
                        ),
                    );
                }
                _ => {}
            }
            route_decision_remote(target_display.as_str(), target_is_ip, dial, rc_name, source)
        }
        Ok(crate::routing::RoutePlan::Fallback {
            target: planned_target,
            reason,
            reserved_proto1,
        }) => {
            if reserved_proto1 {
                output::warn(
                    Scope::Upstream,
                    format_args!(
                        "{} hit reserved proto=1 route (separated from normal routing); forcing {}",
                        output::value(target_display.as_str()),
                        output::route_label(RouteKind::Fallback),
                    ),
                );
            }
            route_decision_fallback(
                target.clone(),
                target_display.as_str(),
                target_addr(&planned_target),
                reason,
                fallback_proxy,
            )
        }
        Err(err) => route_decision_legacy(target, target_display.as_str(), err),
    }
}

fn route_decision_remote(
    target_display: &str,
    target_is_ip: bool,
    dial: String,
    rc_name: String,
    source: crate::routing::RouteSource,
) -> RouteDecision {
    let arrow = output::weak(" -> ");
    let lparen = output::weak("(");
    let rparen = output::weak(")");
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
        path: format!("remote -> {name}({dial}); source={}", source.describe()),
        transport: RouteTransport::Tunnel(dial),
    }
}

fn route_decision_fallback(
    target: ConnectTarget,
    target_display: &str,
    dial: String,
    reason: String,
    fallback_proxy: Option<&FallbackProxy>,
) -> RouteDecision {
    let arrow = output::weak(" -> ");
    if let Some(proxy) = fallback_proxy {
        return RouteDecision {
            line: format!(
                "{target_display}{arrow}{}{arrow}{}",
                output::route_label(RouteKind::Fallback),
                output::value(proxy.url.as_str()),
            ),
            path: format!("fallback -> {}; reason: {reason}", proxy.url),
            transport: RouteTransport::Proxy(proxy.clone(), target),
        };
    }

    RouteDecision {
        line: format!(
            "{target_display}{arrow}{}{arrow}{}",
            output::route_label(RouteKind::Fallback),
            output::route_label(RouteKind::Direct),
        ),
        path: format!("fallback -> direct dial={dial}; reason: {reason}"),
        transport: RouteTransport::Direct(dial),
    }
}

fn route_decision_legacy(
    target: &ConnectTarget,
    target_display: &str,
    err: EcError,
) -> RouteDecision {
    let arrow = output::weak(" -> ");
    let lparen = output::weak("(");
    let rparen = output::weak(")");
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

fn execute_route(client: TcpStream, target_display: &str, route: RouteDecision) -> EcResult<()> {
    let RouteDecision {
        line: _,
        path,
        transport,
    } = route;
    let route_path = path.as_str();

    match transport {
        RouteTransport::Tunnel(dial_target) => {
            let conn = crate::netstack::open_tcp_connection(&dial_target)
                .map_err(|e| route_runtime_error(target_display, route_path, e))?;
            let mut client = client;
            write_connect_ok_reply(&mut client, target_display, route_path)?;
            relay_tunnel(client, conn)
                .map_err(|e| route_runtime_error(target_display, route_path, e))
        }
        RouteTransport::Direct(dial_target) => {
            let conn = TcpStream::connect(&dial_target)
                .map_err(|e| route_runtime_error(target_display, route_path, e))?;
            relay_direct_with_reply(client, conn, target_display, route_path)
        }
        RouteTransport::Proxy(proxy, target) => {
            let conn = connect_via_proxy(&proxy, target.host(), target.port())
                .map_err(|e| route_runtime_error(target_display, route_path, e))?;
            relay_direct_with_reply(client, conn, target_display, route_path)
        }
    }
}

fn route_runtime_error(
    target_display: &str,
    route_path: &str,
    err: impl std::fmt::Display,
) -> EcError {
    let cause = crate::error::concise_error(err);
    EcError::Runtime(format!("{target_display} -> {route_path}; failed: {cause}"))
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

fn is_ip_host(host: &str) -> bool {
    host.trim().parse::<Ipv4Addr>().is_ok() || host.trim().parse::<Ipv6Addr>().is_ok()
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
    use super::{ConnectTarget, normalize_bind_addr};

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
}
