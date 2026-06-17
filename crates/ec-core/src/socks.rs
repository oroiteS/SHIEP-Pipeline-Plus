use crate::error::{EcError, EcResult};
use crate::output::{self, RouteKind, Scope};
use crate::socks_proxy::{FallbackProxy, connect_via_proxy, parse_fallback_proxy};
use crate::socks_wire::{
    ConnectTarget, SOCKS_REP_CMD_NOT_SUPPORTED, SOCKS_REP_GENERAL_FAILURE, SOCKS_REP_SUCCEEDED,
    SocksCommand, encode_socks_udp_packet, format_socket_target, negotiate_method,
    parse_socks_udp_packet, read_socks_request, write_bound_reply, write_reply,
};
use std::io::ErrorKind;
use std::io::{Read, Write};
use std::net::{
    Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, ToSocketAddrs,
    UdpSocket,
};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

const RELAY_BUFFER_SIZE: usize = 4096;
const UDP_RELAY_BUFFER_SIZE: usize = 64 * 1024;

pub fn serve(bind_addr: &str, fallback_proxy: Option<&str>) -> EcResult<()> {
    let normalized = normalize_bind_addr(bind_addr);
    let fallback_proxy = parse_fallback_proxy(fallback_proxy)?;
    let listener = TcpListener::bind(&normalized)
        .map_err(|e| EcError::Runtime(format!("socks bind failed on {bind_addr}: {e}")))?;
    log_socks_startup(normalized.as_str(), fallback_proxy.as_ref());
    spawn_accept_loop(listener, fallback_proxy.clone());

    let reason = crate::protocol::wait_tunnel_fatal_reason();
    Err(EcError::Runtime(format!(
        "tunnel closed: {}",
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
        format_args!("listening on {}", output::value(bind_addr)),
    );
}

fn spawn_accept_loop(listener: TcpListener, fallback_proxy: Option<FallbackProxy>) {
    thread::spawn(move || {
        loop {
            let (stream, _peer) = match listener.accept() {
                Ok(v) => v,
                Err(err) => {
                    output::warn(Scope::Req, format_args!("accept failed: {err}"));
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
    let request = read_socks_request(&mut client)?;
    match request.command {
        SocksCommand::Connect => handle_connect(client, request.target, fallback_proxy),
        SocksCommand::UdpAssociate => handle_udp_associate(client, fallback_proxy),
        SocksCommand::Other(_) => {
            let _ = write_reply(&mut client, SOCKS_REP_CMD_NOT_SUPPORTED);
            Err(EcError::Runtime(format!(
                "unsupported socks command: {}",
                request.command
            )))
        }
    }
}

fn handle_connect(
    client: TcpStream,
    target: ConnectTarget,
    fallback_proxy: Option<&FallbackProxy>,
) -> EcResult<()> {
    let target_display = target.to_string();
    let route = decide_route(&target, fallback_proxy);
    output::info(Scope::Req, &route.line);
    execute_route(client, target_display.as_str(), route)
}

fn handle_udp_associate(
    mut client: TcpStream,
    fallback_proxy: Option<&FallbackProxy>,
) -> EcResult<()> {
    let relay_bind = udp_relay_bind_addr(&client)?;
    let udp_socket = Arc::new(
        UdpSocket::bind(relay_bind)
            .map_err(|e| EcError::Runtime(format!("udp relay bind failed: {e}")))?,
    );
    let relay_addr = match udp_socket
        .local_addr()
        .map_err(|e| EcError::Runtime(format!("udp relay local addr failed: {e}")))?
    {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(_) => {
            let _ = write_reply(&mut client, SOCKS_REP_GENERAL_FAILURE);
            return Err(EcError::Runtime(
                "udp relay only supports ipv4 bind address".to_string(),
            ));
        }
    };

    let mut control = client
        .try_clone()
        .map_err(|e| EcError::Runtime(format!("clone socks control stream failed: {e}")))?;
    let udp_assoc = crate::netstack::open_udp_association()?;
    let tunnel_sender = udp_assoc.sender();
    let tunnel_rx = udp_assoc.into_receiver();
    if let Err(err) = write_bound_reply(&mut client, SOCKS_REP_SUCCEEDED, relay_addr) {
        let _ = tunnel_sender.close();
        return Err(err);
    }
    output::info(
        Scope::Req,
        format_args!("UDP ASSOCIATE -> {}", output::value(relay_addr)),
    );

    let client_peer = Arc::new(Mutex::new(None::<SocketAddr>));
    let tunnel_socket = Arc::clone(&udp_socket);
    let tunnel_peer = Arc::clone(&client_peer);
    let tunnel_to_client = thread::spawn(move || {
        forward_udp_from_tunnel(tunnel_rx, tunnel_socket, tunnel_peer);
    });

    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let control_addr = relay_addr;
    let control_watcher = thread::spawn(move || {
        let mut buf = [0u8; 1];
        loop {
            match control.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => {}
                Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    continue;
                }
                Err(_) => break,
            }
        }
        let _ = stop_tx.send(());
        wake_udp_relay(control_addr);
    });

    let relay_result = run_udp_relay(
        udp_socket,
        &tunnel_sender,
        fallback_proxy,
        client_peer,
        stop_rx,
    );
    let _ = tunnel_sender.close();
    let _ = client.shutdown(Shutdown::Both);
    let _ = tunnel_to_client.join();
    let _ = control_watcher.join();
    relay_result
}

fn decide_route(target: &ConnectTarget, fallback_proxy: Option<&FallbackProxy>) -> RouteDecision {
    let target_display = target.to_string();
    let target_is_ip = is_ip_host(target.host());
    match crate::routing::plan_target_with_proto(
        target.host(),
        target.port(),
        crate::routing::FlowProto::Tcp,
    ) {
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
            log_resolved_route_source(target.host(), resolved_ip, rc_id, source);
            route_decision_remote(target_display.as_str(), target_is_ip, dial, rc_name, source)
        }
        Ok(crate::routing::RoutePlan::Fallback {
            target: planned_target,
            reason,
        }) => route_decision_fallback(
            target.clone(),
            target_display.as_str(),
            target_addr(&planned_target),
            reason,
            fallback_proxy,
        ),
        Err(err) => route_decision_legacy(target, target_display.as_str(), err),
    }
}

fn decide_udp_route(
    target: &ConnectTarget,
    fallback_proxy: Option<&FallbackProxy>,
) -> UdpRouteDecision {
    let target_display = target.to_string();
    let target_is_ip = is_ip_host(target.host());
    match crate::routing::plan_target_with_proto(
        target.host(),
        target.port(),
        crate::routing::FlowProto::Udp,
    ) {
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
            log_resolved_route_source(target.host(), resolved_ip, rc_id, source);
            let decision =
                route_decision_remote(target_display.as_str(), target_is_ip, dial, rc_name, source);
            let transport = match resolve_dial_v4_from_str(decision_tunnel_target(&decision)) {
                Ok(target) => UdpRouteTransport::Tunnel(target),
                Err(err) => UdpRouteTransport::Unsupported(format!(
                    "udp remote target is not ipv4: {}",
                    crate::error::concise_error(err)
                )),
            };
            UdpRouteDecision {
                line: decision.line,
                path: decision.path,
                transport,
            }
        }
        Ok(crate::routing::RoutePlan::Fallback {
            target: planned_target,
            reason,
        }) => {
            let decision = route_decision_fallback(
                target.clone(),
                target_display.as_str(),
                target_addr(&planned_target),
                reason,
                fallback_proxy,
            );
            UdpRouteDecision {
                line: decision.line,
                path: decision.path,
                transport: UdpRouteTransport::Unsupported(
                    "udp fallback transport is not supported yet".to_string(),
                ),
            }
        }
        Err(err) => UdpRouteDecision {
            line: format!(
                "{target_display}{}{}{}legacy",
                output::weak(" -> "),
                output::route_label(RouteKind::Remote),
                output::weak(" -> "),
            ),
            path: format!("remote -> legacy; reason: planner unavailable: {err}"),
            transport: UdpRouteTransport::Unsupported(
                "udp legacy route is not supported".to_string(),
            ),
        },
    }
}

fn log_resolved_route_source(
    host: &str,
    resolved_ip: &str,
    rc_id: i32,
    source: crate::routing::RouteSource,
) {
    let arrow = output::weak(" -> ");
    match source {
        crate::routing::RouteSource::DnsDataIpRule => {
            output::info(
                Scope::Upstream,
                format_args!(
                    "dns.data resolved {}{}{} for rc_id={}",
                    output::value(host),
                    arrow,
                    output::value(resolved_ip),
                    output::value(rc_id)
                ),
            );
        }
        crate::routing::RouteSource::DnsServerQuery(server)
        | crate::routing::RouteSource::CnameDnsServerQuery(server)
        | crate::routing::RouteSource::DnsServerIpRuleQuery(server) => {
            output::info(
                Scope::Upstream,
                format_args!(
                    "dnsserver resolved {}{}{} via {} for rc_id={}",
                    output::value(host),
                    arrow,
                    output::value(resolved_ip),
                    output::value(server),
                    output::value(rc_id)
                ),
            );
        }
        crate::routing::RouteSource::DnsServerCache
        | crate::routing::RouteSource::CnameDnsServerCache
        | crate::routing::RouteSource::DnsServerIpRuleCache => {
            output::info(
                Scope::Upstream,
                format_args!(
                    "dns cache hit {}{}{} for rc_id={}",
                    output::value(host),
                    arrow,
                    output::value(resolved_ip),
                    output::value(rc_id)
                ),
            );
        }
        _ => {}
    }
}

fn decision_tunnel_target(decision: &RouteDecision) -> &str {
    match &decision.transport {
        RouteTransport::Tunnel(dial) => dial,
        RouteTransport::Direct(dial) => dial,
        RouteTransport::Proxy(_, target) => target.host(),
    }
}

fn udp_relay_bind_addr(client: &TcpStream) -> EcResult<SocketAddrV4> {
    match client
        .local_addr()
        .map_err(|e| EcError::Runtime(format!("socks control local addr failed: {e}")))?
    {
        SocketAddr::V4(addr) => Ok(SocketAddrV4::new(*addr.ip(), 0)),
        SocketAddr::V6(_) => Err(EcError::Runtime(
            "udp associate over ipv6 control connection is not supported".to_string(),
        )),
    }
}

fn run_udp_relay(
    socket: Arc<UdpSocket>,
    tunnel_sender: &crate::netstack::TunnelUdpSender,
    fallback_proxy: Option<&FallbackProxy>,
    client_peer: Arc<Mutex<Option<SocketAddr>>>,
    stop_rx: mpsc::Receiver<()>,
) -> EcResult<()> {
    let mut buf = vec![0u8; UDP_RELAY_BUFFER_SIZE];
    loop {
        let (n, peer) = socket
            .recv_from(&mut buf)
            .map_err(|e| EcError::Runtime(format!("udp relay recv failed: {e}")))?;
        if stop_rx.try_recv().is_ok() {
            break;
        }
        if n == 0 {
            continue;
        }
        if !remember_udp_client(&client_peer, peer) {
            output::warn(
                Scope::Req,
                format_args!(
                    "drop udp packet from unexpected peer {}",
                    output::value(peer)
                ),
            );
            continue;
        }

        let packet = match parse_socks_udp_packet(&buf[..n]) {
            Ok(packet) => packet,
            Err(err) => {
                output::warn(
                    Scope::Req,
                    format_args!(
                        "drop invalid udp packet: {}",
                        crate::error::concise_error(err)
                    ),
                );
                continue;
            }
        };
        let route = decide_udp_route(&packet.target, fallback_proxy);
        output::info(Scope::Req, &route.line);
        match route.transport {
            UdpRouteTransport::Tunnel(target) => {
                if let Err(err) = tunnel_sender.send(target, packet.payload) {
                    output::error(
                        Scope::Upstream,
                        format_args!(
                            "{}; error: {}",
                            route.path,
                            crate::error::concise_error(err)
                        ),
                    );
                }
            }
            UdpRouteTransport::Unsupported(reason) => {
                output::error(
                    Scope::Upstream,
                    format_args!("{}; error: {reason}", route.path),
                );
            }
        }
    }
    Ok(())
}

fn forward_udp_from_tunnel(
    tunnel_rx: mpsc::Receiver<crate::netstack::UdpDatagram>,
    socket: Arc<UdpSocket>,
    client_peer: Arc<Mutex<Option<SocketAddr>>>,
) {
    while let Ok(datagram) = tunnel_rx.recv() {
        let Some(peer) = current_udp_client(&client_peer) else {
            continue;
        };
        let packet = encode_socks_udp_packet(datagram.source, &datagram.data);
        let _ = socket.send_to(&packet, peer);
    }
}

fn remember_udp_client(client_peer: &Mutex<Option<SocketAddr>>, peer: SocketAddr) -> bool {
    let Ok(mut guard) = client_peer.lock() else {
        return false;
    };
    match *guard {
        Some(existing) => existing == peer,
        None => {
            *guard = Some(peer);
            true
        }
    }
}

fn current_udp_client(client_peer: &Mutex<Option<SocketAddr>>) -> Option<SocketAddr> {
    client_peer.lock().ok().and_then(|guard| *guard)
}

fn wake_udp_relay(relay_addr: SocketAddrV4) {
    if let Ok(waker) = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)) {
        let _ = waker.send_to(&[], relay_addr);
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
        path: format!("fallback -> direct; dial: {dial}; reason: {reason}"),
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
        path: format!("remote -> legacy({legacy}); reason: planner unavailable: {err}"),
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
    EcError::Runtime(format!("{target_display} -> {route_path}; error: {cause}"))
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

fn resolve_dial_v4_from_str(target: &str) -> EcResult<SocketAddrV4> {
    let mut addrs = target
        .to_socket_addrs()
        .map_err(|e| EcError::Runtime(format!("resolve udp target failed: {target}: {e}")))?;
    addrs
        .find_map(|addr| match addr {
            SocketAddr::V4(v4) => Some(v4),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| {
            EcError::Runtime(format!("no ipv4 address resolved for udp target {target}"))
        })
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

enum UdpRouteTransport {
    Tunnel(SocketAddrV4),
    Unsupported(String),
}

struct UdpRouteDecision {
    line: String,
    path: String,
    transport: UdpRouteTransport,
}

fn target_addr(target: &str) -> String {
    if let Some((host, port)) = target.rsplit_once(':') {
        return format_socket_target(host, port);
    }
    target.to_string()
}

fn is_ip_host(host: &str) -> bool {
    host.trim().parse::<Ipv4Addr>().is_ok() || host.trim().parse::<Ipv6Addr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::normalize_bind_addr;

    #[test]
    fn normalize_bind_addr_expands_port_only() {
        assert_eq!(normalize_bind_addr(":1080"), "0.0.0.0:1080");
    }

    #[test]
    fn normalize_bind_addr_keeps_explicit_host() {
        assert_eq!(normalize_bind_addr("127.0.0.1:1080"), "127.0.0.1:1080");
    }
}
