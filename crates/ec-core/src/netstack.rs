use crate::error::{EcError, EcResult};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::sync::OnceLock;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

static CONTROL_TX: OnceLock<mpsc::Sender<ControlMessage>> = OnceLock::new();

pub fn validate_netstack_preconditions() -> EcResult<()> {
    Ok(())
}

pub fn start_runtime(assigned_ip: [u8; 4]) -> EcResult<()> {
    if CONTROL_TX.get().is_some() {
        return Ok(());
    }

    let tunnel_rx = crate::protocol::take_tunnel_packet_receiver()?;
    let (control_tx, control_rx) = mpsc::channel::<ControlMessage>();
    CONTROL_TX
        .set(control_tx)
        .map_err(|_| EcError::Runtime("netstack runtime already initialized".to_string()))?;

    thread::spawn(move || {
        if let Err(err) = run_netstack_loop(assigned_ip, tunnel_rx, control_rx) {
            eprintln!("[NETSTACK] fatal error: {err}");
        }
    });

    Ok(())
}

pub fn open_tcp_connection(target: &str) -> EcResult<TunnelTcpConnection> {
    let control = CONTROL_TX
        .get()
        .ok_or_else(|| EcError::Runtime("netstack runtime is not started".to_string()))?
        .clone();

    let target_addr = resolve_ipv4_target(target)?;
    let (reply_tx, reply_rx) = mpsc::channel::<EcResult<(u64, mpsc::Receiver<Vec<u8>>)>>();
    control
        .send(ControlMessage::Open {
            target: target_addr,
            reply: reply_tx,
        })
        .map_err(|e| EcError::Runtime(format!("send open connection request failed: {e}")))?;

    match reply_rx.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok((id, rx))) => Ok(TunnelTcpConnection {
            id,
            control_tx: control,
            rx,
        }),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(EcError::Runtime(format!(
            "wait open connection response failed: {e}"
        ))),
    }
}

#[derive(Debug)]
pub struct TunnelTcpConnection {
    id: u64,
    control_tx: mpsc::Sender<ControlMessage>,
    rx: mpsc::Receiver<Vec<u8>>,
}

impl TunnelTcpConnection {
    pub fn sender(&self) -> TunnelTcpSender {
        TunnelTcpSender {
            id: self.id,
            control_tx: self.control_tx.clone(),
        }
    }

    pub fn into_receiver(self) -> mpsc::Receiver<Vec<u8>> {
        self.rx
    }
}

#[derive(Clone, Debug)]
pub struct TunnelTcpSender {
    id: u64,
    control_tx: mpsc::Sender<ControlMessage>,
}

impl TunnelTcpSender {
    pub fn send(&self, data: Vec<u8>) -> EcResult<()> {
        self.control_tx
            .send(ControlMessage::Send { id: self.id, data })
            .map_err(|e| EcError::Runtime(format!("send tcp payload request failed: {e}")))
    }

    pub fn close(&self) -> EcResult<()> {
        self.control_tx
            .send(ControlMessage::Close { id: self.id })
            .map_err(|e| EcError::Runtime(format!("send tcp close request failed: {e}")))
    }
}

enum ControlMessage {
    Open {
        target: SocketAddrV4,
        reply: mpsc::Sender<EcResult<(u64, mpsc::Receiver<Vec<u8>>)>>,
    },
    Send {
        id: u64,
        data: Vec<u8>,
    },
    Close {
        id: u64,
    },
}

struct ConnectionState {
    handle: SocketHandle,
    uplink: mpsc::Sender<Vec<u8>>,
    pending_send: VecDeque<Vec<u8>>,
    close_requested: bool,
}

fn run_netstack_loop(
    assigned_ip: [u8; 4],
    tunnel_rx: mpsc::Receiver<Vec<u8>>,
    control_rx: mpsc::Receiver<ControlMessage>,
) -> EcResult<()> {
    let mut device = TunnelDevice::new();
    let mut cfg = Config::new(HardwareAddress::Ip);
    cfg.random_seed = Instant::now().elapsed().as_nanos() as u64;
    let mut iface = Interface::new(cfg, &mut device, smol_now(Instant::now()));
    let client_ip = Ipv4Address::new(assigned_ip[0], assigned_ip[1], assigned_ip[2], assigned_ip[3]);
    iface.update_ip_addrs(|ip_addrs| {
        let _ = ip_addrs.push(IpCidr::new(IpAddress::Ipv4(client_ip), 0));
    });

    let mut sockets = SocketSet::new(vec![]);
    let mut connections = HashMap::<u64, ConnectionState>::new();
    let mut next_conn_id: u64 = 1;
    let mut next_local_port: u16 = 40000;
    let start = Instant::now();

    loop {
        while let Ok(packet) = tunnel_rx.try_recv() {
            device.push_rx(packet);
        }

        while let Ok(msg) = control_rx.try_recv() {
            match msg {
                ControlMessage::Open { target, reply } => {
                    let socket = tcp::Socket::new(
                        tcp::SocketBuffer::new(vec![0; 64 * 1024]),
                        tcp::SocketBuffer::new(vec![0; 64 * 1024]),
                    );
                    let handle = sockets.add(socket);
                    let local_port = alloc_local_port(&mut next_local_port);
                    let connect_result = {
                        let socket = sockets.get_mut::<tcp::Socket>(handle);
                        socket.connect(
                            iface.context(),
                            (IpAddress::Ipv4(*target.ip()), target.port()),
                            local_port,
                        )
                    };

                    match connect_result {
                        Ok(()) => {
                            let (uplink_tx, uplink_rx) = mpsc::channel::<Vec<u8>>();
                            let id = next_conn_id;
                            next_conn_id = next_conn_id.wrapping_add(1);
                            connections.insert(
                                id,
                                ConnectionState {
                                    handle,
                                    uplink: uplink_tx,
                                    pending_send: VecDeque::new(),
                                    close_requested: false,
                                },
                            );
                            let _ = reply.send(Ok((id, uplink_rx)));
                        }
                        Err(e) => {
                            let _ = sockets.remove(handle);
                            let _ = reply.send(Err(EcError::Runtime(format!(
                                "tcp connect failed: {e}"
                            ))));
                        }
                    }
                }
                ControlMessage::Send { id, data } => {
                    if let Some(conn) = connections.get_mut(&id) {
                        conn.pending_send.push_back(data);
                    }
                }
                ControlMessage::Close { id } => {
                    if let Some(conn) = connections.get_mut(&id) {
                        conn.close_requested = true;
                    }
                }
            }
        }

        let now = smol_now(start);
        let _ = iface.poll(now, &mut device, &mut sockets);

        let mut remove_ids = Vec::new();
        for (id, conn) in &mut connections {
            let socket = sockets.get_mut::<tcp::Socket>(conn.handle);

            while socket.can_send() {
                let Some(mut chunk) = conn.pending_send.pop_front() else {
                    break;
                };
                match socket.send_slice(&chunk) {
                    Ok(sent) if sent == chunk.len() => {}
                    Ok(sent) => {
                        chunk.drain(..sent);
                        conn.pending_send.push_front(chunk);
                        break;
                    }
                    Err(_) => {
                        conn.close_requested = true;
                        break;
                    }
                }
            }

            while socket.can_recv() {
                let mut buf = [0u8; 4096];
                match socket.recv_slice(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if conn.uplink.send(buf[..n].to_vec()).is_err() {
                            conn.close_requested = true;
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }

            if conn.close_requested && socket.may_send() {
                socket.close();
            }
            if !socket.is_open() {
                remove_ids.push(*id);
            }
        }

        for id in remove_ids {
            if let Some(conn) = connections.remove(&id) {
                let _ = sockets.remove(conn.handle);
            }
        }

        thread::sleep(Duration::from_millis(2));
    }
}

fn resolve_ipv4_target(target: &str) -> EcResult<SocketAddrV4> {
    let mut addrs = target
        .to_socket_addrs()
        .map_err(|e| EcError::Runtime(format!("resolve target failed: {target}: {e}")))?;
    addrs
        .find_map(|addr| match addr {
            SocketAddr::V4(v4) => Some(v4),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| EcError::Runtime(format!("no ipv4 address resolved for {target}")))
}

fn alloc_local_port(next: &mut u16) -> u16 {
    let port = *next;
    *next = if *next >= 60000 { 40000 } else { *next + 1 };
    port
}

fn smol_now(start: Instant) -> SmolInstant {
    SmolInstant::from_millis(start.elapsed().as_millis() as i64)
}

struct TunnelDevice {
    rx_queue: VecDeque<Vec<u8>>,
}

impl TunnelDevice {
    fn new() -> Self {
        Self {
            rx_queue: VecDeque::new(),
        }
    }

    fn push_rx(&mut self, packet: Vec<u8>) {
        self.rx_queue.push_back(packet);
    }
}

struct TunnelRxToken {
    frame: Vec<u8>,
}

impl RxToken for TunnelRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.frame)
    }
}

#[derive(Default)]
struct TunnelTxToken;

impl TxToken for TunnelTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = vec![0u8; len];
        let out = f(&mut frame);
        if let Err(err) = crate::protocol::send_tunnel_packet(frame) {
            eprintln!("[NETSTACK] send tunnel packet failed: {err}");
        }
        out
    }
}

impl Device for TunnelDevice {
    type RxToken<'a>
        = TunnelRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = TunnelTxToken
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let frame = self.rx_queue.pop_front()?;
        Some((TunnelRxToken { frame }, TunnelTxToken))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TunnelTxToken)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps
    }
}
