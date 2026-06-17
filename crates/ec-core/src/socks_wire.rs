use crate::error::{EcError, EcResult};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, TcpStream};

const SOCKS_VERSION_5: u8 = 0x05;
const SOCKS_METHOD_NO_AUTH: u8 = 0x00;
const SOCKS_METHOD_NOT_ACCEPTABLE: u8 = 0xff;
const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_CMD_UDP_ASSOCIATE: u8 = 0x03;
const SOCKS_RSV: u8 = 0x00;
const SOCKS_ATYP_IPV4: u8 = 0x01;
const SOCKS_ATYP_DOMAIN: u8 = 0x03;
const SOCKS_ATYP_IPV6: u8 = 0x04;
pub(crate) const SOCKS_REP_GENERAL_FAILURE: u8 = 0x01;
pub(crate) const SOCKS_REP_SUCCEEDED: u8 = 0x00;
pub(crate) const SOCKS_REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const SOCKS_REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

pub(crate) fn negotiate_method(client: &mut TcpStream) -> EcResult<()> {
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

pub(crate) fn read_socks_request(client: &mut TcpStream) -> EcResult<SocksRequest> {
    let mut req = [0u8; 4];
    client
        .read_exact(&mut req)
        .map_err(|e| EcError::Runtime(format!("socks request head read failed: {e}")))?;

    if req[0] != SOCKS_VERSION_5 {
        return Err(EcError::Runtime(
            "invalid socks request version".to_string(),
        ));
    }
    let command = SocksCommand::from_byte(req[1]);
    if matches!(command, SocksCommand::Other(_)) {
        let _ = write_reply(client, SOCKS_REP_CMD_NOT_SUPPORTED);
        return Err(EcError::Runtime(format!(
            "unsupported socks command: {command}"
        )));
    }
    if req[2] != SOCKS_RSV {
        let _ = write_reply(client, SOCKS_REP_GENERAL_FAILURE);
        return Err(EcError::Runtime("invalid socks reserved byte".to_string()));
    }

    let target = read_request_target(client, req[3])?;
    Ok(SocksRequest { command, target })
}

fn read_request_target(client: &mut TcpStream, atyp: u8) -> EcResult<ConnectTarget> {
    let host = match atyp {
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

pub(crate) fn write_reply(client: &mut TcpStream, rep: u8) -> EcResult<()> {
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

pub(crate) fn write_bound_reply(
    client: &mut TcpStream,
    rep: u8,
    bound: SocketAddrV4,
) -> EcResult<()> {
    let mut reply = Vec::with_capacity(10);
    reply.extend_from_slice(&[SOCKS_VERSION_5, rep, SOCKS_RSV, SOCKS_ATYP_IPV4]);
    reply.extend_from_slice(&bound.ip().octets());
    reply.extend_from_slice(&bound.port().to_be_bytes());
    client
        .write_all(&reply)
        .map_err(|e| EcError::Runtime(format!("socks bound reply write failed: {e}")))
}

pub(crate) fn parse_socks_udp_packet(data: &[u8]) -> EcResult<SocksUdpPacket> {
    if data.len() < 4 {
        return Err(EcError::Runtime(
            "udp packet header is too short".to_string(),
        ));
    }
    if data[0] != 0 || data[1] != 0 {
        return Err(EcError::Runtime(
            "udp packet with non-zero RSV is not supported".to_string(),
        ));
    }
    if data[2] != 0 {
        return Err(EcError::Runtime(
            "fragmented udp packet is not supported".to_string(),
        ));
    }

    let mut offset = 4;
    let host = match data[3] {
        SOCKS_ATYP_IPV4 => {
            if data.len() < offset + 4 {
                return Err(EcError::Runtime(
                    "udp ipv4 address is truncated".to_string(),
                ));
            }
            let ip = Ipv4Addr::new(
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            );
            offset += 4;
            ip.to_string()
        }
        SOCKS_ATYP_DOMAIN => {
            if data.len() < offset + 1 {
                return Err(EcError::Runtime(
                    "udp domain length is truncated".to_string(),
                ));
            }
            let len = data[offset] as usize;
            offset += 1;
            if data.len() < offset + len {
                return Err(EcError::Runtime("udp domain is truncated".to_string()));
            }
            let domain = String::from_utf8(data[offset..offset + len].to_vec())
                .map_err(|e| EcError::Runtime(format!("invalid udp domain utf8: {e}")))?;
            offset += len;
            domain
        }
        SOCKS_ATYP_IPV6 => {
            return Err(EcError::Runtime(
                "udp ipv6 targets are not supported yet".to_string(),
            ));
        }
        atyp => {
            return Err(EcError::Runtime(format!(
                "unsupported udp atyp: 0x{atyp:02x}"
            )));
        }
    };
    if data.len() < offset + 2 {
        return Err(EcError::Runtime("udp port is truncated".to_string()));
    }
    let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    Ok(SocksUdpPacket {
        target: ConnectTarget { host, port },
        payload: data[offset..].to_vec(),
    })
}

pub(crate) fn encode_socks_udp_packet(source: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + payload.len());
    out.extend_from_slice(&[0, 0, 0, SOCKS_ATYP_IPV4]);
    out.extend_from_slice(&source.ip().octets());
    out.extend_from_slice(&source.port().to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub(crate) fn format_socket_target(host: &str, port: impl std::fmt::Display) -> String {
    let h = host.trim();
    if h.parse::<Ipv6Addr>().is_ok() {
        format!("[{h}]:{port}")
    } else {
        format!("{h}:{port}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocksCommand {
    Connect,
    UdpAssociate,
    Other(u8),
}

impl SocksCommand {
    fn from_byte(value: u8) -> Self {
        match value {
            SOCKS_CMD_CONNECT => Self::Connect,
            SOCKS_CMD_UDP_ASSOCIATE => Self::UdpAssociate,
            other => Self::Other(other),
        }
    }
}

impl std::fmt::Display for SocksCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect => f.write_str("CONNECT"),
            Self::UdpAssociate => f.write_str("UDP ASSOCIATE"),
            Self::Other(value) => write!(f, "0x{value:02x}"),
        }
    }
}

pub(crate) struct SocksRequest {
    pub(crate) command: SocksCommand,
    pub(crate) target: ConnectTarget,
}

pub(crate) struct SocksUdpPacket {
    pub(crate) target: ConnectTarget,
    pub(crate) payload: Vec<u8>,
}

#[derive(Clone)]
pub(crate) struct ConnectTarget {
    host: String,
    port: u16,
}

impl ConnectTarget {
    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }
}

impl std::fmt::Display for ConnectTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::{SocksCommand, encode_socks_udp_packet, parse_socks_udp_packet};
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn socks_command_maps_known_values() {
        assert_eq!(SocksCommand::from_byte(0x01), SocksCommand::Connect);
        assert_eq!(SocksCommand::from_byte(0x03), SocksCommand::UdpAssociate);
        assert_eq!(SocksCommand::from_byte(0x02), SocksCommand::Other(0x02));
    }

    #[test]
    fn parse_socks_udp_packet_reads_ipv4_target() {
        let raw = [0, 0, 0, 1, 10, 50, 2, 206, 0, 53, b'q', b'1'];
        let packet = parse_socks_udp_packet(&raw).unwrap();
        assert_eq!(packet.target.host(), "10.50.2.206");
        assert_eq!(packet.target.port(), 53);
        assert_eq!(packet.payload, b"q1");
    }

    #[test]
    fn parse_socks_udp_packet_reads_domain_target() {
        let raw = [
            0, 0, 0, 3, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 53, b'q',
        ];
        let packet = parse_socks_udp_packet(&raw).unwrap();
        assert_eq!(packet.target.host(), "example");
        assert_eq!(packet.target.port(), 53);
        assert_eq!(packet.payload, b"q");
    }

    #[test]
    fn parse_socks_udp_packet_rejects_fragments() {
        let raw = [0, 0, 1, 1, 10, 50, 2, 206, 0, 53];
        assert!(parse_socks_udp_packet(&raw).is_err());
    }

    #[test]
    fn encode_socks_udp_packet_writes_ipv4_source() {
        let source = SocketAddrV4::new(Ipv4Addr::new(10, 50, 2, 206), 53);
        let packet = encode_socks_udp_packet(source, b"ans");
        assert_eq!(
            packet,
            vec![0, 0, 0, 1, 10, 50, 2, 206, 0, 53, b'a', b'n', b's']
        );
    }
}
