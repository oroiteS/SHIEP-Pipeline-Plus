use crate::error::{EcError, EcResult};

pub(crate) const PROTOCOL_TOKEN_LEN: usize = 48;
pub(crate) const HEARTBEAT_SESSION_LEN: usize = 16;
pub(crate) const HEARTBEAT_OPAQUE_TAIL_LEN: usize = 8;
const TX_HEARTBEAT_PACKET_LEN: usize = 0x4c;
const TX_HEARTBEAT_DST: [u8; 4] = [10, 166, 64, 3];
const TX_HEARTBEAT_IPV4_ID: [u8; 2] = [0xbb, 0xaa];
const TX_HEARTBEAT_TTL: u8 = 0x40;
const TX_HEARTBEAT_ICMP_ID: [u8; 2] = [0x55, 0x55];
const TX_HEARTBEAT_ICMP_SEQ: [u8; 2] = [0x44, 0x33];
const TX_HEARTBEAT_PAYLOAD_PREFIX: &[u8; 18] = b"SANGFORSCSIPCLIENT";
const TX_HEARTBEAT_PAYLOAD_SUFFIX: &[u8; 6] = b"L3VPN\0";
const NATIVE_CONTROL_FRAME_LEN: usize = 0x28;
const NATIVE_CONTROL_MAGIC: &[u8; 4] = b"AABB";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeControlType {
    SendIp,
    RxAck,
    TxAck,
    ServerReset,
    Recovered,
    IpBusy,
    Shutdown,
    IpConflict,
    IpKick,
    Heartbeat,
    Unknown(u32),
}

impl NativeControlType {
    pub(crate) fn code(self) -> u32 {
        match self {
            Self::SendIp => 0,
            Self::RxAck => 1,
            Self::TxAck => 2,
            Self::ServerReset => 3,
            Self::Recovered => 4,
            Self::IpBusy => 5,
            Self::Shutdown => 8,
            Self::IpConflict => 9,
            Self::IpKick => 14,
            Self::Heartbeat => 15,
            Self::Unknown(v) => v,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::SendIp => "send-ip",
            Self::RxAck => "rx-ack",
            Self::TxAck => "tx-ack",
            Self::ServerReset => "server-reset",
            Self::Recovered => "recovered",
            Self::IpBusy => "ip-busy",
            Self::Shutdown => "shutdown",
            Self::IpConflict => "ip-conflict",
            Self::IpKick => "ip-kick",
            Self::Heartbeat => "heartbeat",
            Self::Unknown(_) => "unknown",
        }
    }
}

pub(crate) fn parse_native_control_frame(data: &[u8]) -> Option<NativeControlType> {
    if data.len() != NATIVE_CONTROL_FRAME_LEN || !data.starts_with(NATIVE_CONTROL_MAGIC) {
        return None;
    }

    let code = u32::from_le_bytes(data[4..8].try_into().ok()?);
    Some(match code {
        0 => NativeControlType::SendIp,
        1 => NativeControlType::RxAck,
        2 => NativeControlType::TxAck,
        3 => NativeControlType::ServerReset,
        4 => NativeControlType::Recovered,
        5 => NativeControlType::IpBusy,
        8 => NativeControlType::Shutdown,
        9 => NativeControlType::IpConflict,
        14 => NativeControlType::IpKick,
        15 => NativeControlType::Heartbeat,
        v => NativeControlType::Unknown(v),
    })
}

pub(crate) fn parse_protocol_token(token: &str) -> EcResult<[u8; PROTOCOL_TOKEN_LEN]> {
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

pub(crate) fn build_query_ip_message(token: &[u8; PROTOCOL_TOKEN_LEN]) -> [u8; 64] {
    let mut message = [0u8; 64];
    message[4..(4 + PROTOCOL_TOKEN_LEN)].copy_from_slice(token);
    message[60..64].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
    message
}

pub(crate) fn build_stream_handshake_message(
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

pub(crate) fn build_tx_heartbeat_packet(
    assigned_ip: [u8; 4],
    session: &[u8; HEARTBEAT_SESSION_LEN],
    opaque_tail: &[u8; HEARTBEAT_OPAQUE_TAIL_LEN],
) -> [u8; TX_HEARTBEAT_PACKET_LEN] {
    let mut packet = [0u8; TX_HEARTBEAT_PACKET_LEN];

    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(TX_HEARTBEAT_PACKET_LEN as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&TX_HEARTBEAT_IPV4_ID);
    packet[8] = TX_HEARTBEAT_TTL;
    packet[9] = 0x01;
    packet[12..16].copy_from_slice(&assigned_ip);
    packet[16..20].copy_from_slice(&TX_HEARTBEAT_DST);

    packet[20] = 0x08;
    packet[21] = 0x00;
    packet[24..26].copy_from_slice(&TX_HEARTBEAT_ICMP_ID);
    packet[26..28].copy_from_slice(&TX_HEARTBEAT_ICMP_SEQ);
    packet[28..46].copy_from_slice(TX_HEARTBEAT_PAYLOAD_PREFIX);
    packet[46..62].copy_from_slice(session);
    packet[62..70].copy_from_slice(opaque_tail);
    packet[70..76].copy_from_slice(TX_HEARTBEAT_PAYLOAD_SUFFIX);

    let ip_checksum = internet_checksum(&packet[0..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    let icmp_checksum = internet_checksum(&packet[20..]);
    packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());

    packet
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        let word = if let [hi, lo] = chunk {
            u16::from_be_bytes([*hi, *lo])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += u32::from(word);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::NativeControlType::{Heartbeat, RxAck, Unknown};
    use super::{
        PROTOCOL_TOKEN_LEN, build_query_ip_message, build_stream_handshake_message,
        build_tx_heartbeat_packet, parse_native_control_frame, parse_protocol_token,
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

    #[test]
    fn native_control_frame_parses_aabb_little_endian_type() {
        let mut frame = [0u8; 0x28];
        frame[0..4].copy_from_slice(b"AABB");
        frame[4..8].copy_from_slice(&15u32.to_le_bytes());
        assert_eq!(parse_native_control_frame(&frame), Some(Heartbeat));

        frame[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(parse_native_control_frame(&frame), Some(RxAck));

        frame[4..8].copy_from_slice(&42u32.to_le_bytes());
        assert_eq!(parse_native_control_frame(&frame), Some(Unknown(42)));
    }

    #[test]
    fn native_control_frame_rejects_wrong_len_or_magic() {
        let mut frame = [0u8; 0x28];
        frame[0..4].copy_from_slice(b"AABB");
        frame[4..8].copy_from_slice(&15u32.to_le_bytes());
        assert_eq!(parse_native_control_frame(&frame[..0x27]), None);

        frame[0..4].copy_from_slice(b"TIMQ");
        assert_eq!(parse_native_control_frame(&frame), None);
    }

    #[test]
    fn tx_heartbeat_packet_matches_captured_layout() {
        let packet = build_tx_heartbeat_packet(
            [10, 166, 80, 12],
            b"eab27cdf7c24a40f",
            &[0x03, 0xa2, 0x16, 0x5a, 0xd5, 0x3d, 0x79, 0xb8],
        );
        let expected = [
            0x45, 0x00, 0x00, 0x4c, 0xbb, 0xaa, 0x00, 0x00, 0x40, 0x01, 0x19, 0xac, 0x0a, 0xa6,
            0x50, 0x0c, 0x0a, 0xa6, 0x40, 0x03, 0x08, 0x00, 0x04, 0xbd, 0x55, 0x55, 0x44, 0x33,
            0x53, 0x41, 0x4e, 0x47, 0x46, 0x4f, 0x52, 0x53, 0x43, 0x53, 0x49, 0x50, 0x43, 0x4c,
            0x49, 0x45, 0x4e, 0x54, 0x65, 0x61, 0x62, 0x32, 0x37, 0x63, 0x64, 0x66, 0x37, 0x63,
            0x32, 0x34, 0x61, 0x34, 0x30, 0x66, 0x03, 0xa2, 0x16, 0x5a, 0xd5, 0x3d, 0x79, 0xb8,
            0x4c, 0x33, 0x56, 0x50, 0x4e, 0x00,
        ];
        assert_eq!(packet, expected);
    }
}
