use crate::error::{EcError, EcResult};

pub(crate) const PROTOCOL_TOKEN_LEN: usize = 48;
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

#[cfg(test)]
mod tests {
    use super::NativeControlType::{Heartbeat, RxAck, Unknown};
    use super::{
        PROTOCOL_TOKEN_LEN, build_query_ip_message, build_stream_handshake_message,
        parse_native_control_frame, parse_protocol_token,
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
}
