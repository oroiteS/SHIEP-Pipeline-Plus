use crate::error::{EcError, EcResult};

pub(crate) const PROTOCOL_TOKEN_LEN: usize = 48;

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
    use super::{
        PROTOCOL_TOKEN_LEN, build_query_ip_message, build_stream_handshake_message,
        parse_protocol_token,
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
}
