use crate::error::{EcError, EcResult};

pub fn query_assigned_ip(_server: &str, _token: &str) -> EcResult<[u8; 4]> {
    Err(EcError::NotImplemented("protocol.query_assigned_ip"))
}

pub fn start_tunnel_runtime(_server: &str, _token: &str, _assigned_ip: [u8; 4]) -> EcResult<()> {
    Err(EcError::NotImplemented("protocol.start_tunnel_runtime"))
}
