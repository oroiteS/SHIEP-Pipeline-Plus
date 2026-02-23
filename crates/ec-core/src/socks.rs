use crate::error::{EcError, EcResult};

pub fn serve(_bind_addr: &str) -> EcResult<()> {
    Err(EcError::NotImplemented("socks.serve"))
}
