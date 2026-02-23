use crate::error::{EcError, EcResult};

pub fn fetch_agent_token(_server: &str, _twf_id: &str) -> EcResult<String> {
    Err(EcError::NotImplemented("token.fetch_agent_token"))
}
