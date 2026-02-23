use crate::config::AppConfig;
use crate::error::{EcError, EcResult};

pub fn login(_config: &AppConfig) -> EcResult<String> {
    Err(EcError::NotImplemented("auth.login"))
}
