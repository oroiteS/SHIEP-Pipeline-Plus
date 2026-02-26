use std::fmt::Display;
use thiserror::Error;

pub type EcResult<T> = Result<T, EcError>;

#[derive(Debug, Error)]
pub enum EcError {
    #[error("invalid config: {0}")]
    InvalidConfig(&'static str),

    #[error("not implemented yet: {0}")]
    NotImplemented(&'static str),

    #[error("runtime failure: {0}")]
    Runtime(String),
}

const RUNTIME_PREFIX: &str = "runtime failure: ";

pub fn concise_error(err: impl Display) -> String {
    concise_message(err.to_string())
}

pub fn concise_message(message: impl Into<String>) -> String {
    let mut message = message.into();
    while let Some(rest) = message.strip_prefix(RUNTIME_PREFIX) {
        message = rest.to_string();
    }
    message
}
