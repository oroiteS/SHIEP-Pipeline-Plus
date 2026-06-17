use std::fmt::Display;
use thiserror::Error;

pub type EcResult<T> = Result<T, EcError>;

#[derive(Debug, Error)]
pub enum EcError {
    #[error("invalid config: {0}")]
    InvalidConfig(&'static str),

    #[error("unsupported: {0}")]
    Unsupported(&'static str),

    #[error("runtime failure: {0}")]
    Runtime(String),
}

const RUNTIME_PREFIX: &str = "runtime failure: ";

pub fn concise_error(err: impl Display) -> String {
    concise_message(err.to_string())
}

pub fn concise_message(message: impl Into<String>) -> String {
    strip_runtime_prefixes(message.into().as_str()).to_string()
}

fn strip_runtime_prefixes(mut message: &str) -> &str {
    while let Some(rest) = message.strip_prefix(RUNTIME_PREFIX) {
        message = rest;
    }
    message
}

#[cfg(test)]
mod tests {
    use super::{RUNTIME_PREFIX, concise_message};

    #[test]
    fn concise_message_strips_single_runtime_prefix() {
        let message = format!("{RUNTIME_PREFIX}socket closed");
        assert_eq!(concise_message(message), "socket closed");
    }

    #[test]
    fn concise_message_strips_repeated_runtime_prefixes() {
        let message = format!("{RUNTIME_PREFIX}{RUNTIME_PREFIX}inner failure");
        assert_eq!(concise_message(message), "inner failure");
    }
}
