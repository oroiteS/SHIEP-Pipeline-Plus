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
