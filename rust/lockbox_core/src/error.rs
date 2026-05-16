use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    CorruptHeader,
    CorruptRecord,
    InvalidKey,
    NotFound(String),
    InvalidPath(String),
    Io(String),
    SecurityLimitExceeded(String),
    Truncated,
}

impl std::error::Error for Error {}

impl From<lockbox_secure::Error> for Error {
    fn from(err: lockbox_secure::Error) -> Self {
        Error::SecurityLimitExceeded(err.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::CorruptHeader => write!(f, "corrupt lockbox header"),
            Error::CorruptRecord => write!(f, "corrupt lockbox record"),
            Error::InvalidKey => write!(f, "invalid key or payload authentication failed"),
            Error::NotFound(path) => write!(f, "file not found: {path}"),
            Error::InvalidPath(path) => write!(f, "invalid path: {path}"),
            Error::Io(message) => write!(f, "io error: {message}"),
            Error::SecurityLimitExceeded(message) => {
                write!(f, "security limit exceeded: {message}")
            }
            Error::Truncated => write!(f, "truncated lockbox"),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
