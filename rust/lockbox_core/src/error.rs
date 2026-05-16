use std::fmt;

/// Error type returned by lockbox operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The public header could not be parsed or authenticated.
    CorruptHeader,
    /// An encrypted record or decoded page failed validation.
    CorruptRecord,
    /// The supplied key was wrong or authentication failed.
    InvalidKey,
    /// A requested logical path was not found.
    NotFound(String),
    /// A caller supplied an invalid logical or host path.
    InvalidPath(String),
    /// Filesystem or platform IO failed.
    Io(String),
    /// A configured safety limit rejected the operation.
    SecurityLimitExceeded(String),
    /// The input ended before a complete lockbox structure could be read.
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

/// Convenient result alias for lockbox operations.
pub type Result<T> = std::result::Result<T, Error>;
