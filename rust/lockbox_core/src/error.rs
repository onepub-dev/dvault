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

impl Error {
    /// Return user-facing recovery guidance for this error.
    pub fn guidance(&self) -> &'static str {
        match self {
            Error::CorruptHeader => {
                "Verify this is a lockbox file, then try recovery if the file may be damaged."
            }
            Error::CorruptRecord => {
                "The lockbox contents failed validation; try recovery or restore from a clean copy."
            }
            Error::InvalidKey => {
                "Check the password, raw key, recipient private key, or local vault unlock state."
            }
            Error::NotFound(_) => {
                "Check the logical lockbox path and list the parent directory to see available entries."
            }
            Error::InvalidPath(_) => {
                "Use an absolute logical lockbox path such as /docs/file.txt; host paths, '..', control characters, and unsafe Unicode are rejected."
            }
            Error::Io(_) => {
                "Check filesystem permissions, whether the path exists, and whether another process is using the file."
            }
            Error::SecurityLimitExceeded(_) => {
                "Reduce the input size or raise the explicit limit only if the source is trusted."
            }
            Error::Truncated => {
                "The input ended early; check whether the file copy or range response is complete."
            }
        }
    }
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
            Error::CorruptHeader => {
                write!(f, "corrupt lockbox header. {}", self.guidance())
            }
            Error::CorruptRecord => {
                write!(f, "corrupt lockbox page or record. {}", self.guidance())
            }
            Error::InvalidKey => {
                write!(
                    f,
                    "unlock failed or payload authentication failed. {}",
                    self.guidance()
                )
            }
            Error::NotFound(path) => {
                write!(f, "lockbox entry not found: {path}. {}", self.guidance())
            }
            Error::InvalidPath(path) => {
                write!(f, "invalid lockbox path: {path}. {}", self.guidance())
            }
            Error::Io(message) => write!(f, "io error: {message}. {}", self.guidance()),
            Error::SecurityLimitExceeded(message) => {
                write!(f, "security limit exceeded: {message}. {}", self.guidance())
            }
            Error::Truncated => write!(f, "truncated lockbox input. {}", self.guidance()),
        }
    }
}

/// Convenient result alias for lockbox operations.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn display_errors_include_context_and_guidance() {
        let invalid_path = Error::InvalidPath("../secret".to_string()).to_string();
        assert!(invalid_path.contains("invalid lockbox path: ../secret"));
        assert!(invalid_path.contains("Use an absolute logical lockbox path"));

        let missing = Error::NotFound("/missing".to_string()).to_string();
        assert!(missing.contains("lockbox entry not found: /missing"));
        assert!(missing.contains("list the parent directory"));

        let invalid_key = Error::InvalidKey.to_string();
        assert!(invalid_key.contains("unlock failed"));
        assert!(invalid_key.contains("password"));
    }
}
