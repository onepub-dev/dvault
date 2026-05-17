use std::fmt;

/// Error type returned by lockbox operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The public header could not be parsed or authenticated.
    CorruptHeader,
    /// An encrypted record or decoded page failed validation.
    CorruptRecord,
    /// Stored vault metadata failed validation.
    CorruptVaultRecord(String),
    /// The supplied key was wrong or authentication failed.
    InvalidKey,
    /// A requested logical path was not found.
    NotFound(String),
    /// A caller tried to add an entry where one already exists.
    AlreadyExists(String),
    /// A caller supplied an invalid logical or host path.
    InvalidPath(String),
    /// A caller supplied invalid non-path input.
    InvalidInput(String),
    /// Key bytes, key text, or a key file could not be decoded as the expected key type.
    InvalidKeyMaterial(String),
    /// The requested operation conflicts with the current lockbox state.
    InvalidOperation(String),
    /// A vault-backed operation could not use the local vault or unlock cache.
    VaultUnavailable(String),
    /// A required host or process configuration value is missing or invalid.
    Configuration(String),
    /// A host filesystem path cannot be imported by the requested operation.
    UnsupportedHostPath(String),
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
            Error::CorruptVaultRecord(_) => {
                "The local vault metadata is inconsistent; delete or recreate the named vault record after confirming it is not needed."
            }
            Error::InvalidKey => "Check the password, content key, recipient keypair, or local vault unlock state.",
            Error::NotFound(_) => {
                "Check the logical lockbox path and list the parent directory to see available entries."
            }
            Error::AlreadyExists(_) => {
                "Pass replace = true only when intentionally replacing an existing lockbox entry."
            }
            Error::InvalidPath(_) => {
                "Use an absolute logical lockbox path such as /docs/file.txt; host paths, '..', control characters, and unsafe Unicode are rejected."
            }
            Error::InvalidInput(_) => {
                "Check the supplied value and use the documented input format."
            }
            Error::InvalidKeyMaterial(_) => {
                "Check the key file, key encoding, key format, and whether a public key was supplied where a private key was required."
            }
            Error::InvalidOperation(_) => {
                "Check the current entry state and use the API intended for that state."
            }
            Error::VaultUnavailable(_) => {
                "Unlock the lockbox with a password, recipient keypair, or content key, or configure the local vault before retrying."
            }
            Error::Configuration(_) => {
                "Set the required environment variable or pass an explicit path/value."
            }
            Error::UnsupportedHostPath(_) => {
                "Use a regular file or directory with valid UTF-8 path components, or add unsupported filesystem objects explicitly."
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
            Error::CorruptVaultRecord(message) => {
                write!(f, "corrupt vault record: {message}. {}", self.guidance())
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
            Error::AlreadyExists(path) => {
                write!(
                    f,
                    "lockbox entry already exists: {path}. {}",
                    self.guidance()
                )
            }
            Error::InvalidPath(path) => {
                write!(f, "invalid lockbox path: {path}. {}", self.guidance())
            }
            Error::InvalidInput(message) => {
                write!(f, "invalid input: {message}. {}", self.guidance())
            }
            Error::InvalidKeyMaterial(message) => {
                write!(f, "invalid key material: {message}. {}", self.guidance())
            }
            Error::InvalidOperation(message) => {
                write!(f, "invalid operation: {message}. {}", self.guidance())
            }
            Error::VaultUnavailable(message) => {
                write!(f, "vault unavailable: {message}. {}", self.guidance())
            }
            Error::Configuration(message) => {
                write!(f, "configuration error: {message}. {}", self.guidance())
            }
            Error::UnsupportedHostPath(message) => {
                write!(f, "unsupported host path: {message}. {}", self.guidance())
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

        let duplicate = Error::AlreadyExists("/exists".to_string()).to_string();
        assert!(duplicate.contains("lockbox entry already exists: /exists"));
        assert!(duplicate.contains("replace = true"));

        let invalid_key = Error::InvalidKey.to_string();
        assert!(invalid_key.contains("unlock failed"));
        assert!(invalid_key.contains("password"));

        let corrupt_vault_record =
            Error::CorruptVaultRecord("bad private key record".to_string()).to_string();
        assert!(corrupt_vault_record.contains("corrupt vault record: bad private key record"));

        let invalid_input = Error::InvalidInput("bad env value".to_string()).to_string();
        assert!(invalid_input.contains("invalid input: bad env value"));

        let invalid_key_material =
            Error::InvalidKeyMaterial("bad public key".to_string()).to_string();
        assert!(invalid_key_material.contains("invalid key material: bad public key"));

        let invalid_operation =
            Error::InvalidOperation("environment variable is secret".to_string()).to_string();
        assert!(invalid_operation.contains("invalid operation: environment variable is secret"));

        let vault = Error::VaultUnavailable("no cached key".to_string()).to_string();
        assert!(vault.contains("vault unavailable: no cached key"));

        let config = Error::Configuration("HOME is not set".to_string()).to_string();
        assert!(config.contains("configuration error: HOME is not set"));

        let host_path = Error::UnsupportedHostPath("socket".to_string()).to_string();
        assert!(host_path.contains("unsupported host path: socket"));
    }
}
