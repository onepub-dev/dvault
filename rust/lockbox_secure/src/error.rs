use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    AllocationFailed,
    CapacityOverflow,
    CorruptAllocation,
    InvalidUtf8,
    LockFailed,
    ProtectionFailed,
    RandomFailed,
    ReadAccessActive,
    WeakAllocationDisabled,
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AllocationFailed => write!(f, "secure allocation failed"),
            Error::CapacityOverflow => write!(f, "secure allocation capacity overflowed"),
            Error::CorruptAllocation => write!(f, "secure allocation metadata is corrupt"),
            Error::InvalidUtf8 => write!(f, "secure string is not valid utf-8"),
            Error::LockFailed => write!(f, "secure memory lock failed"),
            Error::ProtectionFailed => write!(f, "secure memory protection failed"),
            Error::RandomFailed => write!(f, "secure random source failed"),
            Error::ReadAccessActive => {
                write!(
                    f,
                    "secure memory cannot be mutated while read access is active"
                )
            }
            Error::WeakAllocationDisabled => {
                write!(f, "weakened secure memory allocation is disabled")
            }
        }
    }
}
