pub use lockbox_secure::{
    allocation_chunk_bytes as secure_allocation_chunk_bytes, read_access as secure_read_access,
    secure_memory_capabilities, set_allocation_chunk_bytes as set_secure_allocation_chunk_bytes,
    set_weakened_allocation_allowed, weakened_allocation_allowed, AllocationSecurity,
    SecureMemoryCapabilities, SecureReadAccess, SecureString as SecretString,
    SecureVec as SecretVec,
};

pub(crate) use lockbox_secure::SecureVec;
