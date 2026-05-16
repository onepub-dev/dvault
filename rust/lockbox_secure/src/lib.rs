#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

mod allocation;
mod arena;
mod canary;
mod capabilities;
mod config;
mod error;
mod memory_region;
mod page_permission;
mod secure_access;
mod secure_heap;
mod secure_string;
mod secure_vec;

#[cfg(test)]
mod tests;

pub use capabilities::{
    secure_memory_capabilities, set_weakened_allocation_allowed, weakened_allocation_allowed,
    AllocationSecurity, SecureMemoryCapabilities,
};
pub use config::{allocation_chunk_bytes, set_allocation_chunk_bytes};
pub use error::{Error, Result};
pub use secure_access::{read_access, SecureReadAccess};
pub use secure_string::SecureString;
pub use secure_vec::SecureVec;
