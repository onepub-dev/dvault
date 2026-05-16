use std::sync::atomic::{AtomicBool, Ordering};

static WEAKENED_ALLOCATION_ALLOWED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocationSecurity {
    Hardened,
    Weakened,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecureMemoryCapabilities {
    pub security: AllocationSecurity,
    pub memory_locked: bool,
    pub page_protected: bool,
    pub guard_pages: bool,
    pub dump_excluded: bool,
    pub fork_excluded: bool,
}

pub fn weakened_allocation_allowed() -> bool {
    WEAKENED_ALLOCATION_ALLOWED.load(Ordering::Relaxed)
}

pub fn set_weakened_allocation_allowed(allowed: bool) {
    WEAKENED_ALLOCATION_ALLOWED.store(allowed, Ordering::Relaxed);
}

pub fn secure_memory_capabilities() -> SecureMemoryCapabilities {
    #[cfg(any(unix, windows))]
    {
        SecureMemoryCapabilities {
            security: AllocationSecurity::Hardened,
            memory_locked: true,
            page_protected: true,
            guard_pages: true,
            dump_excluded: cfg!(target_os = "linux"),
            fork_excluded: cfg!(target_os = "linux"),
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        SecureMemoryCapabilities {
            security: AllocationSecurity::Weakened,
            memory_locked: false,
            page_protected: false,
            guard_pages: false,
            dump_excluded: false,
            fork_excluded: false,
        }
    }
}
