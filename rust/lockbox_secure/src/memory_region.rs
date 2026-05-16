#[cfg(unix)]
mod imp {
    use std::{ptr, sync::OnceLock};

    use zeroize::Zeroize;

    use crate::{
        capabilities::weakened_allocation_allowed,
        error::{Error, Result},
        memory_region::Protection,
    };

    pub struct MemoryRegion {
        inner: RegionInner,
    }

    enum RegionInner {
        Hardened(HardenedRegion),
        Weakened(WeakenedRegion),
    }

    struct HardenedRegion {
        base: *mut u8,
        data: *mut u8,
        data_size: usize,
        total_size: usize,
    }

    struct WeakenedRegion {
        data: Vec<u8>,
    }

    // SAFETY: MemoryRegion owns private memory. Access to protection changes
    // and deallocation is coordinated by the heap mutex.
    unsafe impl Send for MemoryRegion {}

    impl MemoryRegion {
        pub fn new(data_size: usize) -> Result<Self> {
            match HardenedRegion::new(data_size) {
                Ok(region) => Ok(Self {
                    inner: RegionInner::Hardened(region),
                }),
                Err(_err) if weakened_allocation_allowed() => {
                    WeakenedRegion::new(data_size).map(|region| Self {
                        inner: RegionInner::Weakened(region),
                    })
                }
                Err(Error::LockFailed) => Err(Error::WeakAllocationDisabled),
                Err(err) => Err(err),
            }
        }

        pub fn data_ptr(&self) -> *mut u8 {
            match &self.inner {
                RegionInner::Hardened(region) => region.data,
                RegionInner::Weakened(region) => region.data.as_ptr().cast_mut(),
            }
        }

        #[cfg(test)]
        pub(crate) fn guard_before_ptr_for_test(&self) -> *const u8 {
            match &self.inner {
                RegionInner::Hardened(region) => region.base.cast_const(),
                RegionInner::Weakened(region) => region.data.as_ptr(),
            }
        }

        #[cfg(test)]
        pub(crate) fn guard_after_ptr_for_test(&self) -> *const u8 {
            match &self.inner {
                RegionInner::Hardened(region) => {
                    region.data.wrapping_add(region.data_size).cast_const()
                }
                RegionInner::Weakened(region) => region.data.as_ptr(),
            }
        }

        pub fn protect_data_page(
            &mut self,
            page_index: usize,
            protection: Protection,
        ) -> Result<()> {
            match &mut self.inner {
                RegionInner::Hardened(region) => region.protect_data_page(page_index, protection),
                RegionInner::Weakened(_) => Ok(()),
            }
        }
    }

    impl HardenedRegion {
        fn new(data_size: usize) -> Result<Self> {
            let page_size = page_size();
            let data_size = round_to_page(data_size, page_size)?;
            let total_size = data_size
                .checked_add(page_size * 2)
                .ok_or(Error::CapacityOverflow)?;
            // SAFETY: mmap is called with a null address to request a fresh
            // private anonymous region. The returned pointer is checked before
            // being stored.
            let base = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    total_size,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            if base == libc::MAP_FAILED {
                return Err(Error::AllocationFailed);
            }
            let base = base.cast::<u8>();
            // SAFETY: data starts one page into the freshly mapped region.
            let data = unsafe { base.add(page_size) };
            if let Err(err) = protect(data, data_size, Protection::ReadWrite)
                .and_then(|_| lock_and_harden(data, data_size))
            {
                // SAFETY: base/total_size match the successful mmap call.
                unsafe {
                    libc::munmap(base.cast(), total_size);
                }
                return Err(err);
            }
            // SAFETY: data pages are currently writable and owned exclusively
            // by this MemoryRegion.
            unsafe {
                ptr::write_bytes(data, 0, data_size);
            }
            protect(data, data_size, Protection::None)?;
            Ok(Self {
                base,
                data,
                data_size,
                total_size,
            })
        }

        fn protect_data_page(&mut self, page_index: usize, protection: Protection) -> Result<()> {
            let page_size = page_size();
            let offset = page_index
                .checked_mul(page_size)
                .ok_or(Error::CapacityOverflow)?;
            if offset >= self.data_size {
                return Err(Error::ProtectionFailed);
            }
            // SAFETY: offset was bounds checked against the data mapping.
            let ptr = unsafe { self.data.add(offset) };
            protect(ptr, page_size, protection)
        }
    }

    impl Drop for HardenedRegion {
        fn drop(&mut self) {
            let _ = protect(self.data, self.data_size, Protection::ReadWrite);
            // SAFETY: data pages are writable and owned by this MemoryRegion.
            unsafe {
                ptr::write_bytes(self.data, 0, self.data_size);
                libc::munlock(self.data.cast(), self.data_size);
                libc::munmap(self.base.cast(), self.total_size);
            }
        }
    }

    impl WeakenedRegion {
        fn new(data_size: usize) -> Result<Self> {
            Ok(Self {
                data: vec![0; round_to_page(data_size, page_size())?],
            })
        }
    }

    impl Drop for WeakenedRegion {
        fn drop(&mut self) {
            self.data.zeroize();
        }
    }

    pub fn page_size() -> usize {
        static PAGE_SIZE: OnceLock<usize> = OnceLock::new();
        *PAGE_SIZE.get_or_init(|| {
            // SAFETY: sysconf has no Rust aliasing requirements.
            let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            if value <= 0 {
                4096
            } else {
                value as usize
            }
        })
    }

    fn lock_and_harden(data: *mut u8, data_size: usize) -> Result<()> {
        // SAFETY: data/data_size describe the accessible data pages in the
        // fresh mapping. mlock does not retain Rust references.
        if unsafe { libc::mlock(data.cast(), data_size) } != 0 {
            return Err(Error::LockFailed);
        }
        advise_no_dump_or_fork(data, data_size)
    }

    #[cfg(target_os = "linux")]
    fn advise_no_dump_or_fork(data: *mut u8, data_size: usize) -> Result<()> {
        // SAFETY: data/data_size describe this process mapping.
        let dont_dump = unsafe { libc::madvise(data.cast(), data_size, libc::MADV_DONTDUMP) };
        // SAFETY: data/data_size describe this process mapping.
        let dont_fork = unsafe { libc::madvise(data.cast(), data_size, libc::MADV_DONTFORK) };
        if dont_dump == 0 && dont_fork == 0 {
            Ok(())
        } else {
            Err(Error::ProtectionFailed)
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn advise_no_dump_or_fork(_data: *mut u8, _data_size: usize) -> Result<()> {
        Ok(())
    }

    fn protect(ptr: *mut u8, len: usize, protection: Protection) -> Result<()> {
        let prot = match protection {
            Protection::None => libc::PROT_NONE,
            Protection::Read => libc::PROT_READ,
            Protection::ReadWrite => libc::PROT_READ | libc::PROT_WRITE,
        };
        // SAFETY: callers pass page-aligned pointers and page-rounded lengths
        // belonging to this process.
        if unsafe { libc::mprotect(ptr.cast(), len, prot) } == 0 {
            Ok(())
        } else {
            Err(Error::ProtectionFailed)
        }
    }

    fn round_to_page(size: usize, page_size: usize) -> Result<usize> {
        size.checked_add(page_size - 1)
            .map(|value| value / page_size * page_size)
            .ok_or(Error::CapacityOverflow)
    }
}

#[cfg(windows)]
mod imp {
    use std::{mem::MaybeUninit, ptr, sync::OnceLock};

    use windows_sys::Win32::System::{
        Memory::{
            VirtualAlloc, VirtualFree, VirtualLock, VirtualProtect, VirtualUnlock, MEM_COMMIT,
            MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
        },
        SystemInformation::{GetSystemInfo, SYSTEM_INFO},
    };
    use zeroize::Zeroize;

    use crate::{
        capabilities::weakened_allocation_allowed,
        error::{Error, Result},
        memory_region::Protection,
    };

    pub struct MemoryRegion {
        inner: RegionInner,
    }

    enum RegionInner {
        Hardened(HardenedRegion),
        Weakened(WeakenedRegion),
    }

    struct HardenedRegion {
        base: *mut u8,
        data: *mut u8,
        data_size: usize,
    }

    struct WeakenedRegion {
        data: Vec<u8>,
    }

    // SAFETY: MemoryRegion owns private memory. Access to protection changes
    // and deallocation is coordinated by the heap mutex.
    unsafe impl Send for MemoryRegion {}

    impl MemoryRegion {
        pub fn new(data_size: usize) -> Result<Self> {
            match HardenedRegion::new(data_size) {
                Ok(region) => Ok(Self {
                    inner: RegionInner::Hardened(region),
                }),
                Err(_err) if weakened_allocation_allowed() => {
                    WeakenedRegion::new(data_size).map(|region| Self {
                        inner: RegionInner::Weakened(region),
                    })
                }
                Err(Error::LockFailed) => Err(Error::WeakAllocationDisabled),
                Err(err) => Err(err),
            }
        }

        pub fn data_ptr(&self) -> *mut u8 {
            match &self.inner {
                RegionInner::Hardened(region) => region.data,
                RegionInner::Weakened(region) => region.data.as_ptr().cast_mut(),
            }
        }

        #[cfg(test)]
        pub(crate) fn guard_before_ptr_for_test(&self) -> *const u8 {
            match &self.inner {
                RegionInner::Hardened(region) => region.base.cast_const(),
                RegionInner::Weakened(region) => region.data.as_ptr(),
            }
        }

        #[cfg(test)]
        pub(crate) fn guard_after_ptr_for_test(&self) -> *const u8 {
            match &self.inner {
                RegionInner::Hardened(region) => {
                    region.data.wrapping_add(region.data_size).cast_const()
                }
                RegionInner::Weakened(region) => region.data.as_ptr(),
            }
        }

        pub fn protect_data_page(
            &mut self,
            page_index: usize,
            protection: Protection,
        ) -> Result<()> {
            match &mut self.inner {
                RegionInner::Hardened(region) => region.protect_data_page(page_index, protection),
                RegionInner::Weakened(_) => Ok(()),
            }
        }
    }

    impl HardenedRegion {
        fn new(data_size: usize) -> Result<Self> {
            let page_size = page_size();
            let data_size = round_to_page(data_size, page_size)?;
            let total_size = data_size
                .checked_add(page_size * 2)
                .ok_or(Error::CapacityOverflow)?;
            // SAFETY: VirtualAlloc is asked for a fresh private region.
            let base = unsafe {
                VirtualAlloc(
                    ptr::null_mut(),
                    total_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_NOACCESS,
                )
            };
            if base.is_null() {
                return Err(Error::AllocationFailed);
            }
            let base = base.cast::<u8>();
            // SAFETY: data starts one page into the fresh allocation.
            let data = unsafe { base.add(page_size) };
            if let Err(err) = protect(data, data_size, Protection::ReadWrite)
                .and_then(|_| lock_region(data, data_size))
            {
                // SAFETY: base matches the successful VirtualAlloc call.
                unsafe {
                    VirtualFree(base.cast(), 0, MEM_RELEASE);
                }
                return Err(err);
            }
            // SAFETY: data pages are writable and exclusively owned.
            unsafe {
                ptr::write_bytes(data, 0, data_size);
            }
            protect(data, data_size, Protection::None)?;
            Ok(Self {
                base,
                data,
                data_size,
            })
        }

        fn protect_data_page(&mut self, page_index: usize, protection: Protection) -> Result<()> {
            let page_size = page_size();
            let offset = page_index
                .checked_mul(page_size)
                .ok_or(Error::CapacityOverflow)?;
            if offset >= self.data_size {
                return Err(Error::ProtectionFailed);
            }
            // SAFETY: offset was bounds checked against the data mapping.
            let ptr = unsafe { self.data.add(offset) };
            protect(ptr, page_size, protection)
        }
    }

    impl Drop for HardenedRegion {
        fn drop(&mut self) {
            let _ = protect(self.data, self.data_size, Protection::ReadWrite);
            // SAFETY: data pages are writable and owned by this MemoryRegion.
            unsafe {
                ptr::write_bytes(self.data, 0, self.data_size);
                VirtualUnlock(self.data.cast(), self.data_size);
                VirtualFree(self.base.cast(), 0, MEM_RELEASE);
            }
        }
    }

    impl WeakenedRegion {
        fn new(data_size: usize) -> Result<Self> {
            Ok(Self {
                data: vec![0; round_to_page(data_size, page_size())?],
            })
        }
    }

    impl Drop for WeakenedRegion {
        fn drop(&mut self) {
            self.data.zeroize();
        }
    }

    pub fn page_size() -> usize {
        static PAGE_SIZE: OnceLock<usize> = OnceLock::new();
        *PAGE_SIZE.get_or_init(|| {
            let mut info = MaybeUninit::<SYSTEM_INFO>::uninit();
            // SAFETY: GetSystemInfo initializes the provided SYSTEM_INFO.
            unsafe {
                GetSystemInfo(info.as_mut_ptr());
                info.assume_init().dwPageSize as usize
            }
        })
    }

    fn lock_region(data: *mut u8, data_size: usize) -> Result<()> {
        // SAFETY: data/data_size describe committed writable pages.
        if unsafe { VirtualLock(data.cast(), data_size) } == 0 {
            Err(Error::LockFailed)
        } else {
            Ok(())
        }
    }

    fn protect(ptr: *mut u8, len: usize, protection: Protection) -> Result<()> {
        let protect = match protection {
            Protection::None => PAGE_NOACCESS,
            Protection::Read => PAGE_READONLY,
            Protection::ReadWrite => PAGE_READWRITE,
        };
        let mut old = 0;
        // SAFETY: callers pass page-aligned pointers and page-rounded lengths
        // belonging to this process.
        if unsafe { VirtualProtect(ptr.cast(), len, protect, &mut old) } != 0 {
            Ok(())
        } else {
            Err(Error::ProtectionFailed)
        }
    }

    fn round_to_page(size: usize, page_size: usize) -> Result<usize> {
        size.checked_add(page_size - 1)
            .map(|value| value / page_size * page_size)
            .ok_or(Error::CapacityOverflow)
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use zeroize::Zeroize;

    use crate::{
        capabilities::weakened_allocation_allowed,
        error::{Error, Result},
        memory_region::Protection,
    };

    pub struct MemoryRegion {
        data: Vec<u8>,
    }

    impl MemoryRegion {
        pub fn new(data_size: usize) -> Result<Self> {
            if !weakened_allocation_allowed() {
                return Err(Error::WeakAllocationDisabled);
            }
            Ok(Self {
                data: vec![0; data_size],
            })
        }

        pub fn data_ptr(&self) -> *mut u8 {
            self.data.as_ptr().cast_mut()
        }

        #[cfg(all(test, any(unix, windows)))]
        pub(crate) fn guard_before_ptr_for_test(&self) -> *const u8 {
            self.data.as_ptr()
        }

        #[cfg(all(test, any(unix, windows)))]
        pub(crate) fn guard_after_ptr_for_test(&self) -> *const u8 {
            self.data.as_ptr()
        }

        pub fn protect_data_page(
            &mut self,
            _page_index: usize,
            _protection: Protection,
        ) -> Result<()> {
            Ok(())
        }
    }

    impl Drop for MemoryRegion {
        fn drop(&mut self) {
            self.data.zeroize();
        }
    }

    pub fn page_size() -> usize {
        4096
    }
}

pub enum Protection {
    None,
    Read,
    ReadWrite,
}

pub use imp::{page_size, MemoryRegion};
