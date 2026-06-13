use std::{cell::RefCell, marker::PhantomData, sync::MutexGuard};

use crate::{
    allocation::Allocation,
    canary::{canary_offset, expected_canary, CanarySide, CANARY_LEN},
    error::{Error, Result},
    memory_region,
    page_permission::PagePermission,
    secure_heap::{lock_secure_heap, SecureHeap},
    secure_string::SecureString,
    secure_vec::SecureVec,
};

thread_local! {
    static ACTIVE_READ_ACCESS: RefCell<Option<SecureReadAccess<'static>>> = const {
        RefCell::new(None)
    };
    static PENDING_READ_DROPS: RefCell<Vec<Allocation>> = const {
        RefCell::new(Vec::new())
    };
}

pub fn read_access<R>(f: impl FnOnce(&SecureReadAccess<'_>) -> R) -> R {
    ACTIVE_READ_ACCESS.with(|active| {
        if active.borrow().is_some() {
            let borrowed = active.borrow();
            let Some(access) = borrowed.as_ref() else {
                std::process::abort();
            };
            return f(access);
        }

        *active.borrow_mut() = Some(SecureReadAccess {
            pool: RefCell::new(lock_secure_heap()),
            touched: RefCell::new(Vec::new()),
            _not_send: PhantomData,
        });

        struct ReadAccessCleanup;
        impl Drop for ReadAccessCleanup {
            fn drop(&mut self) {
                ACTIVE_READ_ACCESS.with(|active| {
                    if let Some(access) = active.borrow_mut().take() {
                        access.finish();
                    }
                });
            }
        }
        let _cleanup = ReadAccessCleanup;

        {
            let borrowed = active.borrow();
            let Some(access) = borrowed.as_ref() else {
                std::process::abort();
            };
            f(access)
        }
    })
}

pub(crate) fn read_access_is_active() -> bool {
    ACTIVE_READ_ACCESS.with(|active| active.borrow().is_some())
}

pub(crate) fn defer_free_until_read_access_exits(allocation: Allocation) -> bool {
    ACTIVE_READ_ACCESS.with(|active| {
        if active.borrow().is_none() {
            return false;
        }
        PENDING_READ_DROPS.with(|pending| pending.borrow_mut().push(allocation));
        true
    })
}

pub struct SecureReadAccess<'a> {
    pool: RefCell<MutexGuard<'a, SecureHeap>>,
    touched: RefCell<Vec<TouchedPage>>,
    _not_send: PhantomData<*mut ()>,
}

impl SecureReadAccess<'_> {
    pub fn with_bytes<R>(&self, value: &SecureVec, f: impl FnOnce(&[u8]) -> R) -> Result<R> {
        value.with_bytes_in(self, f)
    }

    pub fn with_str<R>(&self, value: &SecureString, f: impl FnOnce(&str) -> R) -> Result<R> {
        value.with_str_in(self, f)
    }

    pub(crate) fn slice(&self, allocation: Allocation, len: usize) -> Result<&[u8]> {
        let ptr = {
            let pool = self.pool.borrow();
            pool.validate_allocation(allocation)?;
            pool.ptr_for(allocation)
        };
        if len == 0 {
            return Ok(&[]);
        }
        self.unprotect_allocation(allocation)?;
        self.check_canaries(allocation, ptr)?;
        // SAFETY: the allocation is live, the requested range was validated by
        // construction of `SecureVec`, and the access guard keeps the page
        // readable until the returned slice's closure has completed.
        Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
    }

    fn check_canaries(&self, allocation: Allocation, user_ptr: *const u8) -> Result<()> {
        self.check_canary(allocation, user_ptr, CanarySide::Before)?;
        self.check_canary(allocation, user_ptr, CanarySide::After)
    }

    fn check_canary(
        &self,
        allocation: Allocation,
        user_ptr: *const u8,
        side: CanarySide,
    ) -> Result<()> {
        let ptr = match side {
            CanarySide::Before => user_ptr.wrapping_sub(CANARY_LEN),
            CanarySide::After => user_ptr.wrapping_add(allocation.capacity),
        };
        let mut actual = [0u8; CANARY_LEN];
        // SAFETY: `unprotect_allocation` made the allocation canary pages
        // readable before this copy.
        unsafe {
            std::ptr::copy_nonoverlapping(ptr, actual.as_mut_ptr(), CANARY_LEN);
        }
        if actual == expected_canary(allocation, side) {
            Ok(())
        } else {
            Err(Error::CorruptAllocation)
        }
    }

    fn unprotect_allocation(&self, allocation: Allocation) -> Result<()> {
        let start = canary_offset(allocation, CanarySide::Before);
        let end = canary_offset(allocation, CanarySide::After)
            .checked_add(CANARY_LEN)
            .ok_or(Error::CapacityOverflow)?;
        self.unprotect_absolute_range(allocation.arena, start, end - start, PagePermission::Read)
    }

    fn unprotect_absolute_range(
        &self,
        arena_index: usize,
        offset: usize,
        len: usize,
        permission: PagePermission,
    ) -> Result<()> {
        let page_size = memory_region::page_size();
        let start = offset / page_size;
        let end = (offset + len).div_ceil(page_size);
        for page in start..end {
            self.unprotect_page(arena_index, page, permission)?;
        }
        Ok(())
    }

    fn unprotect_page(
        &self,
        arena_index: usize,
        page_index: usize,
        permission: PagePermission,
    ) -> Result<()> {
        let mut touched_pages = self.touched.borrow_mut();
        if let Some(touched) = touched_pages
            .iter_mut()
            .find(|touched| touched.arena == arena_index && touched.page == page_index)
        {
            if touched.permission == PagePermission::Read && permission == PagePermission::Write {
                self.pool.borrow_mut().arenas[arena_index]
                    .protect_page(page_index, PagePermission::Write)?;
                touched.permission = PagePermission::Write;
            }
            return Ok(());
        }

        self.pool.borrow_mut().arenas[arena_index].protect_page(page_index, permission)?;
        touched_pages.push(TouchedPage {
            arena: arena_index,
            page: page_index,
            permission,
        });
        Ok(())
    }
}

impl Drop for SecureReadAccess<'_> {
    fn drop(&mut self) {
        self.reprotect_touched_pages();
    }
}

impl SecureReadAccess<'_> {
    fn finish(mut self) {
        self.reprotect_touched_pages();
        self.free_deferred_drops();
    }

    fn reprotect_touched_pages(&mut self) {
        let pool = self.pool.get_mut();
        for touched in self.touched.get_mut().iter().rev() {
            let _ = pool.arenas[touched.arena].protect_page_none(touched.page);
        }
        self.touched.get_mut().clear();
    }

    fn free_deferred_drops(&mut self) {
        let pending = PENDING_READ_DROPS.with(|pending| {
            let mut pending = pending.borrow_mut();
            pending.drain(..).collect::<Vec<_>>()
        });
        let pool = self.pool.get_mut();
        for allocation in pending {
            let _ = pool.free(allocation);
        }
    }
}

struct TouchedPage {
    arena: usize,
    page: usize,
    permission: PagePermission,
}
