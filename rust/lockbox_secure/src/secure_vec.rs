use std::fmt;

use zeroize::Zeroize;

use crate::{
    allocation::Allocation,
    error::{Error, Result},
    secure_access::{defer_free_until_read_access_exits, read_access, SecureReadAccess},
    secure_heap::{lock_secure_heap, lock_secure_heap_for_mutation},
};

pub struct SecureVec {
    allocation: Option<Allocation>,
    len: usize,
}

impl SecureVec {
    pub fn new() -> Self {
        Self {
            allocation: None,
            len: 0,
        }
    }

    pub fn try_from_vec(mut bytes: Vec<u8>) -> Result<Self> {
        let result = Self::try_from_slice(&bytes);
        bytes.zeroize();
        result
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self> {
        let mut secure = Self::new();
        if !bytes.is_empty() {
            secure.replace_from_slice(bytes)?;
        }
        Ok(secure)
    }

    pub fn try_clone(&self) -> Result<Self> {
        let Some(allocation) = self.allocation else {
            return Ok(Self::new());
        };
        let mut pool = lock_secure_heap_for_mutation()?;
        let new_allocation = pool.clone_allocation(allocation, self.len)?;
        Ok(Self {
            allocation: Some(new_allocation),
            len: self.len,
        })
    }

    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R> {
        read_access(|access| self.with_bytes_in(access, f))
    }

    pub fn with_bytes_in<R>(
        &self,
        access: &SecureReadAccess<'_>,
        f: impl FnOnce(&[u8]) -> R,
    ) -> Result<R> {
        match self.allocation {
            Some(allocation) if self.len != 0 => {
                let slice = access.slice(allocation, self.len)?;
                Ok(f(slice))
            }
            _ => Ok(f(&[])),
        }
    }

    pub fn try_push(&mut self, byte: u8) -> Result<()> {
        self.ensure_capacity(1)?;
        let allocation = self.allocation.ok_or(Error::CorruptAllocation)?;
        let mut pool = lock_secure_heap_for_mutation()?;
        pool.write(allocation, self.len, &[byte])?;
        self.len += 1;
        Ok(())
    }

    pub fn try_extend_from_slice(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.ensure_capacity(bytes.len())?;
        let allocation = self.allocation.ok_or(Error::CorruptAllocation)?;
        let mut pool = lock_secure_heap_for_mutation()?;
        pool.write(allocation, self.len, bytes)?;
        self.len += bytes.len();
        Ok(())
    }

    pub fn try_extend_from_secure(&mut self, source: &Self) -> Result<()> {
        self.try_extend_secure_range(source, 0, source.len)
    }

    pub fn try_extend_secure_range(
        &mut self,
        source: &Self,
        offset: usize,
        len: usize,
    ) -> Result<()> {
        let source_allocation = source.allocation.ok_or(Error::CorruptAllocation)?;
        let source_end = offset.checked_add(len).ok_or(Error::CapacityOverflow)?;
        if source_end > source.len {
            return Err(Error::CapacityOverflow);
        }
        if len == 0 {
            return Ok(());
        }
        self.ensure_capacity(len)?;
        let destination_allocation = self.allocation.ok_or(Error::CorruptAllocation)?;
        let old_len = self.len;
        let mut pool = lock_secure_heap_for_mutation()?;
        pool.copy_range(
            source_allocation,
            offset,
            destination_allocation,
            old_len,
            len,
        )?;
        self.len += len;
        Ok(())
    }

    pub fn try_clone_range(&self, offset: usize, len: usize) -> Result<Self> {
        let end = offset.checked_add(len).ok_or(Error::CapacityOverflow)?;
        if end > self.len {
            return Err(Error::CapacityOverflow);
        }
        let mut out = Self::new();
        out.try_extend_secure_range(self, offset, len)?;
        Ok(out)
    }

    pub fn resize_zeroed(&mut self, len: usize) -> Result<()> {
        if len <= self.len {
            if len < self.len {
                if let Some(allocation) = self.allocation {
                    let mut pool = lock_secure_heap_for_mutation()?;
                    pool.zero_range(allocation, len, self.len - len)?;
                }
            }
            self.len = len;
            return Ok(());
        }

        let old_len = self.len;
        self.ensure_capacity(len - self.len)?;
        let allocation = self.allocation.ok_or(Error::CorruptAllocation)?;
        let mut pool = lock_secure_heap_for_mutation()?;
        pool.zero_range(allocation, old_len, len - old_len)?;
        self.len = len;
        Ok(())
    }

    pub fn truncate(&mut self, len: usize) -> Result<()> {
        if len >= self.len {
            return Ok(());
        }
        if let Some(allocation) = self.allocation {
            let mut pool = lock_secure_heap_for_mutation()?;
            pool.zero_range(allocation, len, self.len - len)?;
        }
        self.len = len;
        Ok(())
    }

    pub fn with_mut_bytes<R>(&mut self, f: impl FnOnce(&mut [u8]) -> R) -> Result<R> {
        match self.allocation {
            Some(allocation) if self.len != 0 => {
                let mut pool = lock_secure_heap_for_mutation()?;
                pool.with_mut_slice(allocation, self.len, f)
            }
            _ => {
                let mut empty = [];
                Ok(f(&mut empty))
            }
        }
    }

    pub fn try_pop(&mut self) -> Result<Option<u8>> {
        if self.len == 0 {
            return Ok(None);
        }
        let allocation = self.allocation.ok_or(Error::CorruptAllocation)?;
        let offset = self.len - 1;
        let mut pool = lock_secure_heap_for_mutation()?;
        let byte = pool.read_byte(allocation, offset)?;
        pool.zero_range(allocation, offset, 1)?;
        self.len = offset;
        Ok(Some(byte))
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn zeroize(&mut self) -> Result<()> {
        if let Some(allocation) = self.allocation {
            let mut pool = lock_secure_heap_for_mutation()?;
            pool.zero_range(allocation, 0, allocation.capacity)?;
        }
        self.len = 0;
        Ok(())
    }

    fn ensure_capacity(&mut self, additional: usize) -> Result<()> {
        let needed = self
            .len
            .checked_add(additional)
            .ok_or(Error::CapacityOverflow)?;
        let capacity = self.allocation.map_or(0, |allocation| allocation.capacity);
        if needed <= capacity {
            return Ok(());
        }

        let mut next_capacity = capacity.max(64);
        while next_capacity < needed {
            next_capacity = next_capacity
                .checked_mul(2)
                .ok_or(Error::CapacityOverflow)?;
        }
        self.reallocate(next_capacity)
    }

    fn reallocate(&mut self, capacity: usize) -> Result<()> {
        let mut pool = lock_secure_heap_for_mutation()?;
        let new_allocation = pool.allocate(capacity)?;
        if let Some(old_allocation) = self.allocation {
            if let Err(err) = pool.copy(old_allocation, new_allocation, self.len) {
                let _ = pool.free(new_allocation);
                return Err(err);
            }
            pool.free(old_allocation)?;
        }
        self.allocation = Some(new_allocation);
        Ok(())
    }

    fn replace_from_slice(&mut self, bytes: &[u8]) -> Result<()> {
        let mut pool = lock_secure_heap_for_mutation()?;
        let allocation = pool.allocate(bytes.len())?;
        if let Err(err) = pool.write(allocation, 0, bytes) {
            let _ = pool.free(allocation);
            return Err(err);
        }
        self.allocation = Some(allocation);
        self.len = bytes.len();
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn capacity_for_test(&self) -> usize {
        self.allocation.map_or(0, |allocation| allocation.capacity)
    }

    #[cfg(test)]
    pub(crate) fn canaries_intact_for_test(&self) -> bool {
        let Some(allocation) = self.allocation else {
            return true;
        };
        lock_secure_heap().canaries_intact_for_test(allocation)
    }

    #[cfg(test)]
    pub(crate) fn corrupt_after_canary_for_test(&self) {
        let allocation = self.allocation.expect("secure bytes must be allocated");
        lock_secure_heap().corrupt_after_canary_for_test(allocation);
    }

    #[cfg(test)]
    pub(crate) fn restore_canaries_for_test(&self) {
        if let Some(allocation) = self.allocation {
            lock_secure_heap().restore_canaries_for_test(allocation);
        }
    }

    #[cfg(all(test, any(unix, windows)))]
    pub(crate) fn protected_ptr_for_test(&self) -> *const u8 {
        self.with_bytes(|bytes| bytes.as_ptr())
            .expect("test protected pointer")
    }
}

impl TryFrom<Vec<u8>> for SecureVec {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        Self::try_from_vec(bytes)
    }
}

impl TryFrom<&[u8]> for SecureVec {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::try_from_slice(bytes)
    }
}

impl Default for SecureVec {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for SecureVec {
    fn eq(&self, other: &Self) -> bool {
        read_access(|access| {
            self.with_bytes_in(access, |left| {
                other
                    .with_bytes_in(access, |right| left == right)
                    .unwrap_or(false)
            })
            .unwrap_or(false)
        })
    }
}

impl Eq for SecureVec {}

impl fmt::Debug for SecureVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureVec")
            .field("len", &self.len)
            .field("redacted", &true)
            .finish()
    }
}

impl Drop for SecureVec {
    fn drop(&mut self) {
        if let Some(allocation) = self.allocation.take() {
            if defer_free_until_read_access_exits(allocation) {
                return;
            }
            let mut pool = lock_secure_heap();
            let _ = pool.free(allocation);
        }
    }
}
