use crate::secret_vec::{secure_read_access, SecureVec};
use crate::{Error, Result};

pub(crate) trait PageBuffer: Sized {
    fn truncate(&mut self, len: usize) -> Result<()>;
    fn try_clone_range(&self, offset: usize, len: usize) -> Result<Self>;
    fn with_bytes<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> Result<R>;
    fn with_mut_bytes<R, F: FnOnce(&mut [u8]) -> R>(&mut self, f: F) -> Result<R>;
}

impl PageBuffer for Vec<u8> {
    fn truncate(&mut self, len: usize) -> Result<()> {
        Vec::truncate(self, len);
        Ok(())
    }

    fn try_clone_range(&self, offset: usize, len: usize) -> Result<Self> {
        let end = offset.checked_add(len).ok_or(Error::CorruptRecord)?;
        let range = self.get(offset..end).ok_or(Error::CorruptRecord)?;
        Ok(range.to_vec())
    }

    fn with_bytes<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> Result<R> {
        Ok(f(self))
    }

    fn with_mut_bytes<R, F: FnOnce(&mut [u8]) -> R>(&mut self, f: F) -> Result<R> {
        Ok(f(self))
    }
}

impl PageBuffer for SecureVec {
    fn truncate(&mut self, len: usize) -> Result<()> {
        SecureVec::truncate(self, len)?;
        Ok(())
    }

    fn try_clone_range(&self, offset: usize, len: usize) -> Result<Self> {
        Ok(SecureVec::try_clone_range(self, offset, len)?)
    }

    fn with_bytes<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> Result<R> {
        secure_read_access(|access| self.with_bytes_in(access, f)).map_err(Into::into)
    }

    fn with_mut_bytes<R, F: FnOnce(&mut [u8]) -> R>(&mut self, f: F) -> Result<R> {
        SecureVec::with_mut_bytes(self, f).map_err(Into::into)
    }
}
