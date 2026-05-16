pub(crate) mod cache_options;
pub(crate) mod free_index;
pub(crate) mod free_slot;
pub(crate) mod memory_pressure;
pub(crate) mod page_cache;

use crate::secret_vec::SecureVec;
use crate::{Error, Result};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub(crate) trait Storage: Clone + std::fmt::Debug {
    fn len(&self) -> Result<u64>;
    fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>>;
    fn read_at_into(&self, offset: u64, out: &mut [u8]) -> Result<()>;
    fn append(&mut self, bytes: &[u8]) -> Result<u64>;
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<()>;

    fn read_at_secure(&self, offset: u64, len: usize) -> Result<SecureVec> {
        let mut out = SecureVec::new();
        out.resize_zeroed(len)?;
        out.with_mut_bytes(|bytes| self.read_at_into(offset, bytes))??;
        Ok(out)
    }

    fn read_all(&self) -> Result<Vec<u8>> {
        let len = self.len()?;
        if len > usize::MAX as u64 {
            return Err(Error::SecurityLimitExceeded(
                "vault is too large to materialize in memory".to_string(),
            ));
        }
        self.read_at(0, len as usize)
    }
}

#[derive(Debug, Clone)]
pub(crate) enum StorageBackend {
    Memory(MemoryStore),
    File(FileStore),
}

impl StorageBackend {
    pub(crate) fn memory(bytes: Vec<u8>) -> Self {
        Self::Memory(MemoryStore::new(bytes))
    }

    pub(crate) fn file(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self::File(FileStore::open(path)?))
    }

    pub(crate) fn create_file(path: impl AsRef<Path>, initial_bytes: &[u8]) -> Result<Self> {
        Ok(Self::File(FileStore::create(path, initial_bytes)?))
    }

    pub(crate) fn path(&self) -> Option<&Path> {
        match self {
            Self::Memory(_) => None,
            Self::File(store) => Some(store.path()),
        }
    }
}

impl Storage for StorageBackend {
    fn len(&self) -> Result<u64> {
        match self {
            Self::Memory(store) => store.len(),
            Self::File(store) => store.len(),
        }
    }

    fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        match self {
            Self::Memory(store) => store.read_at(offset, len),
            Self::File(store) => store.read_at(offset, len),
        }
    }

    fn read_at_into(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        match self {
            Self::Memory(store) => store.read_at_into(offset, out),
            Self::File(store) => store.read_at_into(offset, out),
        }
    }

    fn append(&mut self, bytes: &[u8]) -> Result<u64> {
        match self {
            Self::Memory(store) => store.append(bytes),
            Self::File(store) => store.append(bytes),
        }
    }

    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<()> {
        match self {
            Self::Memory(store) => store.write_at(offset, bytes),
            Self::File(store) => store.write_at(offset, bytes),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MemoryStore {
    bytes: Vec<u8>,
    #[cfg(test)]
    fail_append_after_successes: Option<usize>,
    #[cfg(test)]
    fail_next_write_at: Option<u64>,
}

impl MemoryStore {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            #[cfg(test)]
            fail_append_after_successes: None,
            #[cfg(test)]
            fail_next_write_at: None,
        }
    }

    #[cfg(test)]
    fn fail_append_after_successes(&mut self, successes: usize) {
        self.fail_append_after_successes = Some(successes);
    }

    #[cfg(test)]
    fn fail_next_write_at(&mut self, offset: u64) {
        self.fail_next_write_at = Some(offset);
    }

    #[cfg(test)]
    fn should_fail_append(&mut self) -> bool {
        let Some(remaining) = self.fail_append_after_successes.as_mut() else {
            return false;
        };
        if *remaining == 0 {
            self.fail_append_after_successes = None;
            true
        } else {
            *remaining -= 1;
            false
        }
    }

    #[cfg(test)]
    fn should_fail_write_at(&mut self, offset: u64) -> bool {
        if self.fail_next_write_at == Some(offset) {
            self.fail_next_write_at = None;
            true
        } else {
            false
        }
    }
}

impl Storage for MemoryStore {
    fn len(&self) -> Result<u64> {
        Ok(self.bytes.len() as u64)
    }

    fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let start = offset as usize;
        let end = start
            .checked_add(len)
            .ok_or_else(|| Error::Io("storage read offset overflow".to_string()))?;
        if end > self.bytes.len() {
            return Err(Error::Truncated);
        }
        Ok(self.bytes[start..end].to_vec())
    }

    fn read_at_into(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        let start = offset as usize;
        let end = start
            .checked_add(out.len())
            .ok_or_else(|| Error::Io("storage read offset overflow".to_string()))?;
        if end > self.bytes.len() {
            return Err(Error::Truncated);
        }
        out.copy_from_slice(&self.bytes[start..end]);
        Ok(())
    }

    fn append(&mut self, bytes: &[u8]) -> Result<u64> {
        #[cfg(test)]
        if self.should_fail_append() {
            return Err(Error::Io("injected storage append failure".to_string()));
        }
        let offset = self.bytes.len() as u64;
        self.bytes.extend_from_slice(bytes);
        Ok(offset)
    }

    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<()> {
        #[cfg(test)]
        if self.should_fail_write_at(offset) {
            return Err(Error::Io("injected storage write failure".to_string()));
        }
        let start = offset as usize;
        let end = start
            .checked_add(bytes.len())
            .ok_or_else(|| Error::Io("storage write offset overflow".to_string()))?;
        if end > self.bytes.len() {
            return Err(Error::Io("storage write beyond end".to_string()));
        }
        self.bytes[start..end].copy_from_slice(bytes);
        Ok(())
    }
}

#[cfg(test)]
impl StorageBackend {
    pub(crate) fn fail_memory_append_after_successes(&mut self, successes: usize) {
        match self {
            Self::Memory(store) => store.fail_append_after_successes(successes),
            Self::File(_) => panic!("failure injection is only available for memory storage"),
        }
    }

    pub(crate) fn fail_memory_next_write_at(&mut self, offset: u64) {
        match self {
            Self::Memory(store) => store.fail_next_write_at(offset),
            Self::File(_) => panic!("failure injection is only available for memory storage"),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FileStore {
    path: PathBuf,
    file: Arc<Mutex<std::fs::File>>,
}

impl FileStore {
    fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|err| Error::Io(format!("open {}: {err}", path.display())))?;
        Ok(Self {
            path,
            file: Arc::new(Mutex::new(file)),
        })
    }

    fn create(path: impl AsRef<Path>, initial_bytes: &[u8]) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| Error::Io(err.to_string()))?;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .map_err(|err| Error::Io(format!("create {}: {err}", path.display())))?;
        file.write_all(initial_bytes)
            .map_err(|err| Error::Io(format!("write {}: {err}", path.display())))?;
        file.sync_data()
            .map_err(|err| Error::Io(format!("sync {}: {err}", path.display())))?;
        Ok(Self {
            path,
            file: Arc::new(Mutex::new(file)),
        })
    }

    fn lock_file(&self) -> Result<std::sync::MutexGuard<'_, std::fs::File>> {
        self.file
            .lock()
            .map_err(|_| Error::Io("storage file lock poisoned".to_string()))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Storage for FileStore {
    fn len(&self) -> Result<u64> {
        Ok(fs::metadata(&self.path)
            .map_err(|err| Error::Io(format!("metadata {}: {err}", self.path.display())))?
            .len())
    }

    fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let mut out = vec![0; len];
        self.read_at_into(offset, &mut out)?;
        Ok(out)
    }

    fn read_at_into(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        let mut file = self.lock_file()?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|err| Error::Io(format!("seek {}: {err}", self.path.display())))?;
        file.read_exact(out).map_err(|err| {
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::Truncated
            } else {
                Error::Io(format!("read {}: {err}", self.path.display()))
            }
        })
    }

    fn append(&mut self, bytes: &[u8]) -> Result<u64> {
        let mut file = self.lock_file()?;
        let offset = file
            .seek(SeekFrom::End(0))
            .map_err(|err| Error::Io(format!("seek {}: {err}", self.path.display())))?;
        file.write_all(bytes)
            .map_err(|err| Error::Io(format!("append {}: {err}", self.path.display())))?;
        Ok(offset)
    }

    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<()> {
        let mut file = self.lock_file()?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|err| Error::Io(format!("seek {}: {err}", self.path.display())))?;
        file.write_all(bytes)
            .map_err(|err| Error::Io(format!("write {}: {err}", self.path.display())))
    }
}
