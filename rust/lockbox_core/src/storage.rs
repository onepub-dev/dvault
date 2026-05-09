use crate::{Error, Result};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub(crate) trait Storage: Clone + std::fmt::Debug {
    fn len(&self) -> Result<u64>;
    fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>>;
    fn append(&mut self, bytes: &[u8]) -> Result<u64>;
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<()>;

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
}

impl MemoryStore {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
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

    fn append(&mut self, bytes: &[u8]) -> Result<u64> {
        let offset = self.bytes.len() as u64;
        self.bytes.extend_from_slice(bytes);
        Ok(offset)
    }

    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<()> {
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
            .map_err(|err| Error::Io(err.to_string()))?;
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
            .map_err(|err| Error::Io(err.to_string()))?;
        file.write_all(initial_bytes)
            .map_err(|err| Error::Io(err.to_string()))?;
        file.sync_data().map_err(|err| Error::Io(err.to_string()))?;
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
}

impl Storage for FileStore {
    fn len(&self) -> Result<u64> {
        Ok(fs::metadata(&self.path)
            .map_err(|err| Error::Io(err.to_string()))?
            .len())
    }

    fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let mut file = self.lock_file()?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|err| Error::Io(err.to_string()))?;
        let mut out = vec![0; len];
        file.read_exact(&mut out).map_err(|err| {
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::Truncated
            } else {
                Error::Io(err.to_string())
            }
        })?;
        Ok(out)
    }

    fn append(&mut self, bytes: &[u8]) -> Result<u64> {
        let mut file = self.lock_file()?;
        let offset = file
            .seek(SeekFrom::End(0))
            .map_err(|err| Error::Io(err.to_string()))?;
        file.write_all(bytes)
            .map_err(|err| Error::Io(err.to_string()))?;
        Ok(offset)
    }

    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<()> {
        let mut file = self.lock_file()?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|err| Error::Io(err.to_string()))?;
        file.write_all(bytes)
            .map_err(|err| Error::Io(err.to_string()))
    }
}
