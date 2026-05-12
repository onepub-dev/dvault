use lockbox_core::{Error, Lockbox, LockboxCreate, LockboxId, LockboxUnlock, Result};
pub use lockbox_core::{SecretBytes, SecretString};
use std::io;
use std::path::Path;

mod key_format;
mod vault_directory;

pub use key_format::{
    export_private_key, export_public_key, import_private_key, import_public_key, KeyFormat,
};
pub use vault_directory::{
    default_vault_dir, default_vault_path, StoredTrustedRecipient, VaultDirectory,
};

const PROTOCOL_VERSION: &str = "LBX1";
const MAX_REQUEST_BYTES: usize = 128 * 1024;

#[cfg(unix)]
mod unix;

#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as platform;

#[cfg(windows)]
use windows as platform;

#[cfg(not(any(unix, windows)))]
mod platform {
    use lockbox_core::LockboxId;
    use std::io;

    pub(crate) fn serve_agent() -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "lockbox agent is not supported on this platform",
        ))
    }

    pub(crate) fn verify_agent_transport_security() -> io::Result<()> {
        Ok(())
    }

    pub(crate) fn get(_lockbox_id: LockboxId) -> io::Result<Option<Vec<u8>>> {
        Ok(None)
    }

    pub(crate) fn put(_lockbox_id: LockboxId, _key: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "lockbox agent is not supported on this platform",
        ))
    }

    pub(crate) fn forget(_lockbox_id: LockboxId) -> io::Result<()> {
        Ok(())
    }

    pub(crate) fn forget_all() -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AgentClient;

#[derive(Debug, Clone, Copy, Default)]
pub struct NoopStore;

pub trait ContentKeyStore {
    fn get_content_key(&self, lockbox_id: LockboxId) -> Result<Option<Vec<u8>>>;
    fn put_content_key(&self, lockbox_id: LockboxId, key: &[u8]) -> Result<()>;
    fn forget_content_key(&self, lockbox_id: LockboxId) -> Result<()>;
    fn forget_all_content_keys(&self) -> Result<()>;
}

pub type LocalVault = Vault<AgentClient>;

pub fn local_vault() -> LocalVault {
    Vault::new(AgentClient)
}

#[derive(Debug, Clone)]
pub struct Vault<S = AgentClient> {
    store: S,
}

impl<S> Vault<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &S {
        &self.store
    }
}

impl<S: ContentKeyStore> Vault<S> {
    pub fn create_lockbox_with_password(
        &self,
        path: impl AsRef<Path>,
        password: &SecretString,
    ) -> Result<Lockbox> {
        self.create_lockbox(
            path,
            LockboxCreate::Password(password.expose_bytes().to_vec()),
        )
    }

    pub fn unlock_lockbox_with_password(
        &self,
        path: impl AsRef<Path>,
        password: &SecretString,
    ) -> Result<Lockbox> {
        self.unlock_lockbox(
            path,
            LockboxUnlock::Password(password.expose_bytes().to_vec()),
        )
    }

    pub fn create_lockbox(&self, path: impl AsRef<Path>, method: LockboxCreate) -> Result<Lockbox> {
        let path = path.as_ref();
        match method {
            LockboxCreate::RawKey(key) => {
                let lockbox = Lockbox::create_file(path, LockboxCreate::RawKey(key.clone()))?;
                self.store.put_content_key(lockbox.lockbox_id(), &key)?;
                Ok(lockbox)
            }
            LockboxCreate::Password(password) => {
                let lockbox =
                    Lockbox::create_file(path, LockboxCreate::Password(password.clone()))?;
                let unlocked = Lockbox::unlock_path_with_password(path, &password)?;
                if let Err(err) = self
                    .store
                    .put_content_key(unlocked.lockbox_id, unlocked.key())
                {
                    if !matches!(err, Error::Io(_)) {
                        return Err(err);
                    }
                }
                Ok(lockbox)
            }
            LockboxCreate::RecipientKey(recipient) => {
                Lockbox::create_file(path, LockboxCreate::RecipientKey(recipient))
            }
            LockboxCreate::RecipientKeyFile(key_path) => {
                Lockbox::create_file(path, LockboxCreate::RecipientKeyFile(key_path))
            }
        }
    }

    pub fn open_lockbox(&self, path: impl AsRef<Path>) -> Result<Lockbox> {
        let path = path.as_ref();
        let lockbox_id = Lockbox::read_lockbox_id_path(path)?;
        let Some(key) = self.store.get_content_key(lockbox_id)? else {
            return Err(Error::InvalidKey);
        };
        Lockbox::open_file(path, LockboxUnlock::RawKey(key))
    }

    pub fn unlock_lockbox(&self, path: impl AsRef<Path>, method: LockboxUnlock) -> Result<Lockbox> {
        let path = path.as_ref();
        match method {
            LockboxUnlock::RawKey(key) => {
                let lockbox = Lockbox::open_file(path, LockboxUnlock::RawKey(key.clone()))?;
                self.store.put_content_key(lockbox.lockbox_id(), &key)?;
                Ok(lockbox)
            }
            LockboxUnlock::Password(password) => {
                let unlocked = unlock_path_or_backup_with_password(path, &password)?;
                self.store
                    .put_content_key(unlocked.lockbox_id, unlocked.key())?;
                Lockbox::open_file(path, LockboxUnlock::RawKey(unlocked.into_key_bytes()))
            }
            LockboxUnlock::RecipientKey(recipient) => {
                let unlocked = unlock_path_or_backup_with_recipient(path, &recipient)?;
                self.store
                    .put_content_key(unlocked.lockbox_id, unlocked.key())?;
                Lockbox::open_file(path, LockboxUnlock::RawKey(unlocked.into_key_bytes()))
            }
            LockboxUnlock::RecipientKeyFile(key_path) => {
                Lockbox::open_file(path, LockboxUnlock::RecipientKeyFile(key_path))
            }
        }
    }

    pub fn lock_lockbox(&self, path: impl AsRef<Path>) -> Result<()> {
        let lockbox_id = Lockbox::read_lockbox_id_path(path)?;
        self.store.forget_content_key(lockbox_id)
    }

    pub fn lock_all(&self) -> Result<()> {
        self.store.forget_all_content_keys()
    }
}

fn unlock_path_or_backup_with_password(
    path: &Path,
    password: &[u8],
) -> Result<lockbox_core::UnlockedContentKey> {
    match Lockbox::unlock_path_with_password(path, password) {
        Ok(unlocked) => Ok(unlocked),
        Err(primary_err) => {
            let lockbox_id =
                Lockbox::read_lockbox_id_path(path).map_err(|_| primary_err.clone())?;
            let vault_password = vault_password_from_env().map_err(|_| primary_err.clone())?;
            let backup = VaultDirectory::open_default(&vault_password)
                .and_then(|vault| vault.load_key_directory_backup(lockbox_id))
                .map_err(|_| primary_err.clone())?;
            Lockbox::unlock_key_directory_backup_with_password(&backup, password)
                .map_err(|_| primary_err)
        }
    }
}

fn unlock_path_or_backup_with_recipient(
    path: &Path,
    recipient: &lockbox_core::MlKemKeyPair,
) -> Result<lockbox_core::UnlockedContentKey> {
    match Lockbox::unlock_path_with_recipient(path, recipient) {
        Ok(unlocked) => Ok(unlocked),
        Err(primary_err) => {
            let lockbox_id =
                Lockbox::read_lockbox_id_path(path).map_err(|_| primary_err.clone())?;
            let vault_password = vault_password_from_env().map_err(|_| primary_err.clone())?;
            let backup = VaultDirectory::open_default(&vault_password)
                .and_then(|vault| vault.load_key_directory_backup(lockbox_id))
                .map_err(|_| primary_err.clone())?;
            Lockbox::unlock_key_directory_backup_with_recipient(&backup, recipient)
                .map_err(|_| primary_err)
        }
    }
}

fn vault_password_from_env() -> Result<SecretString> {
    std::env::var("LOCKBOX_VAULT_PASSWORD")
        .map(|password| SecretString::from_bytes(password.into_bytes()))
        .map_err(|_| Error::InvalidKey)
}

impl ContentKeyStore for AgentClient {
    fn get_content_key(&self, lockbox_id: LockboxId) -> Result<Option<Vec<u8>>> {
        get(lockbox_id).map_err(io_to_core)
    }

    fn put_content_key(&self, lockbox_id: LockboxId, key: &[u8]) -> Result<()> {
        put(lockbox_id, key).map_err(io_to_core)
    }

    fn forget_content_key(&self, lockbox_id: LockboxId) -> Result<()> {
        forget(lockbox_id).map_err(io_to_core)
    }

    fn forget_all_content_keys(&self) -> Result<()> {
        forget_all().map_err(io_to_core)
    }
}

impl ContentKeyStore for NoopStore {
    fn get_content_key(&self, _lockbox_id: LockboxId) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    fn put_content_key(&self, _lockbox_id: LockboxId, _key: &[u8]) -> Result<()> {
        Ok(())
    }

    fn forget_content_key(&self, _lockbox_id: LockboxId) -> Result<()> {
        Ok(())
    }

    fn forget_all_content_keys(&self) -> Result<()> {
        Ok(())
    }
}

fn io_to_core(err: io::Error) -> Error {
    Error::Io(err.to_string())
}

pub fn serve_agent() -> io::Result<()> {
    platform::serve_agent()
}

pub fn verify_agent_transport_security() -> io::Result<()> {
    platform::verify_agent_transport_security()
}

pub fn get(lockbox_id: LockboxId) -> io::Result<Option<Vec<u8>>> {
    platform::get(lockbox_id)
}

pub fn put(lockbox_id: LockboxId, key: &[u8]) -> io::Result<()> {
    platform::put(lockbox_id, key)
}

pub fn forget(lockbox_id: LockboxId) -> io::Result<()> {
    platform::forget(lockbox_id)
}

pub fn forget_all() -> io::Result<()> {
    platform::forget_all()
}

pub(crate) const DEFAULT_TTL_SECONDS: u64 = 15 * 60;

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn decode_hex(text: &str) -> io::Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid hex"));
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for chunk in text.as_bytes().chunks(2) {
        let high = hex_value(chunk[0])?;
        let low = hex_value(chunk[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> io::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid hex")),
    }
}

pub(crate) enum AgentRequest {
    Get(String),
    Put(String, Vec<u8>),
    Forget(String),
    ForgetAll,
}

pub(crate) fn encode_get(lockbox_id: LockboxId) -> String {
    format!("{PROTOCOL_VERSION} GET {lockbox_id}\n")
}

pub(crate) fn encode_put(lockbox_id: LockboxId, key: &[u8]) -> String {
    format!("{PROTOCOL_VERSION} PUT {lockbox_id} {}\n", encode_hex(key))
}

pub(crate) fn encode_forget(lockbox_id: LockboxId) -> String {
    format!("{PROTOCOL_VERSION} FORGET {lockbox_id}\n")
}

pub(crate) fn encode_forget_all() -> &'static str {
    "LBX1 FORGET_ALL\n"
}

pub(crate) fn parse_request(request: &str) -> io::Result<AgentRequest> {
    if request.len() > MAX_REQUEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "agent request too large",
        ));
    }
    let parts: Vec<&str> = request.split_whitespace().collect();
    match parts.as_slice() {
        [version, "GET", lockbox_id] if *version == PROTOCOL_VERSION => {
            Ok(AgentRequest::Get((*lockbox_id).to_string()))
        }
        [version, "PUT", lockbox_id, key_hex] if *version == PROTOCOL_VERSION => Ok(
            AgentRequest::Put((*lockbox_id).to_string(), decode_hex(key_hex)?),
        ),
        [version, "FORGET", lockbox_id] if *version == PROTOCOL_VERSION => {
            Ok(AgentRequest::Forget((*lockbox_id).to_string()))
        }
        [version, "FORGET_ALL"] if *version == PROTOCOL_VERSION => Ok(AgentRequest::ForgetAll),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid agent request",
        )),
    }
}

#[cfg(unix)]
pub(crate) fn max_request_bytes() -> usize {
    MAX_REQUEST_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_rejects_wrong_version_and_oversized_requests() {
        assert!(parse_request("LBX0 GET vault\n").is_err());
        assert!(parse_request(&"x".repeat(MAX_REQUEST_BYTES + 1)).is_err());
    }

    #[test]
    fn protocol_parses_put_and_forget_all() {
        match parse_request("LBX1 PUT vault 616263\n").unwrap() {
            AgentRequest::Put(lockbox_id, key) => {
                assert_eq!(lockbox_id, "vault");
                assert_eq!(key, b"abc");
            }
            _ => panic!("expected PUT"),
        }
        assert!(matches!(
            parse_request("LBX1 FORGET_ALL\n").unwrap(),
            AgentRequest::ForgetAll
        ));
    }
}
