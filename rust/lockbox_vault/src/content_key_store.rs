use lockbox_core::{LockboxId, Result};

pub trait ContentKeyStore {
    fn get_content_key(&self, lockbox_id: LockboxId) -> Result<Option<Vec<u8>>>;
    fn put_content_key(&self, lockbox_id: LockboxId, key: &[u8]) -> Result<()>;
    fn forget_content_key(&self, lockbox_id: LockboxId) -> Result<()>;
    fn forget_all_content_keys(&self) -> Result<()>;
}
