use lockbox_core::{LockboxId, Result};

use crate::ContentKeyStore;

#[derive(Debug, Clone, Copy, Default)]
pub struct NoopStore;

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
