use lockbox_core::{LockboxId, Result, SecretVec};

use crate::ContentKeyStore;

/// Content-key store that never retains keys.
///
/// This is useful for commands or tests that want `Vault`'s create/unlock
/// helpers without enabling cache-only reopening.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopStore;

impl ContentKeyStore for NoopStore {
    fn get_content_key(&self, _lockbox_id: LockboxId) -> Result<Option<SecretVec>> {
        Ok(None)
    }

    fn put_content_key(&self, _lockbox_id: LockboxId, _key: SecretVec) -> Result<()> {
        Ok(())
    }

    fn forget_content_key(&self, _lockbox_id: LockboxId) -> Result<()> {
        Ok(())
    }

    fn forget_all_content_keys(&self) -> Result<()> {
        Ok(())
    }
}
