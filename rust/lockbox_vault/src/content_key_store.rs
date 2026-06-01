use lockbox_core::{LockboxId, Result, SecretVec};

/// Storage backend for unlocked Lockbox content keys.
///
/// `Vault` uses this trait to cache content keys after a lockbox is created or
/// unlocked, and to retrieve them for later cache-only opens. Implementations
/// may keep keys in memory, forward them to a local agent, or deliberately
/// discard them.
pub trait ContentKeyStore {
    /// Returns the cached content key for `lockbox_id`, if one is available.
    fn get_content_key(&self, lockbox_id: LockboxId) -> Result<Option<SecretVec>>;

    /// Stores the unlocked content key for `lockbox_id`.
    fn put_content_key(&self, lockbox_id: LockboxId, key: SecretVec) -> Result<()>;

    /// Removes the cached content key for `lockbox_id`.
    fn forget_content_key(&self, lockbox_id: LockboxId) -> Result<()>;

    /// Removes all cached content keys known to this store.
    fn forget_all_content_keys(&self) -> Result<()>;
}
