use argon2::{Algorithm, Argon2, Params, Version};

use crate::secret_vec::SecretString;
use crate::{Error, Result};

pub(crate) fn derive_key_from_password(password: &SecretString, salt: &[u8]) -> Result<[u8; 32]> {
    password.with_bytes(|bytes| derive_key_from_password_bytes(bytes, salt))?
}

pub(crate) fn derive_key_from_password_bytes(password: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    if salt.len() < 16 {
        return Err(Error::InvalidInput(
            "Argon2id salt must be at least 16 bytes".to_string(),
        ));
    }
    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|err| Error::SecurityLimitExceeded(err.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|_| Error::InvalidKey)?;
    Ok(key)
}
