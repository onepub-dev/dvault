use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use lockbox_core::{Error, MlKemKeyPair, MlKemRecipientKey, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{decode_hex, encode_hex};

const PRIVATE_LABEL: &str = "LOCKBOX PRIVATE KEY";
const PUBLIC_LABEL: &str = "LOCKBOX PUBLIC KEY";
const KTY: &str = "AKP";
const ALG: &str = "ML-KEM-1024";
const CRV: &str = "ML-KEM-1024";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    LockboxPem,
    Jwk,
    Jwks,
    RawHex,
}

impl KeyFormat {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "lockbox" | "lockbox-pem" | "pem" => Ok(Self::LockboxPem),
            "jwk" => Ok(Self::Jwk),
            "jwks" => Ok(Self::Jwks),
            "raw" | "raw-hex" | "hex" => Ok(Self::RawHex),
            _ => Err(Error::InvalidPath(format!(
                "unsupported key format: {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwkKey {
    kty: String,
    alg: String,
    crv: String,
    kid: String,
    x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    d: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_ops: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Jwks {
    keys: Vec<JwkKey>,
}

pub fn export_private_key(keypair: &MlKemKeyPair, format: KeyFormat) -> Result<Vec<u8>> {
    match format {
        KeyFormat::LockboxPem => pem(PRIVATE_LABEL, &private_jwk(keypair)?),
        KeyFormat::Jwk => serde_json::to_vec_pretty(&private_jwk(keypair)?)
            .map_err(|err| Error::Io(err.to_string())),
        KeyFormat::Jwks => serde_json::to_vec_pretty(&Jwks {
            keys: vec![private_jwk(keypair)?],
        })
        .map_err(|err| Error::Io(err.to_string())),
        KeyFormat::RawHex => Ok(encode_hex(&keypair.to_seed_bytes()).into_bytes()),
    }
}

pub fn export_public_key(key: &MlKemRecipientKey, format: KeyFormat) -> Result<Vec<u8>> {
    match format {
        KeyFormat::LockboxPem => pem(PUBLIC_LABEL, &public_jwk(key)?),
        KeyFormat::Jwk => {
            serde_json::to_vec_pretty(&public_jwk(key)?).map_err(|err| Error::Io(err.to_string()))
        }
        KeyFormat::Jwks => serde_json::to_vec_pretty(&Jwks {
            keys: vec![public_jwk(key)?],
        })
        .map_err(|err| Error::Io(err.to_string())),
        KeyFormat::RawHex => Ok(encode_hex(&key.to_bytes()).into_bytes()),
    }
}

pub fn import_private_key(bytes: &[u8]) -> Result<MlKemKeyPair> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidKey)?;
    if text.trim_start().starts_with("-----BEGIN ") {
        let (label, payload) = unpem(text)?;
        if label != PRIVATE_LABEL {
            return Err(Error::InvalidKey);
        }
        return private_from_jwk(&payload);
    }
    if text.trim_start().starts_with('{') {
        if let Ok(jwks) = serde_json::from_str::<Jwks>(text) {
            let key = jwks.keys.into_iter().next().ok_or(Error::InvalidKey)?;
            return private_from_jwk(&key);
        }
        let key = serde_json::from_str::<JwkKey>(text).map_err(|_| Error::InvalidKey)?;
        return private_from_jwk(&key);
    }
    MlKemKeyPair::from_seed_bytes(&decode_hex(text.trim()).map_err(|_| Error::InvalidKey)?)
}

pub fn import_public_key(bytes: &[u8]) -> Result<MlKemRecipientKey> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::CorruptHeader)?;
    if text.trim_start().starts_with("-----BEGIN ") {
        let (label, payload) = unpem(text)?;
        if label != PUBLIC_LABEL {
            return Err(Error::CorruptHeader);
        }
        return public_from_jwk(&payload);
    }
    if text.trim_start().starts_with('{') {
        if let Ok(jwks) = serde_json::from_str::<Jwks>(text) {
            let key = jwks.keys.into_iter().next().ok_or(Error::CorruptHeader)?;
            return public_from_jwk(&key);
        }
        let key = serde_json::from_str::<JwkKey>(text).map_err(|_| Error::CorruptHeader)?;
        return public_from_jwk(&key);
    }
    MlKemRecipientKey::from_bytes(&decode_hex(text.trim()).map_err(|_| Error::CorruptHeader)?)
}

fn private_jwk(keypair: &MlKemKeyPair) -> Result<JwkKey> {
    let public = keypair.recipient_key();
    let public_bytes = public.to_bytes();
    Ok(JwkKey {
        kty: KTY.to_string(),
        alg: ALG.to_string(),
        crv: CRV.to_string(),
        kid: fingerprint(&public_bytes),
        x: Base64UrlUnpadded::encode_string(&public_bytes),
        d: Some(Base64UrlUnpadded::encode_string(&keypair.to_seed_bytes())),
        key_ops: Some(vec!["unwrapKey".to_string(), "deriveKey".to_string()]),
    })
}

fn public_jwk(key: &MlKemRecipientKey) -> Result<JwkKey> {
    let public_bytes = key.to_bytes();
    Ok(JwkKey {
        kty: KTY.to_string(),
        alg: ALG.to_string(),
        crv: CRV.to_string(),
        kid: fingerprint(&public_bytes),
        x: Base64UrlUnpadded::encode_string(&public_bytes),
        d: None,
        key_ops: Some(vec!["wrapKey".to_string()]),
    })
}

fn private_from_jwk(key: &JwkKey) -> Result<MlKemKeyPair> {
    validate_jwk_header(key).map_err(|_| Error::InvalidKey)?;
    let d = key.d.as_ref().ok_or(Error::InvalidKey)?;
    let seed = Base64UrlUnpadded::decode_vec(d).map_err(|_| Error::InvalidKey)?;
    MlKemKeyPair::from_seed_bytes(&seed)
}

fn public_from_jwk(key: &JwkKey) -> Result<MlKemRecipientKey> {
    validate_jwk_header(key).map_err(|_| Error::CorruptHeader)?;
    let public = Base64UrlUnpadded::decode_vec(&key.x).map_err(|_| Error::CorruptHeader)?;
    MlKemRecipientKey::from_bytes(&public)
}

fn validate_jwk_header(key: &JwkKey) -> Result<()> {
    if key.kty == KTY && key.alg == ALG && key.crv == CRV {
        Ok(())
    } else {
        Err(Error::InvalidKey)
    }
}

fn pem(label: &str, payload: &JwkKey) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(payload).map_err(|err| Error::Io(err.to_string()))?;
    let body = Base64::encode_string(&json);
    let mut out = String::new();
    out.push_str(&format!("-----BEGIN {label}-----\n"));
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).map_err(|_| Error::Io("invalid pem".into()))?);
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    Ok(out.into_bytes())
}

fn unpem(text: &str) -> Result<(String, JwkKey)> {
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    let begin = lines.next().ok_or(Error::InvalidKey)?;
    let label = begin
        .strip_prefix("-----BEGIN ")
        .and_then(|value| value.strip_suffix("-----"))
        .ok_or(Error::InvalidKey)?
        .to_string();
    let end = format!("-----END {label}-----");
    let mut body = String::new();
    for line in lines {
        if line == end {
            let json = Base64::decode_vec(&body).map_err(|_| Error::InvalidKey)?;
            let key = serde_json::from_slice(&json).map_err(|_| Error::InvalidKey)?;
            return Ok((label, key));
        }
        body.push_str(line);
    }
    Err(Error::InvalidKey)
}

fn fingerprint(public_key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"lockbox-key-fingerprint-v1");
    hasher.update(public_key);
    encode_hex(&hasher.finalize()[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_pem_round_trips_private_and_public_keys() {
        let keypair = MlKemKeyPair::generate();
        let private = export_private_key(&keypair, KeyFormat::LockboxPem).unwrap();
        let loaded = import_private_key(&private).unwrap();
        assert_eq!(loaded.to_seed_bytes(), keypair.to_seed_bytes());

        let public = export_public_key(&keypair.recipient_key(), KeyFormat::LockboxPem).unwrap();
        let loaded_public = import_public_key(&public).unwrap();
        assert_eq!(loaded_public.to_bytes(), keypair.recipient_key().to_bytes());
    }

    #[test]
    fn jwk_and_jwks_round_trip() {
        let keypair = MlKemKeyPair::generate();
        let jwk = export_private_key(&keypair, KeyFormat::Jwk).unwrap();
        assert_eq!(
            import_private_key(&jwk).unwrap().to_seed_bytes(),
            keypair.to_seed_bytes()
        );
        let jwks = export_public_key(&keypair.recipient_key(), KeyFormat::Jwks).unwrap();
        assert_eq!(
            import_public_key(&jwks).unwrap().to_bytes(),
            keypair.recipient_key().to_bytes()
        );
    }

    #[test]
    fn raw_hex_remains_importable() {
        let keypair = MlKemKeyPair::generate();
        let raw = export_private_key(&keypair, KeyFormat::RawHex).unwrap();
        assert_eq!(
            import_private_key(&raw).unwrap().to_seed_bytes(),
            keypair.to_seed_bytes()
        );
    }
}
