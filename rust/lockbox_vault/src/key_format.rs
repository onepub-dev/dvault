use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use lockbox_core::{Error, MlKemKeyPair, MlKemRecipientKey, Result, SecretVec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

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

pub fn export_private_key(keypair: &MlKemKeyPair, format: KeyFormat) -> Result<SecretVec> {
    let public = keypair.recipient_key();
    let public_bytes = public.to_bytes();
    let public_x = Base64UrlUnpadded::encode_string(&public_bytes);
    let kid = fingerprint(&public_bytes);
    let seed = keypair.to_seed_secure()?;
    match format {
        KeyFormat::RawHex => hex_encode_secure(seed),
        KeyFormat::Jwk => private_jwk_secure(&kid, &public_x, seed),
        KeyFormat::Jwks => {
            let jwk = private_jwk_secure(&kid, &public_x, seed)?;
            jwks_secure(&jwk)
        }
        KeyFormat::LockboxPem => {
            let jwk = private_jwk_secure(&kid, &public_x, seed)?;
            pem_secure(PRIVATE_LABEL, &jwk)
        }
    }
}

pub fn import_private_key(mut bytes: SecretVec) -> Result<MlKemKeyPair> {
    normalize_private_key_to_seed(&mut bytes)?;
    MlKemKeyPair::from_seed_secure(bytes)
}

pub fn import_private_key_from_vec(bytes: Vec<u8>) -> Result<MlKemKeyPair> {
    import_private_key(SecretVec::try_from_vec(bytes)?)
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

fn private_jwk_secure(kid: &str, public_x: &str, seed: SecretVec) -> Result<SecretVec> {
    let seed = base64url_encode_secure(seed)?;
    let mut out = SecretVec::new();
    out.try_extend_from_slice(
        br#"{"kty": "AKP", "alg": "ML-KEM-1024", "crv": "ML-KEM-1024", "kid": ""#,
    )?;
    out.try_extend_from_slice(kid.as_bytes())?;
    out.try_extend_from_slice(br#"", "x": ""#)?;
    out.try_extend_from_slice(public_x.as_bytes())?;
    out.try_extend_from_slice(br#"", "d": ""#)?;
    out.try_extend_from_secure(&seed)?;
    out.try_extend_from_slice(br#"", "key_ops": ["unwrapKey", "deriveKey"]}"#)?;
    Ok(out)
}

fn jwks_secure(jwk: &SecretVec) -> Result<SecretVec> {
    let mut out = SecretVec::new();
    out.try_extend_from_slice(br#"{"keys": ["#)?;
    out.try_extend_from_secure(jwk)?;
    out.try_extend_from_slice(b"]}")?;
    Ok(out)
}

fn pem_secure(label: &str, payload: &SecretVec) -> Result<SecretVec> {
    let body = base64_encode_secure(payload.try_clone()?)?;
    let mut out = SecretVec::new();
    out.try_extend_from_slice(b"-----BEGIN ")?;
    out.try_extend_from_slice(label.as_bytes())?;
    out.try_extend_from_slice(b"-----\n")?;
    append_wrapped_base64(&mut out, &body)?;
    out.try_extend_from_slice(b"-----END ")?;
    out.try_extend_from_slice(label.as_bytes())?;
    out.try_extend_from_slice(b"-----\n")?;
    Ok(out)
}

fn append_wrapped_base64(out: &mut SecretVec, body: &SecretVec) -> Result<()> {
    let len = body.len();
    let mut offset = 0usize;
    while offset < len {
        let chunk = (len - offset).min(64);
        out.try_extend_secure_range(body, offset, chunk)?;
        out.try_push(b'\n')?;
        offset += chunk;
    }
    Ok(())
}

fn normalize_private_key_to_seed(bytes: &mut SecretVec) -> Result<()> {
    bytes
        .with_mut_bytes(|bytes| {
            let (start, end) = trim_ascii_range(bytes);
            if bytes[start..end].starts_with(b"-----BEGIN ") {
                let body_len = compact_pem_body(bytes, start, end)?;
                let decoded_len = Base64::decode_in_place(&mut bytes[..body_len])
                    .map_err(|_| Error::InvalidKey)?
                    .len();
                let (d_start, d_end) = find_json_string_value(&bytes[..decoded_len], b"d")?;
                bytes.copy_within(d_start..d_end, 0);
                let seed_len = Base64UrlUnpadded::decode_in_place(&mut bytes[..d_end - d_start])
                    .map_err(|_| Error::InvalidKey)?
                    .len();
                return Ok(seed_len);
            }
            if bytes[start..end].starts_with(b"{") {
                let (d_start, d_end) = find_json_string_value(&bytes[start..end], b"d")?;
                let d_start = start + d_start;
                let d_end = start + d_end;
                bytes.copy_within(d_start..d_end, 0);
                let seed_len = Base64UrlUnpadded::decode_in_place(&mut bytes[..d_end - d_start])
                    .map_err(|_| Error::InvalidKey)?
                    .len();
                return Ok(seed_len);
            }
            bytes.copy_within(start..end, 0);
            hex_decode_in_place(&mut bytes[..end - start])
        })?
        .and_then(|len| bytes.truncate(len).map_err(Into::into))
}

fn compact_pem_body(bytes: &mut [u8], start: usize, end: usize) -> Result<usize> {
    let begin = b"-----BEGIN LOCKBOX PRIVATE KEY-----";
    if !bytes[start..end].starts_with(begin) {
        return Err(Error::InvalidKey);
    }
    let mut line_start = start;
    while line_start < end && bytes[line_start] != b'\n' && bytes[line_start] != b'\r' {
        line_start += 1;
    }
    if line_start == end {
        return Err(Error::InvalidKey);
    }
    let mut write = 0usize;
    let mut read = line_start;
    while read < end {
        let byte = bytes[read];
        if byte == b'-' && bytes[read..end].starts_with(b"-----END ") {
            break;
        }
        if !byte.is_ascii_whitespace() {
            bytes[write] = byte;
            write += 1;
        }
        read += 1;
    }
    bytes[write..].zeroize();
    Ok(write)
}

fn find_json_string_value(bytes: &[u8], key: &[u8]) -> Result<(usize, usize)> {
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        let key_start = index + 1;
        let Some(key_end) = bytes[key_start..].iter().position(|byte| *byte == b'"') else {
            return Err(Error::InvalidKey);
        };
        let key_end = key_start + key_end;
        index = key_end + 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() || bytes[index] != b':' {
            continue;
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if &bytes[key_start..key_end] == key {
            if index >= bytes.len() || bytes[index] != b'"' {
                return Err(Error::InvalidKey);
            }
            let value_start = index + 1;
            let Some(value_end) = bytes[value_start..].iter().position(|byte| *byte == b'"') else {
                return Err(Error::InvalidKey);
            };
            return Ok((value_start, value_start + value_end));
        }
    }
    Err(Error::InvalidKey)
}

fn hex_encode_secure(mut bytes: SecretVec) -> Result<SecretVec> {
    let original_len = bytes.len();
    bytes.resize_zeroed(original_len * 2)?;
    bytes.with_mut_bytes(|bytes| {
        for index in (0..original_len).rev() {
            let byte = bytes[index];
            bytes[index * 2] = hex_digit(byte >> 4);
            bytes[index * 2 + 1] = hex_digit(byte & 0x0f);
        }
    })?;
    Ok(bytes)
}

fn base64url_encode_secure(bytes: SecretVec) -> Result<SecretVec> {
    base64_encode_with::<Base64UrlUnpadded>(bytes)
}

fn base64_encode_secure(bytes: SecretVec) -> Result<SecretVec> {
    base64_encode_with::<Base64>(bytes)
}

fn base64_encode_with<E: Encoding>(mut bytes: SecretVec) -> Result<SecretVec> {
    let original_len = bytes.len();
    let encoded_len = bytes.with_bytes(E::encoded_len)?;
    bytes.resize_zeroed(original_len + encoded_len)?;
    bytes.with_mut_bytes(|bytes| {
        bytes.copy_within(0..original_len, encoded_len);
        let (out, input) = bytes.split_at_mut(encoded_len);
        E::encode(&input[..original_len], out).map_err(|_| Error::InvalidKey)?;
        input.zeroize();
        Ok::<_, Error>(())
    })??;
    bytes.truncate(encoded_len)?;
    Ok(bytes)
}

fn hex_decode_in_place(bytes: &mut [u8]) -> Result<usize> {
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::InvalidKey);
    }
    let out_len = bytes.len() / 2;
    for index in 0..out_len {
        let high = hex_value(bytes[index * 2])?;
        let low = hex_value(bytes[index * 2 + 1])?;
        bytes[index] = (high << 4) | low;
    }
    bytes[out_len..].zeroize();
    Ok(out_len)
}

fn hex_digit(value: u8) -> u8 {
    b"0123456789abcdef"[value as usize]
}

fn hex_value(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::InvalidKey),
    }
}

fn trim_ascii_range(bytes: &[u8]) -> (usize, usize) {
    let mut start = 0usize;
    let mut end = bytes.len();
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    (start, end)
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
        let keypair = MlKemKeyPair::generate().unwrap();
        let private = export_private_key(&keypair, KeyFormat::LockboxPem).unwrap();
        let loaded = import_private_key(private).unwrap();
        assert_eq!(
            loaded.to_seed_bytes().unwrap(),
            keypair.to_seed_bytes().unwrap()
        );

        let public = export_public_key(&keypair.recipient_key(), KeyFormat::LockboxPem).unwrap();
        let loaded_public = import_public_key(&public).unwrap();
        assert_eq!(loaded_public.to_bytes(), keypair.recipient_key().to_bytes());
    }

    #[test]
    fn jwk_and_jwks_round_trip() {
        let keypair = MlKemKeyPair::generate().unwrap();
        let jwk = export_private_key(&keypair, KeyFormat::Jwk).unwrap();
        assert_eq!(
            import_private_key(jwk).unwrap().to_seed_bytes().unwrap(),
            keypair.to_seed_bytes().unwrap()
        );
        let jwks = export_public_key(&keypair.recipient_key(), KeyFormat::Jwks).unwrap();
        assert_eq!(
            import_public_key(&jwks).unwrap().to_bytes(),
            keypair.recipient_key().to_bytes()
        );
    }

    #[test]
    fn raw_hex_remains_importable() {
        let keypair = MlKemKeyPair::generate().unwrap();
        let raw = export_private_key(&keypair, KeyFormat::RawHex).unwrap();
        assert_eq!(
            import_private_key(raw).unwrap().to_seed_bytes().unwrap(),
            keypair.to_seed_bytes().unwrap()
        );
    }
}
