use std::fmt;

use sha2::{Digest, Sha256};

const MAGIC: &[u8; 4] = b"LBSP";
const HEADER_LEN: usize = 12;
pub const CONTACT_FINGERPRINT_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum PayloadType {
    ContactShare = 1,
    SignedKeyReplacement = 2,
    UnsignedKeyReplacement = 3,
}

impl PayloadType {
    fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::ContactShare),
            2 => Some(Self::SignedKeyReplacement),
            3 => Some(Self::UnsignedKeyReplacement),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum PayloadError {
    TooShort,
    BadMagic,
    UnsupportedVersion,
    UnknownType,
    TrailingBytes,
    FieldTooLarge,
    MissingField,
    InvalidField,
}

impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for PayloadError {}

pub fn validate_payload(bytes: &[u8]) -> Result<PayloadType, PayloadError> {
    if bytes.len() < HEADER_LEN {
        return Err(PayloadError::TooShort);
    }
    if &bytes[0..4] != MAGIC {
        return Err(PayloadError::BadMagic);
    }
    let version = read_u16(bytes, 4);
    if version != 1 {
        return Err(PayloadError::UnsupportedVersion);
    }
    let payload_type =
        PayloadType::from_u16(read_u16(bytes, 6)).ok_or(PayloadError::UnknownType)?;
    let body_len = read_u32(bytes, 8) as usize;
    if bytes.len() != HEADER_LEN + body_len {
        return Err(PayloadError::TrailingBytes);
    }
    let mut reader = PayloadReader::new(&bytes[HEADER_LEN..]);
    match payload_type {
        PayloadType::ContactShare => validate_contact_share(&mut reader)?,
        PayloadType::SignedKeyReplacement => validate_signed_key_replacement(&mut reader)?,
        PayloadType::UnsignedKeyReplacement => validate_unsigned_key_replacement(&mut reader)?,
    }
    if !reader.is_done() {
        return Err(PayloadError::TrailingBytes);
    }
    Ok(payload_type)
}

pub fn encode_contact_share(
    identity: &str,
    public_key: &[u8],
    signing_public_key: &[u8],
    fingerprint: &[u8],
    share_nonce: &[u8],
    created_at_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> Vec<u8> {
    let mut body = Vec::new();
    put_string(&mut body, identity);
    put_bytes(&mut body, public_key);
    put_bytes(&mut body, signing_public_key);
    put_bytes(&mut body, fingerprint);
    put_bytes(&mut body, share_nonce);
    put_u64(&mut body, created_at_unix_ms);
    put_u64(&mut body, expires_at_unix_ms);
    encode_payload(PayloadType::ContactShare, &body)
}

pub fn normalize_contact_email(email: &str) -> Result<String, PayloadError> {
    let normalized = email.trim().to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 254
        || normalized.bytes().any(|byte| byte.is_ascii_control())
        || !normalized.contains('@')
        || normalized.starts_with('@')
        || normalized.ends_with('@')
    {
        return Err(PayloadError::InvalidField);
    }
    Ok(normalized)
}

pub fn contact_fingerprint(
    email: &str,
    recipient_public_key: &[u8],
    signing_public_key: &[u8],
) -> Result<Vec<u8>, PayloadError> {
    let email = normalize_contact_email(email)?;
    let mut hasher = Sha256::new();
    update_fingerprint_field(&mut hasher, b"revault-contact-fingerprint-v1");
    update_fingerprint_field(&mut hasher, email.as_bytes());
    update_fingerprint_field(&mut hasher, b"recipient-public-key-bytes-v1");
    update_fingerprint_field(&mut hasher, recipient_public_key);
    update_fingerprint_field(&mut hasher, b"owner-signing-public-key-bytes-v1");
    update_fingerprint_field(&mut hasher, signing_public_key);
    Ok(hasher.finalize()[..CONTACT_FINGERPRINT_LEN].to_vec())
}

fn update_fingerprint_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u32).to_be_bytes());
    hasher.update(value);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedContactShare {
    pub identity: String,
    pub public_key: Vec<u8>,
    pub signing_public_key: Vec<u8>,
    pub fingerprint: Vec<u8>,
    pub share_nonce: Vec<u8>,
    pub created_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

pub fn decode_contact_share(bytes: &[u8]) -> Result<DecodedContactShare, PayloadError> {
    if validate_payload(bytes)? != PayloadType::ContactShare {
        return Err(PayloadError::UnknownType);
    }
    let body_len = read_u32(bytes, 8) as usize;
    let mut reader = PayloadReader::new(&bytes[HEADER_LEN..HEADER_LEN + body_len]);
    Ok(DecodedContactShare {
        identity: reader.string(254)?,
        public_key: reader.bytes(4096)?,
        signing_public_key: reader.bytes(4096)?,
        fingerprint: reader.bytes(128)?,
        share_nonce: reader.bytes(64)?,
        created_at_unix_ms: reader.u64()?,
        expires_at_unix_ms: reader.u64()?,
    })
}

pub struct SignedKeyReplacement<'a> {
    pub identity: &'a str,
    pub old_fingerprint: &'a [u8],
    pub new_public_key: &'a [u8],
    pub new_signing_public_key: &'a [u8],
    pub new_fingerprint: &'a [u8],
    pub replacement_nonce: &'a [u8],
    pub signature_by_old_key: &'a [u8],
    pub created_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

pub type KeyReplacement<'a> = SignedKeyReplacement<'a>;

pub fn encode_key_replacement(replacement: KeyReplacement<'_>) -> Vec<u8> {
    encode_signed_key_replacement(replacement)
}

pub fn encode_signed_key_replacement(replacement: SignedKeyReplacement<'_>) -> Vec<u8> {
    let mut body = Vec::new();
    put_string(&mut body, replacement.identity);
    put_bytes(&mut body, replacement.old_fingerprint);
    put_bytes(&mut body, replacement.new_public_key);
    put_bytes(&mut body, replacement.new_signing_public_key);
    put_bytes(&mut body, replacement.new_fingerprint);
    put_bytes(&mut body, replacement.replacement_nonce);
    put_bytes(&mut body, replacement.signature_by_old_key);
    put_u64(&mut body, replacement.created_at_unix_ms);
    put_u64(&mut body, replacement.expires_at_unix_ms);
    encode_payload(PayloadType::SignedKeyReplacement, &body)
}

pub struct UnsignedKeyReplacement<'a> {
    pub identity: &'a str,
    pub old_fingerprint: &'a [u8],
    pub new_public_key: &'a [u8],
    pub new_signing_public_key: &'a [u8],
    pub new_fingerprint: &'a [u8],
    pub replacement_nonce: &'a [u8],
    pub created_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

pub fn encode_unsigned_key_replacement(replacement: UnsignedKeyReplacement<'_>) -> Vec<u8> {
    let mut body = Vec::new();
    put_string(&mut body, replacement.identity);
    put_bytes(&mut body, replacement.old_fingerprint);
    put_bytes(&mut body, replacement.new_public_key);
    put_bytes(&mut body, replacement.new_signing_public_key);
    put_bytes(&mut body, replacement.new_fingerprint);
    put_bytes(&mut body, replacement.replacement_nonce);
    put_u64(&mut body, replacement.created_at_unix_ms);
    put_u64(&mut body, replacement.expires_at_unix_ms);
    encode_payload(PayloadType::UnsignedKeyReplacement, &body)
}

fn validate_contact_share(reader: &mut PayloadReader<'_>) -> Result<(), PayloadError> {
    let identity = reader.string(254)?;
    validate_identity(&identity)?;
    let public_key = reader.bytes(4096)?;
    validate_non_empty(&public_key)?;
    let signing_public_key = reader.bytes(4096)?;
    validate_non_empty(&signing_public_key)?;
    let fingerprint = reader.bytes(128)?;
    validate_fingerprint(&fingerprint)?;
    let nonce = reader.bytes(64)?;
    validate_nonce(&nonce)?;
    let created_at = reader.u64()?;
    let expires_at = reader.u64()?;
    validate_times(created_at, expires_at)
}

fn validate_signed_key_replacement(reader: &mut PayloadReader<'_>) -> Result<(), PayloadError> {
    let identity = reader.string(254)?;
    validate_identity(&identity)?;
    let old_fingerprint = reader.bytes(128)?;
    validate_fingerprint(&old_fingerprint)?;
    let new_public_key = reader.bytes(4096)?;
    validate_non_empty(&new_public_key)?;
    let new_signing_public_key = reader.bytes(4096)?;
    validate_non_empty(&new_signing_public_key)?;
    let new_fingerprint = reader.bytes(128)?;
    validate_fingerprint(&new_fingerprint)?;
    let nonce = reader.bytes(64)?;
    validate_nonce(&nonce)?;
    let signature = reader.bytes(4096)?;
    validate_non_empty(&signature)?;
    let created_at = reader.u64()?;
    let expires_at = reader.u64()?;
    validate_times(created_at, expires_at)
}

fn validate_unsigned_key_replacement(reader: &mut PayloadReader<'_>) -> Result<(), PayloadError> {
    let identity = reader.string(254)?;
    validate_identity(&identity)?;
    let old_fingerprint = reader.bytes(128)?;
    validate_fingerprint(&old_fingerprint)?;
    let new_public_key = reader.bytes(4096)?;
    validate_non_empty(&new_public_key)?;
    let new_signing_public_key = reader.bytes(4096)?;
    validate_non_empty(&new_signing_public_key)?;
    let new_fingerprint = reader.bytes(128)?;
    validate_fingerprint(&new_fingerprint)?;
    let nonce = reader.bytes(64)?;
    validate_nonce(&nonce)?;
    let created_at = reader.u64()?;
    let expires_at = reader.u64()?;
    validate_times(created_at, expires_at)
}

fn validate_identity(identity: &str) -> Result<(), PayloadError> {
    if identity.is_empty()
        || identity.len() > 254
        || identity
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(PayloadError::InvalidField);
    }
    Ok(())
}

fn validate_fingerprint(fingerprint: &[u8]) -> Result<(), PayloadError> {
    if !(16..=128).contains(&fingerprint.len()) {
        return Err(PayloadError::InvalidField);
    }
    Ok(())
}

fn validate_nonce(nonce: &[u8]) -> Result<(), PayloadError> {
    if !(16..=64).contains(&nonce.len()) {
        return Err(PayloadError::InvalidField);
    }
    Ok(())
}

fn validate_non_empty(bytes: &[u8]) -> Result<(), PayloadError> {
    if bytes.is_empty() {
        return Err(PayloadError::MissingField);
    }
    Ok(())
}

fn validate_times(created_at: u64, expires_at: u64) -> Result<(), PayloadError> {
    if created_at == 0 || expires_at <= created_at {
        return Err(PayloadError::InvalidField);
    }
    Ok(())
}

struct PayloadReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PayloadReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_done(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn u64(&mut self) -> Result<u64, PayloadError> {
        if self.offset + 8 > self.bytes.len() {
            return Err(PayloadError::TooShort);
        }
        let value = u64::from_be_bytes([
            self.bytes[self.offset],
            self.bytes[self.offset + 1],
            self.bytes[self.offset + 2],
            self.bytes[self.offset + 3],
            self.bytes[self.offset + 4],
            self.bytes[self.offset + 5],
            self.bytes[self.offset + 6],
            self.bytes[self.offset + 7],
        ]);
        self.offset += 8;
        Ok(value)
    }

    fn string(&mut self, max_len: usize) -> Result<String, PayloadError> {
        let bytes = self.bytes(max_len)?;
        String::from_utf8(bytes).map_err(|_| PayloadError::InvalidField)
    }

    fn bytes(&mut self, max_len: usize) -> Result<Vec<u8>, PayloadError> {
        if self.offset + 4 > self.bytes.len() {
            return Err(PayloadError::TooShort);
        }
        let len = read_u32(self.bytes, self.offset) as usize;
        self.offset += 4;
        if len > max_len {
            return Err(PayloadError::FieldTooLarge);
        }
        if self.offset + len > self.bytes.len() {
            return Err(PayloadError::TooShort);
        }
        let out = self.bytes[self.offset..self.offset + len].to_vec();
        self.offset += len;
        Ok(out)
    }
}

fn encode_payload(payload_type: PayloadType, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(MAGIC);
    put_u16(&mut out, 1);
    put_u16(&mut out, payload_type as u16);
    put_u32(&mut out, body.len() as u32);
    out.extend_from_slice(body);
    out
}

fn put_string(out: &mut Vec<u8>, value: &str) {
    put_bytes(out, value.as_bytes());
}

fn put_bytes(out: &mut Vec<u8>, value: &[u8]) {
    put_u32(out, value.len() as u32);
    out.extend_from_slice(value);
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}
