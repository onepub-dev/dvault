use std::fmt;

pub const MAGIC: &[u8; 4] = b"LBSR";
pub const VERSION: u16 = 1;
pub const MESSAGE_VERSION: u16 = 1;
const ENVELOPE_LEN: usize = 14;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Operation {
    Share = 1,
    Fetch = 2,
    Delete = 3,
    Replicate = 4,
}

impl Operation {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Share),
            2 => Some(Self::Fetch),
            3 => Some(Self::Delete),
            4 => Some(Self::Replicate),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Status {
    Success = 0,
    MalformedRequest = 1,
    UnsupportedVersion = 2,
    UnknownOperation = 3,
    PayloadTooLarge = 4,
    ShareNotFound = 5,
    ShareExpired = 6,
    ShareExhausted = 7,
    DeleteTokenInvalid = 8,
    RateLimited = 9,
    StoreUnavailable = 10,
    InternalError = 11,
    ReplicationUnauthorized = 12,
}

impl Status {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Success),
            1 => Some(Self::MalformedRequest),
            2 => Some(Self::UnsupportedVersion),
            3 => Some(Self::UnknownOperation),
            4 => Some(Self::PayloadTooLarge),
            5 => Some(Self::ShareNotFound),
            6 => Some(Self::ShareExpired),
            7 => Some(Self::ShareExhausted),
            8 => Some(Self::DeleteTokenInvalid),
            9 => Some(Self::RateLimited),
            10 => Some(Self::StoreUnavailable),
            11 => Some(Self::InternalError),
            12 => Some(Self::ReplicationUnauthorized),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct RequestEnvelope {
    pub operation: Operation,
    pub flags: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub struct ResponseEnvelope {
    pub operation: Operation,
    pub status: Status,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum ProtocolError {
    TooShort,
    BadMagic,
    UnsupportedVersion,
    UnknownOperation,
    UnknownStatus,
    LengthMismatch,
    PayloadTooLarge,
    UnsupportedMessageVersion,
    Utf8,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ProtocolError {}

pub fn decode_request(bytes: &[u8], max_payload: usize) -> Result<RequestEnvelope, ProtocolError> {
    if bytes.len() < ENVELOPE_LEN {
        return Err(ProtocolError::TooShort);
    }
    if &bytes[0..4] != MAGIC {
        return Err(ProtocolError::BadMagic);
    }
    let version = read_u16_at(bytes, 4);
    if version != VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let operation =
        Operation::from_u16(read_u16_at(bytes, 6)).ok_or(ProtocolError::UnknownOperation)?;
    let flags = read_u16_at(bytes, 8);
    let payload_len = read_u32_at(bytes, 10) as usize;
    if payload_len > max_payload {
        return Err(ProtocolError::PayloadTooLarge);
    }
    if bytes.len() != ENVELOPE_LEN + payload_len {
        return Err(ProtocolError::LengthMismatch);
    }
    Ok(RequestEnvelope {
        operation,
        flags,
        payload: bytes[ENVELOPE_LEN..].to_vec(),
    })
}

pub fn decode_response(
    bytes: &[u8],
    max_payload: usize,
) -> Result<ResponseEnvelope, ProtocolError> {
    if bytes.len() < ENVELOPE_LEN {
        return Err(ProtocolError::TooShort);
    }
    if &bytes[0..4] != MAGIC {
        return Err(ProtocolError::BadMagic);
    }
    let version = read_u16_at(bytes, 4);
    if version != VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let status = Status::from_u16(read_u16_at(bytes, 6)).ok_or(ProtocolError::UnknownStatus)?;
    let operation =
        Operation::from_u16(read_u16_at(bytes, 8)).ok_or(ProtocolError::UnknownOperation)?;
    let payload_len = read_u32_at(bytes, 10) as usize;
    if payload_len > max_payload {
        return Err(ProtocolError::PayloadTooLarge);
    }
    if bytes.len() != ENVELOPE_LEN + payload_len {
        return Err(ProtocolError::LengthMismatch);
    }
    Ok(ResponseEnvelope {
        operation,
        status,
        payload: bytes[ENVELOPE_LEN..].to_vec(),
    })
}

pub fn decode_error_payload(payload: &[u8]) -> Result<(Status, String), ProtocolError> {
    let mut reader = Reader::new(payload);
    reader.message_version()?;
    let status = Status::from_u16(reader.u16()?).ok_or(ProtocolError::UnknownStatus)?;
    let message = reader.string()?;
    Ok((status, message))
}

pub fn decode_share_response(payload: &[u8]) -> Result<(String, Vec<u8>, u64, u16), ProtocolError> {
    let mut reader = Reader::new(payload);
    reader.message_version()?;
    let share_code = reader.string()?;
    let delete_token = reader.bytes()?;
    let expires_at_unix_ms = reader.u64()?;
    let max_fetches = reader.u16()?;
    Ok((share_code, delete_token, expires_at_unix_ms, max_fetches))
}

pub fn decode_fetch_response(payload: &[u8]) -> Result<(Vec<u8>, u64, u16), ProtocolError> {
    let mut reader = Reader::new(payload);
    reader.message_version()?;
    let share_payload = reader.bytes()?;
    let expires_at_unix_ms = reader.u64()?;
    let remaining_fetches = reader.u16()?;
    Ok((share_payload, expires_at_unix_ms, remaining_fetches))
}

pub fn decode_delete_response(payload: &[u8]) -> Result<bool, ProtocolError> {
    let mut reader = Reader::new(payload);
    reader.message_version()?;
    Ok(reader.u8()? != 0)
}

pub fn encode_response(operation: Operation, status: Status, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENVELOPE_LEN + payload.len());
    out.extend_from_slice(MAGIC);
    put_u16(&mut out, VERSION);
    put_u16(&mut out, status as u16);
    put_u16(&mut out, operation as u16);
    put_u32(&mut out, payload.len() as u32);
    out.extend_from_slice(payload);
    out
}

pub fn encode_error(operation: Operation, status: Status, message: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    put_u16(&mut payload, MESSAGE_VERSION);
    put_u16(&mut payload, status as u16);
    put_string(&mut payload, message);
    encode_response(operation, status, &payload)
}

pub fn encode_share_request(ttl_seconds: u32, max_fetches: u16, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + 4 + payload.len());
    put_u16(&mut body, MESSAGE_VERSION);
    put_u32(&mut body, ttl_seconds);
    put_u16(&mut body, max_fetches);
    put_bytes(&mut body, payload);
    encode_request(Operation::Share, &body)
}

pub fn encode_fetch_request(share_code: &str) -> Vec<u8> {
    let mut body = Vec::new();
    put_u16(&mut body, MESSAGE_VERSION);
    put_string(&mut body, share_code);
    encode_request(Operation::Fetch, &body)
}

pub fn encode_delete_request(share_code: &str, delete_token: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    put_u16(&mut body, MESSAGE_VERSION);
    put_string(&mut body, share_code);
    put_bytes(&mut body, delete_token);
    encode_request(Operation::Delete, &body)
}

pub fn encode_request(operation: Operation, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENVELOPE_LEN + payload.len());
    out.extend_from_slice(MAGIC);
    put_u16(&mut out, VERSION);
    put_u16(&mut out, operation as u16);
    put_u16(&mut out, 0);
    put_u32(&mut out, payload.len() as u32);
    out.extend_from_slice(payload);
    out
}

pub struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub fn u16(&mut self) -> Result<u16, ProtocolError> {
        if self.offset + 2 > self.bytes.len() {
            return Err(ProtocolError::TooShort);
        }
        let value = read_u16_at(self.bytes, self.offset);
        self.offset += 2;
        Ok(value)
    }

    pub fn u8(&mut self) -> Result<u8, ProtocolError> {
        if self.offset + 1 > self.bytes.len() {
            return Err(ProtocolError::TooShort);
        }
        let value = self.bytes[self.offset];
        self.offset += 1;
        Ok(value)
    }

    pub fn message_version(&mut self) -> Result<(), ProtocolError> {
        let version = self.u16()?;
        if version != MESSAGE_VERSION {
            return Err(ProtocolError::UnsupportedMessageVersion);
        }
        Ok(())
    }

    pub fn u32(&mut self) -> Result<u32, ProtocolError> {
        if self.offset + 4 > self.bytes.len() {
            return Err(ProtocolError::TooShort);
        }
        let value = read_u32_at(self.bytes, self.offset);
        self.offset += 4;
        Ok(value)
    }

    pub fn u64(&mut self) -> Result<u64, ProtocolError> {
        if self.offset + 8 > self.bytes.len() {
            return Err(ProtocolError::TooShort);
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

    pub fn string(&mut self) -> Result<String, ProtocolError> {
        let bytes = self.bytes()?;
        String::from_utf8(bytes).map_err(|_| ProtocolError::Utf8)
    }

    pub fn bytes(&mut self) -> Result<Vec<u8>, ProtocolError> {
        let len = self.u32()? as usize;
        self.fixed_bytes(len).map(|bytes| bytes.to_vec())
    }

    pub fn fixed_bytes(&mut self, len: usize) -> Result<&'a [u8], ProtocolError> {
        if self.offset + len > self.bytes.len() {
            return Err(ProtocolError::TooShort);
        }
        let out = &self.bytes[self.offset..self.offset + len];
        self.offset += len;
        Ok(out)
    }
}

pub fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub fn put_string(out: &mut Vec<u8>, value: &str) {
    put_bytes(out, value.as_bytes());
}

pub fn put_bytes(out: &mut Vec<u8>, value: &[u8]) {
    put_u32(out, value.len() as u32);
    out.extend_from_slice(value);
}

fn read_u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}
