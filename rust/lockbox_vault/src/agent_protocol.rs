use lockbox_core::{LockboxId, SecretVec};
use std::io;

const MAGIC: &[u8; 4] = b"LBX2";
const HEADER_LEN: usize = 9;
const MAX_MESSAGE_BYTES: usize = 128 * 1024;

const REQ_GET: u8 = 0x01;
const REQ_PUT: u8 = 0x02;
const REQ_FORGET: u8 = 0x03;
const REQ_FORGET_ALL: u8 = 0x04;
const REQ_STOP: u8 = 0x05;
const REQ_LIST: u8 = 0x06;
const REQ_REGISTER_SECRET_ACTIVITY: u8 = 0x10;
const REQ_UNREGISTER_SECRET_ACTIVITY: u8 = 0x11;

const RESP_REGISTERED: u8 = 0x80;
const RESP_OK: u8 = 0x81;
const RESP_MISS: u8 = 0x82;
const RESP_KEY: u8 = 0x83;
const RESP_LIST: u8 = 0x84;
const RESP_ERR: u8 = 0xff;

pub(crate) const DEFAULT_TTL_SECONDS: u64 = 15 * 60;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedLockbox {
    pub id: String,
    pub path: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretActivityKind {
    Unlock,
    Open,
    Env,
    Form,
    Recovery,
    Vault,
}

impl SecretActivityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unlock => "unlock",
            Self::Open => "open",
            Self::Env => "env",
            Self::Form => "form",
            Self::Recovery => "recovery",
            Self::Vault => "vault",
        }
    }

    fn to_wire(self) -> u8 {
        match self {
            Self::Unlock => 1,
            Self::Open => 2,
            Self::Env => 3,
            Self::Form => 4,
            Self::Recovery => 5,
            Self::Vault => 6,
        }
    }
}

pub(crate) enum AgentRequest {
    Get(String),
    Put(String, SecretVec, Option<String>, Option<u64>),
    Forget(String),
    ForgetAll,
    Stop,
    List,
}

pub(crate) enum AgentResponse {
    Ok,
    Miss,
    Key(SecretVec),
    List(Vec<CachedLockbox>),
    Err(String),
}

pub(crate) enum ControlRequest {
    RegisterSecretActivity(u32, SecretActivityKind),
    UnregisterSecretActivity(u32, u64),
}

pub(crate) enum ControlResponse {
    Ok,
    Registered(u64),
    Err(String),
}

pub(crate) fn encode_get(lockbox_id: LockboxId) -> io::Result<SecretVec> {
    encode_frame(REQ_GET, lockbox_id.to_string().as_bytes())
}

pub(crate) fn encode_put(
    lockbox_id: LockboxId,
    key: &SecretVec,
    path: Option<&str>,
    ttl_seconds: Option<u64>,
) -> io::Result<SecretVec> {
    let lockbox_id = lockbox_id.to_string();
    let path = path.unwrap_or("");
    let ttl_seconds = ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
    let mut payload = SecretVec::new();
    push_string(&mut payload, &lockbox_id)?;
    push_u32(&mut payload, key.len() as u32)?;
    push_u32(&mut payload, path.len() as u32)?;
    push_u64(&mut payload, ttl_seconds)?;
    payload
        .try_extend_from_secure(key)
        .map_err(io::Error::other)?;
    payload
        .try_extend_from_slice(path.as_bytes())
        .map_err(io::Error::other)?;
    encode_frame_secure(REQ_PUT, &payload)
}

pub(crate) fn encode_forget(lockbox_id: LockboxId) -> io::Result<SecretVec> {
    encode_frame(REQ_FORGET, lockbox_id.to_string().as_bytes())
}

pub(crate) fn encode_forget_all() -> io::Result<SecretVec> {
    encode_frame(REQ_FORGET_ALL, &[])
}

pub(crate) fn encode_stop() -> io::Result<SecretVec> {
    encode_frame(REQ_STOP, &[])
}

pub(crate) fn encode_list() -> io::Result<SecretVec> {
    encode_frame(REQ_LIST, &[])
}

pub(crate) fn encode_register_secret_activity(
    pid: u32,
    kind: SecretActivityKind,
) -> io::Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(5);
    payload.extend_from_slice(&pid.to_le_bytes());
    payload.push(kind.to_wire());
    encode_plain_frame(REQ_REGISTER_SECRET_ACTIVITY, &payload)
}

pub(crate) fn encode_unregister_secret_activity(pid: u32, token: u64) -> io::Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(12);
    payload.extend_from_slice(&pid.to_le_bytes());
    payload.extend_from_slice(&token.to_le_bytes());
    encode_plain_frame(REQ_UNREGISTER_SECRET_ACTIVITY, &payload)
}

pub(crate) fn encode_key_response(key: &SecretVec) -> io::Result<SecretVec> {
    encode_frame_secure(RESP_KEY, key)
}

pub(crate) fn encode_ok_response() -> io::Result<SecretVec> {
    encode_frame(RESP_OK, &[])
}

pub(crate) fn encode_miss_response() -> io::Result<SecretVec> {
    encode_frame(RESP_MISS, &[])
}

pub(crate) fn encode_err_response(message: &str) -> io::Result<SecretVec> {
    encode_frame(RESP_ERR, message.as_bytes())
}

pub(crate) fn encode_control_ok_response() -> io::Result<Vec<u8>> {
    encode_plain_frame(RESP_OK, &[])
}

pub(crate) fn encode_control_err_response(message: &str) -> io::Result<Vec<u8>> {
    encode_plain_frame(RESP_ERR, message.as_bytes())
}

pub(crate) fn encode_registered_response(token: u64) -> io::Result<Vec<u8>> {
    encode_plain_frame(RESP_REGISTERED, &token.to_le_bytes())
}

pub(crate) fn encode_list_response(
    lockboxes: impl Iterator<Item = CachedLockbox>,
) -> io::Result<SecretVec> {
    let lockboxes = lockboxes.collect::<Vec<_>>();
    let mut payload = SecretVec::new();
    push_u32(&mut payload, lockboxes.len() as u32)?;
    for lockbox in lockboxes {
        push_string(&mut payload, &lockbox.id)?;
        match lockbox.path {
            Some(path) => push_bytes_u32(&mut payload, path.as_bytes())?,
            None => push_u32(&mut payload, 0)?,
        }
    }
    encode_frame_secure(RESP_LIST, &payload)
}

pub(crate) fn parse_request(request: &SecretVec) -> io::Result<AgentRequest> {
    let parsed = request
        .with_bytes(parse_request_bytes)
        .map_err(io::Error::other)??;
    match parsed {
        ParsedRequest::Ready(request) => Ok(request),
        ParsedRequest::Put {
            lockbox_id,
            key_offset,
            key_len,
            path,
            ttl_seconds,
        } => {
            let key = request
                .try_clone_range(key_offset, key_len)
                .map_err(io::Error::other)?;
            Ok(AgentRequest::Put(lockbox_id, key, path, Some(ttl_seconds)))
        }
    }
}

enum ParsedRequest {
    Ready(AgentRequest),
    Put {
        lockbox_id: String,
        key_offset: usize,
        key_len: usize,
        path: Option<String>,
        ttl_seconds: u64,
    },
}

fn parse_request_bytes(bytes: &[u8]) -> io::Result<ParsedRequest> {
    let frame = parse_frame(bytes)?;
    match frame.message_type {
        REQ_GET => Ok(ParsedRequest::Ready(AgentRequest::Get(
            read_utf8(frame.payload)?.to_string(),
        ))),
        REQ_PUT => parse_put_request(frame.payload),
        REQ_FORGET => Ok(ParsedRequest::Ready(AgentRequest::Forget(
            read_utf8(frame.payload)?.to_string(),
        ))),
        REQ_FORGET_ALL if frame.payload.is_empty() => {
            Ok(ParsedRequest::Ready(AgentRequest::ForgetAll))
        }
        REQ_STOP if frame.payload.is_empty() => Ok(ParsedRequest::Ready(AgentRequest::Stop)),
        REQ_LIST if frame.payload.is_empty() => Ok(ParsedRequest::Ready(AgentRequest::List)),
        _ => invalid_data("invalid binary agent request"),
    }
}

pub(crate) fn parse_response(response: SecretVec) -> io::Result<AgentResponse> {
    let parsed = response
        .with_bytes(parse_response_bytes)
        .map_err(io::Error::other)??;
    match parsed {
        ParsedResponse::Ready(response) => Ok(response),
        ParsedResponse::Key { offset, len } => {
            let key = response
                .try_clone_range(offset, len)
                .map_err(io::Error::other)?;
            Ok(AgentResponse::Key(key))
        }
    }
}

enum ParsedResponse {
    Ready(AgentResponse),
    Key { offset: usize, len: usize },
}

fn parse_response_bytes(bytes: &[u8]) -> io::Result<ParsedResponse> {
    let frame = parse_frame(bytes)?;
    match frame.message_type {
        RESP_OK if frame.payload.is_empty() => Ok(ParsedResponse::Ready(AgentResponse::Ok)),
        RESP_MISS if frame.payload.is_empty() => Ok(ParsedResponse::Ready(AgentResponse::Miss)),
        RESP_KEY => Ok(ParsedResponse::Key {
            offset: HEADER_LEN,
            len: frame.payload.len(),
        }),
        RESP_LIST => parse_list_response(frame.payload),
        RESP_ERR => Ok(ParsedResponse::Ready(AgentResponse::Err(
            read_utf8(frame.payload)?.to_string(),
        ))),
        _ => invalid_data("invalid binary agent response"),
    }
}

pub(crate) fn parse_control_request(request: &[u8]) -> io::Result<ControlRequest> {
    let frame = parse_frame(request)?;
    match frame.message_type {
        REQ_REGISTER_SECRET_ACTIVITY => parse_register_secret_activity(frame.payload),
        REQ_UNREGISTER_SECRET_ACTIVITY => parse_unregister_secret_activity(frame.payload),
        _ => invalid_data("invalid binary agent control request"),
    }
}

pub(crate) fn parse_control_response(response: &[u8]) -> io::Result<ControlResponse> {
    let frame = parse_frame(response)?;
    match frame.message_type {
        RESP_OK if frame.payload.is_empty() => Ok(ControlResponse::Ok),
        RESP_REGISTERED if frame.payload.len() == 8 => {
            Ok(ControlResponse::Registered(read_u64(frame.payload)?))
        }
        RESP_ERR => Ok(ControlResponse::Err(read_utf8(frame.payload)?.to_string())),
        _ => invalid_data("invalid binary agent control response"),
    }
}

pub(crate) fn max_message_bytes() -> usize {
    MAX_MESSAGE_BYTES
}

pub(crate) fn frame_header_len() -> usize {
    HEADER_LEN
}

pub(crate) fn frame_payload_len(header: &[u8]) -> io::Result<usize> {
    if header.len() != HEADER_LEN || &header[..4] != MAGIC {
        return invalid_data("invalid binary agent frame header");
    }
    let len = read_u32_raw(&header[5..9])? as usize;
    let total = HEADER_LEN
        .checked_add(len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "message too large"))?;
    if total > MAX_MESSAGE_BYTES {
        return invalid_data("message too large");
    }
    Ok(len)
}

pub(crate) fn frame_message_type(header: &[u8]) -> io::Result<u8> {
    if header.len() != HEADER_LEN || &header[..4] != MAGIC {
        return invalid_data("invalid binary agent frame header");
    }
    Ok(header[4])
}

pub(crate) fn is_control_message_type(message_type: u8) -> bool {
    matches!(
        message_type,
        REQ_REGISTER_SECRET_ACTIVITY | REQ_UNREGISTER_SECRET_ACTIVITY
    )
}

fn encode_frame(message_type: u8, payload: &[u8]) -> io::Result<SecretVec> {
    let payload = SecretVec::try_from_slice(payload).map_err(io::Error::other)?;
    encode_frame_secure(message_type, &payload)
}

fn encode_plain_frame(message_type: u8, payload: &[u8]) -> io::Result<Vec<u8>> {
    let total = HEADER_LEN
        .checked_add(payload.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "message too large"))?;
    if total > MAX_MESSAGE_BYTES {
        return invalid_data("message too large");
    }
    let mut message = Vec::with_capacity(total);
    message.extend_from_slice(MAGIC);
    message.push(message_type);
    message.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    message.extend_from_slice(payload);
    Ok(message)
}

fn encode_frame_secure(message_type: u8, payload: &SecretVec) -> io::Result<SecretVec> {
    let total = HEADER_LEN
        .checked_add(payload.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "message too large"))?;
    if total > MAX_MESSAGE_BYTES {
        return invalid_data("message too large");
    }
    let mut message = SecretVec::new();
    message
        .try_extend_from_slice(MAGIC)
        .map_err(io::Error::other)?;
    message.try_push(message_type).map_err(io::Error::other)?;
    push_u32(&mut message, payload.len() as u32)?;
    if !payload.is_empty() {
        message
            .try_extend_from_secure(payload)
            .map_err(io::Error::other)?;
    }
    Ok(message)
}

struct Frame<'a> {
    message_type: u8,
    payload: &'a [u8],
}

fn parse_frame(bytes: &[u8]) -> io::Result<Frame<'_>> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return invalid_data("agent message too large");
    }
    if bytes.len() < HEADER_LEN || &bytes[..4] != MAGIC {
        return invalid_data("invalid binary agent frame");
    }
    let payload_len = read_u32_raw(&bytes[5..9])? as usize;
    if HEADER_LEN + payload_len != bytes.len() {
        return invalid_data("binary agent frame length mismatch");
    }
    Ok(Frame {
        message_type: bytes[4],
        payload: &bytes[HEADER_LEN..],
    })
}

fn parse_put_request(payload: &[u8]) -> io::Result<ParsedRequest> {
    let mut cursor = Cursor::new(payload);
    let lockbox_id = cursor.read_string()?.to_string();
    let key_len = cursor.read_u32()? as usize;
    let path_len = cursor.read_u32()? as usize;
    let ttl_seconds = cursor.read_u64()?;
    if ttl_seconds == 0 {
        return invalid_data("ttl must be positive");
    }
    let key_offset = cursor.position();
    let path_offset = key_offset
        .checked_add(key_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "key length overflow"))?;
    let end = path_offset
        .checked_add(path_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "path length overflow"))?;
    if end != payload.len() {
        return invalid_data("put payload length mismatch");
    }
    let path = if path_len == 0 {
        None
    } else {
        Some(read_utf8(&payload[path_offset..end])?.to_string())
    };
    Ok(ParsedRequest::Put {
        lockbox_id,
        key_offset: HEADER_LEN + key_offset,
        key_len,
        path,
        ttl_seconds,
    })
}

fn parse_register_secret_activity(payload: &[u8]) -> io::Result<ControlRequest> {
    if payload.len() != 5 {
        return invalid_data("invalid secret activity registration length");
    }
    Ok(ControlRequest::RegisterSecretActivity(
        validate_pid(read_u32_raw(&payload[..4])?)?,
        kind_from_wire(payload[4])?,
    ))
}

fn parse_unregister_secret_activity(payload: &[u8]) -> io::Result<ControlRequest> {
    if payload.len() != 12 {
        return invalid_data("invalid secret activity unregister length");
    }
    Ok(ControlRequest::UnregisterSecretActivity(
        validate_pid(read_u32_raw(&payload[..4])?)?,
        read_u64(&payload[4..12])?,
    ))
}

fn parse_list_response(payload: &[u8]) -> io::Result<ParsedResponse> {
    let mut cursor = Cursor::new(payload);
    let count = cursor.read_u32()? as usize;
    let mut lockboxes = Vec::with_capacity(count);
    for _ in 0..count {
        let id = cursor.read_string()?.to_string();
        let path = cursor.read_bytes_u32()?;
        let path = if path.is_empty() {
            None
        } else {
            Some(read_utf8(path)?.to_string())
        };
        lockboxes.push(CachedLockbox { id, path });
    }
    if !cursor.is_finished() {
        return invalid_data("list response has trailing bytes");
    }
    Ok(ParsedResponse::Ready(AgentResponse::List(lockboxes)))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn position(&self) -> usize {
        self.position
    }

    fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn read_u16(&mut self) -> io::Result<u16> {
        let bytes = self.read_exact(2)?;
        Ok(u16::from_le_bytes(
            bytes.try_into().expect("slice length checked"),
        ))
    }

    fn read_u32(&mut self) -> io::Result<u32> {
        read_u32_raw(self.read_exact(4)?)
    }

    fn read_u64(&mut self) -> io::Result<u64> {
        read_u64(self.read_exact(8)?)
    }

    fn read_string(&mut self) -> io::Result<&'a str> {
        let len = self.read_u16()? as usize;
        read_utf8(self.read_exact(len)?)
    }

    fn read_bytes_u32(&mut self) -> io::Result<&'a [u8]> {
        let len = self.read_u32()? as usize;
        self.read_exact(len)
    }

    fn read_exact(&mut self, len: usize) -> io::Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "payload length overflow"))?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "payload too short"))?;
        self.position = end;
        Ok(bytes)
    }
}

fn push_string(out: &mut SecretVec, value: &str) -> io::Result<()> {
    if value.len() > u16::MAX as usize {
        return invalid_data("string too long");
    }
    out.try_extend_from_slice(&(value.len() as u16).to_le_bytes())
        .map_err(io::Error::other)?;
    out.try_extend_from_slice(value.as_bytes())
        .map_err(io::Error::other)
}

fn push_bytes_u32(out: &mut SecretVec, value: &[u8]) -> io::Result<()> {
    push_u32(out, value.len() as u32)?;
    out.try_extend_from_slice(value).map_err(io::Error::other)
}

fn push_u32(out: &mut SecretVec, value: u32) -> io::Result<()> {
    out.try_extend_from_slice(&value.to_le_bytes())
        .map_err(io::Error::other)
}

fn push_u64(out: &mut SecretVec, value: u64) -> io::Result<()> {
    out.try_extend_from_slice(&value.to_le_bytes())
        .map_err(io::Error::other)
}

fn read_utf8(bytes: &[u8]) -> io::Result<&str> {
    std::str::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "payload is not UTF-8"))
}

fn read_u32_raw(bytes: &[u8]) -> io::Result<u32> {
    let bytes: [u8; 4] = bytes
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid u32 length"))?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(bytes: &[u8]) -> io::Result<u64> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid u64 length"))?;
    Ok(u64::from_le_bytes(bytes))
}

fn validate_pid(pid: u32) -> io::Result<u32> {
    if pid == 0 {
        return invalid_data("pid must be positive");
    }
    Ok(pid)
}

fn kind_from_wire(value: u8) -> io::Result<SecretActivityKind> {
    match value {
        1 => Ok(SecretActivityKind::Unlock),
        2 => Ok(SecretActivityKind::Open),
        3 => Ok(SecretActivityKind::Env),
        4 => Ok(SecretActivityKind::Form),
        5 => Ok(SecretActivityKind::Recovery),
        6 => Ok(SecretActivityKind::Vault),
        _ => invalid_data("invalid secret activity kind"),
    }
}

fn invalid_data<T>(message: &str) -> io::Result<T> {
    Err(io::Error::new(io::ErrorKind::InvalidData, message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_rejects_line_based_and_oversized_requests() {
        let request = SecretVec::try_from_slice(b"GET vault\n").unwrap();
        assert!(parse_request(&request).is_err());
        let request = SecretVec::try_from_slice(&vec![b'x'; MAX_MESSAGE_BYTES + 1]).unwrap();
        assert!(parse_request(&request).is_err());
    }

    #[test]
    fn protocol_parses_put_and_cache_commands() {
        let lockbox_id = LockboxId::from_bytes([1; 16]);
        let key = SecretVec::try_from_slice(b"abc").unwrap();
        let request = encode_put(lockbox_id, &key, Some("/tmp/a.lbox"), Some(30)).unwrap();
        match parse_request(&request).unwrap() {
            AgentRequest::Put(id, parsed_key, path, ttl_seconds) => {
                assert_eq!(id, lockbox_id.to_string());
                parsed_key
                    .with_bytes(|key| assert_eq!(key, b"abc"))
                    .unwrap();
                assert_eq!(path.as_deref(), Some("/tmp/a.lbox"));
                assert_eq!(ttl_seconds, Some(30));
            }
            _ => panic!("expected PUT"),
        }

        assert!(matches!(
            parse_request(&encode_forget_all().unwrap()).unwrap(),
            AgentRequest::ForgetAll
        ));
        assert!(matches!(
            parse_request(&encode_stop().unwrap()).unwrap(),
            AgentRequest::Stop
        ));
        assert!(matches!(
            parse_request(&encode_list().unwrap()).unwrap(),
            AgentRequest::List
        ));
    }

    #[test]
    fn protocol_parses_list_and_activity_responses() {
        let response = encode_list_response(
            [
                CachedLockbox {
                    id: "a".to_string(),
                    path: Some("/tmp/a.lbox".to_string()),
                },
                CachedLockbox {
                    id: "b".to_string(),
                    path: None,
                },
            ]
            .into_iter(),
        )
        .unwrap();
        match parse_response(response).unwrap() {
            AgentResponse::List(ids) => {
                assert_eq!(ids[0].id, "a");
                assert_eq!(ids[0].path.as_deref(), Some("/tmp/a.lbox"));
                assert_eq!(ids[1].id, "b");
                assert_eq!(ids[1].path, None);
            }
            _ => panic!("expected LIST"),
        }

        let request = encode_register_secret_activity(42, SecretActivityKind::Unlock).unwrap();
        match parse_control_request(&request).unwrap() {
            ControlRequest::RegisterSecretActivity(42, SecretActivityKind::Unlock) => {}
            _ => panic!("expected activity registration"),
        }
        let response = encode_registered_response(123).unwrap();
        assert!(matches!(
            parse_control_response(&response).unwrap(),
            ControlResponse::Registered(123)
        ));
    }
}
