use lockbox_core::{LockboxId, SecretVec};
use std::io;

const PROTOCOL_VERSION: &str = "LBX1";
const MAX_MESSAGE_BYTES: usize = 128 * 1024;

pub(crate) const DEFAULT_TTL_SECONDS: u64 = 15 * 60;

pub(crate) enum AgentRequest {
    Get(String),
    Put(String, SecretVec),
    Forget(String),
    ForgetAll,
}

pub(crate) enum AgentResponse {
    Ok,
    Miss,
    Key(SecretVec),
    Err(String),
}

pub(crate) fn encode_get(lockbox_id: LockboxId) -> io::Result<SecretVec> {
    secure_message(format!("{PROTOCOL_VERSION} GET {lockbox_id}\n").as_bytes())
}

pub(crate) fn encode_put(lockbox_id: LockboxId, key: &[u8]) -> io::Result<SecretVec> {
    let mut message = SecretVec::new();
    message
        .try_extend_from_slice(
            format!("{PROTOCOL_VERSION} PUT {lockbox_id} {}\n", key.len()).as_bytes(),
        )
        .map_err(io::Error::other)?;
    message
        .try_extend_from_slice(key)
        .map_err(io::Error::other)?;
    Ok(message)
}

pub(crate) fn encode_forget(lockbox_id: LockboxId) -> io::Result<SecretVec> {
    secure_message(format!("{PROTOCOL_VERSION} FORGET {lockbox_id}\n").as_bytes())
}

pub(crate) fn encode_forget_all() -> io::Result<SecretVec> {
    secure_message(b"LBX1 FORGET_ALL\n")
}

pub(crate) fn encode_key_response(key: &SecretVec) -> io::Result<SecretVec> {
    let mut message = SecretVec::new();
    message
        .try_extend_from_slice(format!("KEY {}\n", key.len()).as_bytes())
        .map_err(io::Error::other)?;
    message
        .try_extend_from_secure(key)
        .map_err(io::Error::other)?;
    Ok(message)
}

pub(crate) fn encode_response_line(line: &[u8]) -> io::Result<SecretVec> {
    secure_message(line)
}

pub(crate) fn parse_request(request: &SecretVec) -> io::Result<AgentRequest> {
    let parsed = request
        .with_bytes(parse_header)
        .map_err(io::Error::other)??;
    match parsed {
        ParsedHeader::Get(lockbox_id) => Ok(AgentRequest::Get(lockbox_id)),
        ParsedHeader::Put(lockbox_id, body_offset, body_len) => {
            let key = request
                .try_clone_range(body_offset, body_len)
                .map_err(io::Error::other)?;
            Ok(AgentRequest::Put(lockbox_id, key))
        }
        ParsedHeader::Forget(lockbox_id) => Ok(AgentRequest::Forget(lockbox_id)),
        ParsedHeader::ForgetAll => Ok(AgentRequest::ForgetAll),
    }
}

pub(crate) fn parse_response(response: SecretVec) -> io::Result<AgentResponse> {
    let parsed = response
        .with_bytes(parse_response_header)
        .map_err(io::Error::other)??;
    match parsed {
        ParsedResponse::Ok => Ok(AgentResponse::Ok),
        ParsedResponse::Miss => Ok(AgentResponse::Miss),
        ParsedResponse::Err(message) => Ok(AgentResponse::Err(message)),
        ParsedResponse::Key(body_offset, body_len) => {
            let key = response
                .try_clone_range(body_offset, body_len)
                .map_err(io::Error::other)?;
            Ok(AgentResponse::Key(key))
        }
    }
}

#[cfg(unix)]
pub(crate) fn max_message_bytes() -> usize {
    MAX_MESSAGE_BYTES
}

#[cfg(windows)]
pub(crate) fn max_message_bytes() -> usize {
    MAX_MESSAGE_BYTES
}

fn secure_message(bytes: &[u8]) -> io::Result<SecretVec> {
    SecretVec::try_from_slice(bytes).map_err(io::Error::other)
}

enum ParsedHeader {
    Get(String),
    Put(String, usize, usize),
    Forget(String),
    ForgetAll,
}

fn parse_header(bytes: &[u8]) -> io::Result<ParsedHeader> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return invalid_data("agent request too large");
    }
    let newline = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request header"))?;
    let header = std::str::from_utf8(&bytes[..newline])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "request header is not UTF-8"))?;
    let parts: Vec<&str> = header.split_whitespace().collect();
    match parts.as_slice() {
        [version, "GET", lockbox_id] if *version == PROTOCOL_VERSION => {
            Ok(ParsedHeader::Get((*lockbox_id).to_string()))
        }
        [version, "PUT", lockbox_id, key_len] if *version == PROTOCOL_VERSION => {
            let key_len = key_len
                .parse::<usize>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key length"))?;
            let body_offset = newline + 1;
            let body_end = body_offset
                .checked_add(key_len)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "key length overflow"))?;
            if body_end != bytes.len() {
                return invalid_data("request key length does not match body");
            }
            Ok(ParsedHeader::Put(
                (*lockbox_id).to_string(),
                body_offset,
                key_len,
            ))
        }
        [version, "FORGET", lockbox_id] if *version == PROTOCOL_VERSION => {
            Ok(ParsedHeader::Forget((*lockbox_id).to_string()))
        }
        [version, "FORGET_ALL"] if *version == PROTOCOL_VERSION => Ok(ParsedHeader::ForgetAll),
        _ => invalid_data("invalid agent request"),
    }
}

enum ParsedResponse {
    Ok,
    Miss,
    Key(usize, usize),
    Err(String),
}

fn parse_response_header(bytes: &[u8]) -> io::Result<ParsedResponse> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return invalid_data("agent response too large");
    }
    let newline = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing response header"))?;
    let header = std::str::from_utf8(&bytes[..newline])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response header is not UTF-8"))?;
    if header == "OK" {
        return Ok(ParsedResponse::Ok);
    }
    if header == "MISS" {
        return Ok(ParsedResponse::Miss);
    }
    if let Some(message) = header.strip_prefix("ERR ") {
        return Ok(ParsedResponse::Err(message.to_string()));
    }
    let parts: Vec<&str> = header.split_whitespace().collect();
    match parts.as_slice() {
        ["KEY", key_len] => {
            let key_len = key_len
                .parse::<usize>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key length"))?;
            let body_offset = newline + 1;
            let body_end = body_offset
                .checked_add(key_len)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "key length overflow"))?;
            if body_end != bytes.len() {
                return invalid_data("response key length does not match body");
            }
            Ok(ParsedResponse::Key(body_offset, key_len))
        }
        _ => invalid_data("invalid agent response"),
    }
}

fn invalid_data<T>(message: &str) -> io::Result<T> {
    Err(io::Error::new(io::ErrorKind::InvalidData, message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_rejects_wrong_version_and_oversized_requests() {
        let request = SecretVec::try_from_slice(b"LBX0 GET vault\n").unwrap();
        assert!(parse_request(&request).is_err());
        let request = SecretVec::try_from_slice(&vec![b'x'; MAX_MESSAGE_BYTES + 1]).unwrap();
        assert!(parse_request(&request).is_err());
    }

    #[test]
    fn protocol_parses_put_and_forget_all() {
        let request = SecretVec::try_from_slice(b"LBX1 PUT vault 3\nabc").unwrap();
        match parse_request(&request).unwrap() {
            AgentRequest::Put(lockbox_id, key) => {
                assert_eq!(lockbox_id, "vault");
                key.with_bytes(|key| assert_eq!(key, b"abc")).unwrap();
            }
            _ => panic!("expected PUT"),
        }
        let request = SecretVec::try_from_slice(b"LBX1 FORGET_ALL\n").unwrap();
        assert!(matches!(
            parse_request(&request).unwrap(),
            AgentRequest::ForgetAll
        ));
    }
}
