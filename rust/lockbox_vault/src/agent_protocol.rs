use lockbox_core::{LockboxId, SecretVec};
use std::io;

const PROTOCOL_VERSION: &str = "LBX1";
const MAX_MESSAGE_BYTES: usize = 128 * 1024;

pub(crate) const DEFAULT_TTL_SECONDS: u64 = 15 * 60;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedLockbox {
    pub id: String,
    pub path: Option<String>,
}

pub(crate) enum AgentRequest {
    Get(String),
    Put(String, SecretVec, Option<String>),
    Forget(String),
    ForgetAll,
    List,
}

pub(crate) enum AgentResponse {
    Ok,
    Miss,
    Key(SecretVec),
    List(Vec<CachedLockbox>),
    Err(String),
}

pub(crate) fn encode_get(lockbox_id: LockboxId) -> io::Result<SecretVec> {
    secure_message(format!("{PROTOCOL_VERSION} GET {lockbox_id}\n").as_bytes())
}

pub(crate) fn encode_put(
    lockbox_id: LockboxId,
    key: &SecretVec,
    path: Option<&str>,
) -> io::Result<SecretVec> {
    let path = path.unwrap_or("");
    let mut message = SecretVec::new();
    message
        .try_extend_from_slice(
            format!(
                "{PROTOCOL_VERSION} PUT {lockbox_id} {} {}\n",
                key.len(),
                path.len()
            )
            .as_bytes(),
        )
        .map_err(io::Error::other)?;
    message
        .try_extend_from_secure(key)
        .map_err(io::Error::other)?;
    message
        .try_extend_from_slice(path.as_bytes())
        .map_err(io::Error::other)?;
    Ok(message)
}

pub(crate) fn encode_forget(lockbox_id: LockboxId) -> io::Result<SecretVec> {
    secure_message(format!("{PROTOCOL_VERSION} FORGET {lockbox_id}\n").as_bytes())
}

pub(crate) fn encode_forget_all() -> io::Result<SecretVec> {
    secure_message(b"LBX1 FORGET_ALL\n")
}

pub(crate) fn encode_list() -> io::Result<SecretVec> {
    secure_message(b"LBX1 LIST\n")
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

pub(crate) fn encode_list_response(
    lockboxes: impl Iterator<Item = CachedLockbox>,
) -> io::Result<SecretVec> {
    let lockboxes = lockboxes.collect::<Vec<_>>();
    let mut message = SecretVec::new();
    message
        .try_extend_from_slice(format!("LIST {}\n", lockboxes.len()).as_bytes())
        .map_err(io::Error::other)?;
    for lockbox in lockboxes {
        let path = lockbox.path.unwrap_or_default();
        message
            .try_extend_from_slice(
                format!("{}\t{}\n", lockbox.id, hex_encode(path.as_bytes())).as_bytes(),
            )
            .map_err(io::Error::other)?;
    }
    Ok(message)
}

pub(crate) fn parse_request(request: &SecretVec) -> io::Result<AgentRequest> {
    let parsed = request
        .with_bytes(parse_header)
        .map_err(io::Error::other)??;
    match parsed {
        ParsedHeader::Get(lockbox_id) => Ok(AgentRequest::Get(lockbox_id)),
        ParsedHeader::Put(lockbox_id, body_offset, body_len, path_offset, path_len) => {
            let key = request
                .try_clone_range(body_offset, body_len)
                .map_err(io::Error::other)?;
            let path = if path_len == 0 {
                None
            } else {
                let mut path = None;
                request
                    .with_bytes(|bytes| {
                        let path_bytes = bytes
                            .get(path_offset..path_offset + path_len)
                            .ok_or_else(|| {
                                io::Error::new(io::ErrorKind::InvalidData, "invalid path range")
                            })?;
                        path = Some(
                            std::str::from_utf8(path_bytes)
                                .map_err(|_| {
                                    io::Error::new(io::ErrorKind::InvalidData, "path is not UTF-8")
                                })?
                                .to_string(),
                        );
                        Ok::<(), io::Error>(())
                    })
                    .map_err(io::Error::other)??;
                path
            };
            Ok(AgentRequest::Put(lockbox_id, key, path))
        }
        ParsedHeader::Forget(lockbox_id) => Ok(AgentRequest::Forget(lockbox_id)),
        ParsedHeader::ForgetAll => Ok(AgentRequest::ForgetAll),
        ParsedHeader::List => Ok(AgentRequest::List),
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
        ParsedResponse::List(ids) => Ok(AgentResponse::List(ids)),
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
    Put(String, usize, usize, usize, usize),
    Forget(String),
    ForgetAll,
    List,
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
                body_end,
                0,
            ))
        }
        [version, "PUT", lockbox_id, key_len, path_len] if *version == PROTOCOL_VERSION => {
            let key_len = key_len
                .parse::<usize>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key length"))?;
            let path_len = path_len
                .parse::<usize>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid path length"))?;
            let body_offset = newline + 1;
            let body_end = body_offset
                .checked_add(key_len)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "key length overflow"))?;
            let path_end = body_end.checked_add(path_len).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "path length overflow")
            })?;
            if path_end != bytes.len() {
                return invalid_data("request key/path length does not match body");
            }
            Ok(ParsedHeader::Put(
                (*lockbox_id).to_string(),
                body_offset,
                key_len,
                body_end,
                path_len,
            ))
        }
        [version, "FORGET", lockbox_id] if *version == PROTOCOL_VERSION => {
            Ok(ParsedHeader::Forget((*lockbox_id).to_string()))
        }
        [version, "FORGET_ALL"] if *version == PROTOCOL_VERSION => Ok(ParsedHeader::ForgetAll),
        [version, "LIST"] if *version == PROTOCOL_VERSION => Ok(ParsedHeader::List),
        _ => invalid_data("invalid agent request"),
    }
}

enum ParsedResponse {
    Ok,
    Miss,
    Key(usize, usize),
    List(Vec<CachedLockbox>),
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
    if let Some(count) = header.strip_prefix("LIST ") {
        let count = count
            .parse::<usize>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid list count"))?;
        let body = &bytes[newline + 1..];
        let text = std::str::from_utf8(body).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "list response body is not UTF-8",
            )
        })?;
        let lockboxes = text
            .lines()
            .map(parse_list_line)
            .collect::<io::Result<Vec<_>>>()?;
        if lockboxes.len() != count {
            return invalid_data("list response count does not match body");
        }
        return Ok(ParsedResponse::List(lockboxes));
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

fn parse_list_line(line: &str) -> io::Result<CachedLockbox> {
    let Some((id, path_hex)) = line.split_once('\t') else {
        return Ok(CachedLockbox {
            id: line.to_string(),
            path: None,
        });
    };
    let path_bytes = hex_decode(path_hex)?;
    let path =
        if path_bytes.is_empty() {
            None
        } else {
            Some(String::from_utf8(path_bytes).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "list path is not UTF-8")
            })?)
        };
    Ok(CachedLockbox {
        id: id.to_string(),
        path,
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(hex: &str) -> io::Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return invalid_data("invalid hex length");
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    for chunk in bytes.chunks_exact(2) {
        let high = hex_value(chunk[0])?;
        let low = hex_value(chunk[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> io::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => invalid_data("invalid hex digit"),
    }
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
        let request = SecretVec::try_from_slice(b"LBX1 PUT vault 3 11\nabc/tmp/a.lbox").unwrap();
        match parse_request(&request).unwrap() {
            AgentRequest::Put(lockbox_id, key, path) => {
                assert_eq!(lockbox_id, "vault");
                key.with_bytes(|key| assert_eq!(key, b"abc")).unwrap();
                assert_eq!(path.as_deref(), Some("/tmp/a.lbox"));
            }
            _ => panic!("expected PUT"),
        }
        let request = SecretVec::try_from_slice(b"LBX1 FORGET_ALL\n").unwrap();
        assert!(matches!(
            parse_request(&request).unwrap(),
            AgentRequest::ForgetAll
        ));
        let request = SecretVec::try_from_slice(b"LBX1 LIST\n").unwrap();
        assert!(matches!(
            parse_request(&request).unwrap(),
            AgentRequest::List
        ));

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
    }
}
