use lockbox_core::LockboxId;
use std::io;

use crate::{decode_hex, encode_hex};

const PROTOCOL_VERSION: &str = "LBX1";
const MAX_REQUEST_BYTES: usize = 128 * 1024;

pub(crate) const DEFAULT_TTL_SECONDS: u64 = 15 * 60;

pub(crate) enum AgentRequest {
    Get(String),
    Put(String, Vec<u8>),
    Forget(String),
    ForgetAll,
}

pub(crate) fn encode_get(lockbox_id: LockboxId) -> String {
    format!("{PROTOCOL_VERSION} GET {lockbox_id}\n")
}

pub(crate) fn encode_put(lockbox_id: LockboxId, key: &[u8]) -> String {
    format!("{PROTOCOL_VERSION} PUT {lockbox_id} {}\n", encode_hex(key))
}

pub(crate) fn encode_forget(lockbox_id: LockboxId) -> String {
    format!("{PROTOCOL_VERSION} FORGET {lockbox_id}\n")
}

pub(crate) fn encode_forget_all() -> &'static str {
    "LBX1 FORGET_ALL\n"
}

pub(crate) fn parse_request(request: &str) -> io::Result<AgentRequest> {
    if request.len() > MAX_REQUEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "agent request too large",
        ));
    }
    let parts: Vec<&str> = request.split_whitespace().collect();
    match parts.as_slice() {
        [version, "GET", lockbox_id] if *version == PROTOCOL_VERSION => {
            Ok(AgentRequest::Get((*lockbox_id).to_string()))
        }
        [version, "PUT", lockbox_id, key_hex] if *version == PROTOCOL_VERSION => Ok(
            AgentRequest::Put((*lockbox_id).to_string(), decode_hex(key_hex)?),
        ),
        [version, "FORGET", lockbox_id] if *version == PROTOCOL_VERSION => {
            Ok(AgentRequest::Forget((*lockbox_id).to_string()))
        }
        [version, "FORGET_ALL"] if *version == PROTOCOL_VERSION => Ok(AgentRequest::ForgetAll),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid agent request",
        )),
    }
}

#[cfg(unix)]
pub(crate) fn max_request_bytes() -> usize {
    MAX_REQUEST_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_rejects_wrong_version_and_oversized_requests() {
        assert!(parse_request("LBX0 GET vault\n").is_err());
        assert!(parse_request(&"x".repeat(MAX_REQUEST_BYTES + 1)).is_err());
    }

    #[test]
    fn protocol_parses_put_and_forget_all() {
        match parse_request("LBX1 PUT vault 616263\n").unwrap() {
            AgentRequest::Put(lockbox_id, key) => {
                assert_eq!(lockbox_id, "vault");
                assert_eq!(key, b"abc");
            }
            _ => panic!("expected PUT"),
        }
        assert!(matches!(
            parse_request("LBX1 FORGET_ALL\n").unwrap(),
            AgentRequest::ForgetAll
        ));
    }
}
