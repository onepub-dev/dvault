use lockbox_core::VaultId;
use std::io;
use zeroize::Zeroize;

const PROTOCOL_VERSION: &str = "LBX1";
const MAX_REQUEST_BYTES: usize = 128 * 1024;

#[cfg(unix)]
mod unix;

#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as platform;

#[cfg(windows)]
use windows as platform;

#[cfg(not(any(unix, windows)))]
mod platform {
    use lockbox_core::VaultId;
    use std::io;

    pub(crate) fn serve_agent() -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "lockbox agent is not supported on this platform",
        ))
    }

    pub(crate) fn get(_vault_id: VaultId) -> io::Result<Option<Vec<u8>>> {
        Ok(None)
    }

    pub(crate) fn put(_vault_id: VaultId, _key: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "lockbox agent is not supported on this platform",
        ))
    }

    pub(crate) fn forget(_vault_id: VaultId) -> io::Result<()> {
        Ok(())
    }

    pub(crate) fn forget_all() -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn serve_agent() -> io::Result<()> {
    platform::serve_agent()
}

pub(crate) fn get(vault_id: VaultId) -> io::Result<Option<Vec<u8>>> {
    platform::get(vault_id)
}

pub(crate) fn put(vault_id: VaultId, key: &[u8]) -> io::Result<()> {
    platform::put(vault_id, key)
}

pub(crate) fn forget(vault_id: VaultId) -> io::Result<()> {
    platform::forget(vault_id)
}

pub(crate) fn forget_all() -> io::Result<()> {
    platform::forget_all()
}

pub(crate) const DEFAULT_TTL_SECONDS: u64 = 15 * 60;

pub(crate) struct SecretBytes {
    bytes: Vec<u8>,
    locked: bool,
}

impl SecretBytes {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        let locked = lock_memory(&bytes);
        Self { bytes, locked }
    }

    pub(crate) fn expose(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.bytes.zeroize();
        if self.locked {
            unlock_memory(&self.bytes);
        }
    }
}

#[cfg(unix)]
fn lock_memory(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    unsafe { libc::mlock(bytes.as_ptr().cast(), bytes.len()) == 0 }
}

#[cfg(unix)]
fn unlock_memory(bytes: &[u8]) {
    if !bytes.is_empty() {
        unsafe {
            libc::munlock(bytes.as_ptr().cast(), bytes.len());
        }
    }
}

#[cfg(windows)]
fn lock_memory(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    unsafe {
        windows_sys::Win32::System::Memory::VirtualLock(bytes.as_ptr().cast(), bytes.len()) != 0
    }
}

#[cfg(windows)]
fn unlock_memory(bytes: &[u8]) {
    if !bytes.is_empty() {
        unsafe {
            windows_sys::Win32::System::Memory::VirtualUnlock(bytes.as_ptr().cast(), bytes.len());
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn lock_memory(_bytes: &[u8]) -> bool {
    false
}

#[cfg(not(any(unix, windows)))]
fn unlock_memory(_bytes: &[u8]) {}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(crate) fn decode_hex(text: &str) -> io::Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid hex"));
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for chunk in text.as_bytes().chunks(2) {
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
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid hex")),
    }
}

pub(crate) enum AgentRequest {
    Get(String),
    Put(String, Vec<u8>),
    Forget(String),
    ForgetAll,
}

pub(crate) fn encode_get(vault_id: VaultId) -> String {
    format!("{PROTOCOL_VERSION} GET {vault_id}\n")
}

pub(crate) fn encode_put(vault_id: VaultId, key: &[u8]) -> String {
    format!("{PROTOCOL_VERSION} PUT {vault_id} {}\n", encode_hex(key))
}

pub(crate) fn encode_forget(vault_id: VaultId) -> String {
    format!("{PROTOCOL_VERSION} FORGET {vault_id}\n")
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
        [version, "GET", vault_id] if *version == PROTOCOL_VERSION => {
            Ok(AgentRequest::Get((*vault_id).to_string()))
        }
        [version, "PUT", vault_id, key_hex] if *version == PROTOCOL_VERSION => Ok(
            AgentRequest::Put((*vault_id).to_string(), decode_hex(key_hex)?),
        ),
        [version, "FORGET", vault_id] if *version == PROTOCOL_VERSION => {
            Ok(AgentRequest::Forget((*vault_id).to_string()))
        }
        [version, "FORGET_ALL"] if *version == PROTOCOL_VERSION => Ok(AgentRequest::ForgetAll),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid agent request",
        )),
    }
}

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
            AgentRequest::Put(vault_id, key) => {
                assert_eq!(vault_id, "vault");
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
