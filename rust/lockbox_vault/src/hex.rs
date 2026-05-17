use std::io;

/// Encodes bytes as lowercase hexadecimal text.
pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Decodes hexadecimal text into bytes.
///
/// Both uppercase and lowercase digits are accepted. Invalid input is reported
/// as `io::ErrorKind::InvalidData`.
pub fn decode_hex(text: &str) -> io::Result<Vec<u8>> {
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
