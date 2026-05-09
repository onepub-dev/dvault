use std::io::Cursor;

use crate::constants::DEFAULT_MAX_SEGMENT_BODY_BYTES;
use crate::{Error, Result};

const COMPRESSION_NONE: u8 = 0;
const COMPRESSION_ZSTD: u8 = 1;
const MAX_DECOMPRESSED_SEGMENT_BODY_BYTES: u64 = (DEFAULT_MAX_SEGMENT_BODY_BYTES as u64) * 8;

pub(crate) fn encode_segment_body(payload: &[u8]) -> Vec<u8> {
    let compressed = zstd::stream::encode_all(Cursor::new(payload), 3)
        .expect("zstd compression should not fail for an in-memory buffer");
    let (algorithm, stored) = if compressed.len() < payload.len() {
        (COMPRESSION_ZSTD, compressed)
    } else {
        (COMPRESSION_NONE, payload.to_vec())
    };

    let mut body = Vec::with_capacity(17 + stored.len());
    body.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    body.push(algorithm);
    body.extend_from_slice(&(stored.len() as u64).to_le_bytes());
    body.extend_from_slice(&stored);
    body
}

pub(crate) fn decode_segment_body(body: &[u8]) -> Result<Vec<u8>> {
    if body.len() < 17 {
        return Err(Error::CorruptRecord);
    }
    let real_len = u64::from_le_bytes(body[0..8].try_into().unwrap());
    if real_len > MAX_DECOMPRESSED_SEGMENT_BODY_BYTES {
        return Err(Error::SecurityLimitExceeded(format!(
            "segment body expands to {real_len} bytes"
        )));
    }
    let algorithm = body[8];
    let stored_len = u64::from_le_bytes(body[9..17].try_into().unwrap());
    let stored_len = usize::try_from(stored_len).map_err(|_| Error::CorruptRecord)?;
    if stored_len > body.len() - 17 {
        return Err(Error::CorruptRecord);
    }
    let stored = &body[17..17 + stored_len];
    let decoded = match algorithm {
        COMPRESSION_NONE => stored.to_vec(),
        COMPRESSION_ZSTD => {
            zstd::stream::decode_all(Cursor::new(stored)).map_err(|_| Error::CorruptRecord)?
        }
        _ => return Err(Error::CorruptRecord),
    };
    if decoded.len() as u64 != real_len {
        return Err(Error::CorruptRecord);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_declared_decompression_bomb_before_allocating() {
        let mut body = Vec::new();
        body.extend_from_slice(&(MAX_DECOMPRESSED_SEGMENT_BODY_BYTES + 1).to_le_bytes());
        body.push(COMPRESSION_NONE);
        body.extend_from_slice(&0u64.to_le_bytes());

        assert!(matches!(
            decode_segment_body(&body),
            Err(Error::SecurityLimitExceeded(_))
        ));
    }

    #[test]
    fn rejects_stored_len_past_buffer() {
        let mut body = Vec::new();
        body.extend_from_slice(&1u64.to_le_bytes());
        body.push(COMPRESSION_NONE);
        body.extend_from_slice(&2u64.to_le_bytes());
        body.push(b'x');

        assert!(matches!(
            decode_segment_body(&body),
            Err(Error::CorruptRecord)
        ));
    }

    #[test]
    fn rejects_uncompressed_len_mismatch() {
        let mut body = Vec::new();
        body.extend_from_slice(&2u64.to_le_bytes());
        body.push(COMPRESSION_NONE);
        body.extend_from_slice(&1u64.to_le_bytes());
        body.push(b'x');

        assert!(matches!(
            decode_segment_body(&body),
            Err(Error::CorruptRecord)
        ));
    }
}
