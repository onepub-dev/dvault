use crate::constants::DEFAULT_MAX_SEGMENT_LOGICAL_BYTES;
use crate::{Error, Result};

const COMPRESSION_NONE: u8 = 0;
const COMPRESSION_ZSTD: u8 = 1;
const MAX_DECOMPRESSED_SEGMENT_BODY_BYTES: u64 = DEFAULT_MAX_SEGMENT_LOGICAL_BYTES as u64;
const MIN_INCOMPRESSIBLE_CHECK_BYTES: usize = 64 * 1024;
const INCOMPRESSIBLE_SAMPLE_BYTES: usize = 16 * 1024;
const HIGH_ENTROPY_BITS_PER_BYTE: f64 = 7.80;
const ZSTD_DEFAULT_LEVEL: i32 = 1;

pub(crate) fn encode_segment_body(payload: &[u8]) -> Vec<u8> {
    let (algorithm, stored) = if looks_incompressible(payload) {
        (COMPRESSION_NONE, payload.to_vec())
    } else {
        let compressed = zstd_encode(payload);
        if compressed.len() < payload.len() {
            (COMPRESSION_ZSTD, compressed)
        } else {
            (COMPRESSION_NONE, payload.to_vec())
        }
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
        COMPRESSION_ZSTD => zstd_decode(stored)?,
        _ => return Err(Error::CorruptRecord),
    };
    if decoded.len() as u64 != real_len {
        return Err(Error::CorruptRecord);
    }
    Ok(decoded)
}

fn zstd_encode(payload: &[u8]) -> Vec<u8> {
    oxiarc_zstd::encode_all(payload, ZSTD_DEFAULT_LEVEL)
        .expect("zstd compression should not fail for an in-memory buffer")
}

fn zstd_decode(stored: &[u8]) -> Result<Vec<u8>> {
    oxiarc_zstd::decode_all(stored).map_err(|_| Error::CorruptRecord)
}

pub(crate) fn looks_incompressible(payload: &[u8]) -> bool {
    if payload.len() < MIN_INCOMPRESSIBLE_CHECK_BYTES {
        return false;
    }

    let sample = sample_for_entropy(payload);
    shannon_entropy_bits_per_byte(&sample) >= HIGH_ENTROPY_BITS_PER_BYTE
}

fn sample_for_entropy(payload: &[u8]) -> Vec<u8> {
    if payload.len() <= INCOMPRESSIBLE_SAMPLE_BYTES {
        return payload.to_vec();
    }

    let mut sample = Vec::with_capacity(INCOMPRESSIBLE_SAMPLE_BYTES);
    let chunk_len = INCOMPRESSIBLE_SAMPLE_BYTES / 4;
    let offsets = [
        0,
        payload.len() / 3,
        payload.len().saturating_mul(2) / 3,
        payload.len().saturating_sub(chunk_len),
    ];
    for offset in offsets {
        sample.extend_from_slice(&payload[offset..offset + chunk_len]);
    }
    sample
}

fn shannon_entropy_bits_per_byte(sample: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for byte in sample {
        counts[*byte as usize] += 1;
    }

    let len = sample.len() as f64;
    counts
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let probability = count as f64 / len;
            -probability * probability.log2()
        })
        .sum()
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

    #[test]
    fn repeated_payload_is_compressed() {
        let payload = vec![b'x'; MIN_INCOMPRESSIBLE_CHECK_BYTES * 2];
        let body = encode_segment_body(&payload);

        assert_eq!(body[8], COMPRESSION_ZSTD);
        assert!(body.len() < payload.len());
        assert_eq!(decode_segment_body(&body).unwrap(), payload);
    }

    #[test]
    fn high_entropy_payload_skips_zstd_probe() {
        let mut payload = vec![0u8; MIN_INCOMPRESSIBLE_CHECK_BYTES * 2];
        fill_randomish(&mut payload);
        let body = encode_segment_body(&payload);

        assert_eq!(body[8], COMPRESSION_NONE);
        assert_eq!(decode_segment_body(&body).unwrap(), payload);
    }

    fn fill_randomish(buf: &mut [u8]) {
        for (i, byte) in buf.iter_mut().enumerate() {
            let mut value = i as u64;
            value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            *byte = (value ^ (value >> 31)) as u8;
        }
    }
}
