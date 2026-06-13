use crate::checked::{read_u16_le, read_u32_le, read_u64_le};
use crate::constants::DEFAULT_MAX_PAGE_LOGICAL_BYTES;
use crate::{Error, Result};
use ruzstd::decoding::FrameDecoder;
use ruzstd::encoding::{compress_to_vec, CompressionLevel};

pub(crate) const COMPRESSION_NONE: u8 = 0;
pub(crate) const COMPRESSION_ZSTD: u8 = 1;
pub(crate) const COMPRESSION_ZSTD_NATIVE: u8 = 2;
const MAX_DECOMPRESSED_PAGE_BODY_BYTES: u64 = DEFAULT_MAX_PAGE_LOGICAL_BYTES as u64;
pub(crate) const MAX_DECOMPRESSED_COMPRESSION_FRAME_BYTES: u64 = 4 * 1024 * 1024;
const MIN_INCOMPRESSIBLE_CHECK_BYTES: usize = 64 * 1024;
const INCOMPRESSIBLE_SAMPLE_BYTES: usize = 16 * 1024;
const HIGH_ENTROPY_BITS_PER_BYTE: f64 = 7.80;
pub(crate) const ZSTD_DEFAULT_LEVEL: i32 = 1;
pub(crate) const ZSTD_BULK_IMPORT_LEVEL: i32 = 3;
const ZSTD_MAGIC: &[u8; 4] = &[0x28, 0xb5, 0x2f, 0xfd];

pub(crate) fn encode_page_body(payload: &[u8]) -> Vec<u8> {
    let (algorithm, stored) = if looks_incompressible(payload) {
        (COMPRESSION_NONE, payload.to_vec())
    } else {
        let compressed = zstd_encode(payload, ZSTD_DEFAULT_LEVEL);
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

pub(crate) fn decode_page_body(body: &[u8]) -> Result<Vec<u8>> {
    if body.len() < 17 {
        return Err(Error::CorruptRecord);
    }
    let real_len = read_u64_le(&body[0..8])?;
    if real_len > MAX_DECOMPRESSED_PAGE_BODY_BYTES {
        return Err(Error::SecurityLimitExceeded(format!(
            "page body expands to {real_len} bytes"
        )));
    }
    let algorithm = body[8];
    let stored_len = read_u64_le(&body[9..17])?;
    let stored_len = usize::try_from(stored_len).map_err(|_| Error::CorruptRecord)?;
    if stored_len > body.len() - 17 {
        return Err(Error::CorruptRecord);
    }
    let stored = &body[17..17 + stored_len];
    let decoded = match algorithm {
        COMPRESSION_NONE => stored.to_vec(),
        COMPRESSION_ZSTD => zstd_decode(stored, real_len)?,
        _ => return Err(Error::CorruptRecord),
    };
    if decoded.len() as u64 != real_len {
        return Err(Error::CorruptRecord);
    }
    Ok(decoded)
}

fn zstd_encode(payload: &[u8], level: i32) -> Vec<u8> {
    compress_to_vec(payload, ruzstd_level(level))
}

#[cfg(feature = "native-zstd-encoder")]
fn zstd_encode_compression_frame(payload: &[u8], level: i32) -> Vec<u8> {
    zstd::bulk::compress(payload, level)
        .expect("native zstd compression should not fail for an in-memory buffer")
}

#[cfg(not(feature = "native-zstd-encoder"))]
fn zstd_encode_compression_frame(payload: &[u8], level: i32) -> Vec<u8> {
    zstd_encode(payload, level)
}

fn zstd_decode(stored: &[u8], expected_len: u64) -> Result<Vec<u8>> {
    let expected_len = usize::try_from(expected_len).map_err(|_| Error::CorruptRecord)?;
    let mut decoded = Vec::with_capacity(expected_len);
    FrameDecoder::new()
        .decode_all_to_vec(stored, &mut decoded)
        .map_err(|_| Error::CorruptRecord)?;
    Ok(decoded)
}

fn ruzstd_level(level: i32) -> CompressionLevel {
    match level {
        i32::MIN..=0 => CompressionLevel::Uncompressed,
        1 => CompressionLevel::Fastest,
        2..=3 => CompressionLevel::Default,
        4..=6 => CompressionLevel::Better,
        _ => CompressionLevel::Best,
    }
}

#[cfg(feature = "native-zstd-encoder")]
fn zstd_decode_native(stored: &[u8], expected_len: u64) -> Result<Vec<u8>> {
    let expected_len = usize::try_from(expected_len).map_err(|_| Error::CorruptRecord)?;
    zstd::bulk::decompress(stored, expected_len).map_err(|_| Error::CorruptRecord)
}

pub(crate) fn encode_compression_frame(payload: &[u8]) -> (u8, Vec<u8>) {
    encode_compression_frame_with_level(payload, ZSTD_DEFAULT_LEVEL)
}

pub(crate) fn encode_compression_frame_with_level(payload: &[u8], level: i32) -> (u8, Vec<u8>) {
    if looks_incompressible(payload) {
        return (COMPRESSION_NONE, payload.to_vec());
    }
    let compressed = zstd_encode_compression_frame(payload, level);
    if compressed.len() < payload.len() {
        (compression_frame_zstd_algorithm(), compressed)
    } else {
        (COMPRESSION_NONE, payload.to_vec())
    }
}

#[cfg(feature = "native-zstd-encoder")]
fn compression_frame_zstd_algorithm() -> u8 {
    COMPRESSION_ZSTD_NATIVE
}

#[cfg(not(feature = "native-zstd-encoder"))]
fn compression_frame_zstd_algorithm() -> u8 {
    COMPRESSION_ZSTD
}

pub(crate) fn decode_compression_frame(
    algorithm: u8,
    stored: &[u8],
    expected_len: u64,
) -> Result<Vec<u8>> {
    if expected_len > MAX_DECOMPRESSED_COMPRESSION_FRAME_BYTES {
        return Err(Error::SecurityLimitExceeded(format!(
            "compression frame expands to {expected_len} bytes"
        )));
    }
    let decoded = match algorithm {
        COMPRESSION_NONE => stored.to_vec(),
        COMPRESSION_ZSTD => {
            if let Some(declared_len) = zstd_declared_content_size(stored)? {
                if declared_len != expected_len {
                    return Err(Error::CorruptRecord);
                }
            }
            let decoded = zstd_decode(stored, expected_len)?;
            if decoded.len() as u64 != expected_len {
                return Err(Error::CorruptRecord);
            }
            decoded
        }
        COMPRESSION_ZSTD_NATIVE => {
            #[cfg(feature = "native-zstd-encoder")]
            {
                let declared_len =
                    zstd_declared_content_size(stored)?.ok_or(Error::CorruptRecord)?;
                if declared_len != expected_len {
                    return Err(Error::CorruptRecord);
                }
                zstd_decode_native(stored, expected_len)?
            }
            #[cfg(not(feature = "native-zstd-encoder"))]
            {
                return Err(Error::InvalidOperation(
                    "lockbox uses native zstd compression; rebuild with native-zstd-encoder support"
                        .to_string(),
                ));
            }
        }
        _ => return Err(Error::CorruptRecord),
    };
    if decoded.len() as u64 != expected_len {
        return Err(Error::CorruptRecord);
    }
    Ok(decoded)
}

fn zstd_declared_content_size(stored: &[u8]) -> Result<Option<u64>> {
    if stored.len() < 5 || stored.get(0..4) != Some(ZSTD_MAGIC.as_slice()) {
        return Err(Error::CorruptRecord);
    }
    let descriptor = stored[4];
    let single_segment = (descriptor & 0x20) != 0;
    let dict_id_flag = descriptor & 0x03;
    let content_size_flag = (descriptor & 0xc0) >> 6;
    let mut cursor = 5usize;
    if !single_segment {
        if cursor >= stored.len() {
            return Err(Error::CorruptRecord);
        }
        cursor += 1;
    }
    let dict_id_bytes = match dict_id_flag {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        _ => unreachable!(),
    };
    if stored.len().saturating_sub(cursor) < dict_id_bytes {
        return Err(Error::CorruptRecord);
    }
    cursor += dict_id_bytes;
    if !single_segment && content_size_flag == 0 {
        return Ok(None);
    }
    let size_bytes = match content_size_flag {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };
    if stored.len().saturating_sub(cursor) < size_bytes {
        return Err(Error::CorruptRecord);
    }
    let size = match size_bytes {
        1 => u64::from(stored[cursor]),
        2 => u64::from(read_u16_le(&stored[cursor..cursor + 2])?) + 256,
        4 => u64::from(read_u32_le(&stored[cursor..cursor + 4])?),
        8 => read_u64_le(&stored[cursor..cursor + 8])?,
        _ => unreachable!(),
    };
    Ok(Some(size))
}

pub(crate) fn looks_incompressible(payload: &[u8]) -> bool {
    if payload.len() < MIN_INCOMPRESSIBLE_CHECK_BYTES {
        return false;
    }

    let (counts, len) = entropy_sample_counts(payload);
    shannon_entropy_bits_per_byte(&counts, len) >= HIGH_ENTROPY_BITS_PER_BYTE
}

fn entropy_sample_counts(payload: &[u8]) -> ([usize; 256], usize) {
    let mut counts = [0usize; 256];
    if payload.len() <= INCOMPRESSIBLE_SAMPLE_BYTES {
        count_bytes(payload, &mut counts);
        return (counts, payload.len());
    }

    let chunk_len = INCOMPRESSIBLE_SAMPLE_BYTES / 4;
    let offsets = [
        0,
        payload.len() / 3,
        payload.len().saturating_mul(2) / 3,
        payload.len().saturating_sub(chunk_len),
    ];
    for offset in offsets {
        count_bytes(&payload[offset..offset + chunk_len], &mut counts);
    }
    (counts, INCOMPRESSIBLE_SAMPLE_BYTES)
}

fn count_bytes(bytes: &[u8], counts: &mut [usize; 256]) {
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
}

fn shannon_entropy_bits_per_byte(counts: &[usize; 256], len: usize) -> f64 {
    let len = len as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / len;
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
        body.extend_from_slice(&(MAX_DECOMPRESSED_PAGE_BODY_BYTES + 1).to_le_bytes());
        body.push(COMPRESSION_NONE);
        body.extend_from_slice(&0u64.to_le_bytes());

        assert!(matches!(
            decode_page_body(&body),
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

        assert!(matches!(decode_page_body(&body), Err(Error::CorruptRecord)));
    }

    #[test]
    fn rejects_uncompressed_len_mismatch() {
        let mut body = Vec::new();
        body.extend_from_slice(&2u64.to_le_bytes());
        body.push(COMPRESSION_NONE);
        body.extend_from_slice(&1u64.to_le_bytes());
        body.push(b'x');

        assert!(matches!(decode_page_body(&body), Err(Error::CorruptRecord)));
    }

    #[test]
    fn repeated_payload_is_compressed() {
        let payload = vec![b'x'; MIN_INCOMPRESSIBLE_CHECK_BYTES * 2];
        let body = encode_page_body(&payload);

        assert_eq!(body[8], COMPRESSION_ZSTD);
        assert!(body.len() < payload.len());
        assert_eq!(decode_page_body(&body).unwrap(), payload);
    }

    #[test]
    fn high_entropy_payload_skips_zstd_probe() {
        let mut payload = vec![0u8; MIN_INCOMPRESSIBLE_CHECK_BYTES * 2];
        fill_randomish(&mut payload);
        let body = encode_page_body(&payload);

        assert_eq!(body[8], COMPRESSION_NONE);
        assert_eq!(decode_page_body(&body).unwrap(), payload);
    }

    #[test]
    fn archive_like_high_entropy_compression_frame_stays_uncompressed() {
        let payload = archive_like_randomish_payload(MIN_INCOMPRESSIBLE_CHECK_BYTES * 2);
        let (algorithm, stored) =
            encode_compression_frame_with_level(&payload, ZSTD_BULK_IMPORT_LEVEL);

        assert_eq!(algorithm, COMPRESSION_NONE);
        assert_eq!(stored, payload);
        assert_eq!(
            decode_compression_frame(algorithm, &stored, payload.len() as u64).unwrap(),
            payload
        );
    }

    #[test]
    fn compression_frame_rejects_declared_bomb_before_allocating() {
        assert!(matches!(
            decode_compression_frame(
                COMPRESSION_NONE,
                &[],
                MAX_DECOMPRESSED_COMPRESSION_FRAME_BYTES + 1
            ),
            Err(Error::SecurityLimitExceeded(_))
        ));
    }

    #[test]
    fn zstd_compression_frame_rejects_content_size_mismatch_before_decode() {
        let payload = vec![b'x'; 4096];
        let (_, stored) = encode_compression_frame(&payload);

        assert!(matches!(
            decode_compression_frame(COMPRESSION_ZSTD, &stored, payload.len() as u64 + 1),
            Err(Error::CorruptRecord)
        ));
    }

    #[cfg(not(feature = "native-zstd-encoder"))]
    #[test]
    fn native_zstd_compression_frame_requires_feature() {
        let err = decode_compression_frame(COMPRESSION_ZSTD_NATIVE, &[], 0).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidOperation(message)
                if message.contains("native zstd compression")
                    && message.contains("native-zstd-encoder")
        ));
    }

    #[cfg(feature = "native-zstd-encoder")]
    #[test]
    fn native_zstd_compression_frame_round_trips_with_feature() {
        let payload = b"native backend compatibility ".repeat(4096);
        let (algorithm, stored) = encode_compression_frame_with_level(&payload, 1);

        assert_eq!(algorithm, COMPRESSION_ZSTD_NATIVE);
        assert_eq!(
            zstd_declared_content_size(&stored).unwrap(),
            Some(payload.len() as u64)
        );
        assert_eq!(
            decode_compression_frame(algorithm, &stored, payload.len() as u64).unwrap(),
            payload
        );
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

    fn archive_like_randomish_payload(len: usize) -> Vec<u8> {
        let mut payload = vec![0u8; len];
        fill_randomish(&mut payload);
        payload[0..4].copy_from_slice(b"PK\x03\x04");
        payload[4..6].copy_from_slice(&20u16.to_le_bytes());
        payload[6..8].copy_from_slice(&0u16.to_le_bytes());
        payload[8..10].copy_from_slice(&8u16.to_le_bytes());
        payload[26..28].copy_from_slice(&8u16.to_le_bytes());
        payload[30..38].copy_from_slice(b"data.bin");
        payload
    }
}
