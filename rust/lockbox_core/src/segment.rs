use crate::compression::{decode_segment_body, encode_segment_body};
use crate::constants::{
    DEFAULT_MIN_SEGMENT_BODY_BYTES, HEADER_LEN, RECORD_HEADER_LEN, RECORD_MAGIC,
};
use crate::crypto::{checksum, open, seal};
use crate::record::{DecodedRecord, RecordHeader, RecordKind};
use crate::scan::Scan;
use crate::{Error, Result};

pub(crate) fn encode_record(
    kind: RecordKind,
    sequence: u64,
    payload: &[u8],
    key: &[u8],
) -> Vec<u8> {
    let body = pad_segment_body(payload);
    let encrypted = seal(&body, key, sequence, kind as u8);
    let payload_crc = checksum(&encrypted);
    let total_len = (RECORD_HEADER_LEN + encrypted.len()) as u64;
    let mut out = vec![0; RECORD_HEADER_LEN];
    out[0..8].copy_from_slice(RECORD_MAGIC);
    out[8] = kind as u8;
    out[10..18].copy_from_slice(&sequence.to_le_bytes());
    out[18..26].copy_from_slice(&(encrypted.len() as u64).to_le_bytes());
    out[26..34].copy_from_slice(&total_len.to_le_bytes());
    out[34..38].copy_from_slice(&payload_crc.to_le_bytes());
    let header_crc = checksum(&out[0..44]);
    out[44..48].copy_from_slice(&header_crc.to_le_bytes());
    out.extend_from_slice(&encrypted);
    out
}

pub(crate) fn read_record(bytes: &[u8], offset: u64, key: &[u8]) -> Result<DecodedRecord> {
    let start = offset as usize;
    if start + RECORD_HEADER_LEN > bytes.len() {
        return Err(Error::Truncated);
    }
    if &bytes[start..start + 8] != RECORD_MAGIC {
        return Err(Error::CorruptRecord);
    }
    let kind = RecordKind::from_u8(bytes[start + 8]).ok_or(Error::CorruptRecord)?;
    let sequence = u64::from_le_bytes(bytes[start + 10..start + 18].try_into().unwrap());
    let payload_len = u64::from_le_bytes(bytes[start + 18..start + 26].try_into().unwrap());
    let total_len = u64::from_le_bytes(bytes[start + 26..start + 34].try_into().unwrap());
    let payload_crc = u32::from_le_bytes(bytes[start + 34..start + 38].try_into().unwrap());
    let header_crc = u32::from_le_bytes(bytes[start + 44..start + 48].try_into().unwrap());
    if checksum(&bytes[start..start + 44]) != header_crc {
        return Err(Error::CorruptRecord);
    }
    if total_len != RECORD_HEADER_LEN as u64 + payload_len {
        return Err(Error::CorruptRecord);
    }
    let payload_start = start + RECORD_HEADER_LEN;
    let payload_end = payload_start + payload_len as usize;
    if payload_end > bytes.len() {
        return Err(Error::Truncated);
    }
    let encrypted = &bytes[payload_start..payload_end];
    if checksum(encrypted) != payload_crc {
        return Err(Error::CorruptRecord);
    }
    let body = open(encrypted, key, sequence, kind as u8)?;
    let payload = unpad_segment_body(&body)?;
    Ok(DecodedRecord {
        header: RecordHeader {
            kind,
            sequence,
            total_len,
        },
        offset,
        payload,
    })
}

pub(crate) fn scan_records(bytes: &[u8], key: &[u8]) -> Scan {
    let mut records = Vec::new();
    let mut corrupt_records = 0;
    let mut i = HEADER_LEN;
    while i + RECORD_HEADER_LEN <= bytes.len() {
        if &bytes[i..i + 8] == RECORD_MAGIC {
            match read_record(bytes, i as u64, key) {
                Ok(record) => {
                    let total_len = record.header.total_len as usize;
                    records.push(record);
                    i += total_len.max(1);
                }
                Err(_) => {
                    corrupt_records += 1;
                    i += 1;
                }
            }
        } else {
            i += 1;
        }
    }
    records.sort_by_key(|record| record.header.sequence);
    Scan {
        records,
        corrupt_records,
    }
}

fn pad_segment_body(payload: &[u8]) -> Vec<u8> {
    let encoded = encode_segment_body(payload);
    let min_len = DEFAULT_MIN_SEGMENT_BODY_BYTES.max(encoded.len());
    let mut body = Vec::with_capacity(min_len);
    body.extend_from_slice(&encoded);
    body.resize(min_len, 0);
    body
}

fn unpad_segment_body(body: &[u8]) -> Result<Vec<u8>> {
    decode_segment_body(body)
}
