use crate::checked::read_u64_le;
use crate::{Error, Result};

const COMMIT_ROOT_VERSION: u8 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommitRoot {
    pub(crate) sequence: u64,
    pub(crate) toc_root_offset: u64,
    pub(crate) variable_root_offset: u64,
    pub(crate) form_root_offset: u64,
    pub(crate) free_index_root_offset: u64,
    pub(crate) key_directory_offset: u64,
    pub(crate) key_directory_mirror_offsets: [u64; 2],
    pub(crate) key_directory_generation: u64,
    pub(crate) previous_commit_root_offset: u64,
    pub(crate) flags: u64,
}

pub(crate) fn encode_commit_root(root: &CommitRoot) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 7 + 8 * 11);
    out.push(COMMIT_ROOT_VERSION);
    out.extend_from_slice(&[0; 7]);
    out.extend_from_slice(&root.sequence.to_le_bytes());
    out.extend_from_slice(&root.toc_root_offset.to_le_bytes());
    out.extend_from_slice(&root.variable_root_offset.to_le_bytes());
    out.extend_from_slice(&root.form_root_offset.to_le_bytes());
    out.extend_from_slice(&root.free_index_root_offset.to_le_bytes());
    out.extend_from_slice(&root.key_directory_offset.to_le_bytes());
    out.extend_from_slice(&root.key_directory_mirror_offsets[0].to_le_bytes());
    out.extend_from_slice(&root.key_directory_mirror_offsets[1].to_le_bytes());
    out.extend_from_slice(&root.key_directory_generation.to_le_bytes());
    out.extend_from_slice(&root.previous_commit_root_offset.to_le_bytes());
    out.extend_from_slice(&root.flags.to_le_bytes());
    out
}

pub(crate) fn decode_commit_root(payload: &[u8]) -> Result<CommitRoot> {
    if payload.len() != 1 + 7 + 8 * 11 || payload[0] != COMMIT_ROOT_VERSION {
        return Err(Error::CorruptRecord);
    }
    if payload[1..8].iter().any(|byte| *byte != 0) {
        return Err(Error::CorruptRecord);
    }
    let mut offset = 8usize;
    let sequence = read_u64(payload, &mut offset)?;
    let toc_root_offset = read_u64(payload, &mut offset)?;
    let variable_root_offset = read_u64(payload, &mut offset)?;
    let form_root_offset = read_u64(payload, &mut offset)?;
    let free_index_root_offset = read_u64(payload, &mut offset)?;
    let key_directory_offset = read_u64(payload, &mut offset)?;
    let key_directory_mirror_offsets = [
        read_u64(payload, &mut offset)?,
        read_u64(payload, &mut offset)?,
    ];
    let key_directory_generation = read_u64(payload, &mut offset)?;
    let previous_commit_root_offset = read_u64(payload, &mut offset)?;
    let flags = read_u64(payload, &mut offset)?;
    if toc_root_offset == 0 {
        return Err(Error::CorruptRecord);
    }
    Ok(CommitRoot {
        sequence,
        toc_root_offset,
        variable_root_offset,
        form_root_offset,
        free_index_root_offset,
        key_directory_offset,
        key_directory_mirror_offsets,
        key_directory_generation,
        previous_commit_root_offset,
        flags,
    })
}

fn read_u64(payload: &[u8], offset: &mut usize) -> Result<u64> {
    let value = read_u64_le(&payload[*offset..*offset + 8])?;
    *offset += 8;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_root_round_trips() {
        let root = CommitRoot {
            sequence: 10,
            toc_root_offset: 100,
            variable_root_offset: 150,
            form_root_offset: 175,
            free_index_root_offset: 200,
            key_directory_offset: 300,
            key_directory_mirror_offsets: [301, 302],
            key_directory_generation: 10,
            previous_commit_root_offset: 400,
            flags: 0,
        };

        assert_eq!(
            decode_commit_root(&encode_commit_root(&root)).unwrap(),
            root
        );
    }

    #[test]
    fn commit_root_numeric_fields_are_little_endian() {
        let root = CommitRoot {
            sequence: 0x0102_0304_0506_0708,
            toc_root_offset: 0x1112_1314_1516_1718,
            variable_root_offset: 0x2122_2324_2526_2728,
            form_root_offset: 0x3132_3334_3536_3738,
            free_index_root_offset: 0x4142_4344_4546_4748,
            key_directory_offset: 0x5152_5354_5556_5758,
            key_directory_mirror_offsets: [0x6162_6364_6566_6768, 0x7172_7374_7576_7778],
            key_directory_generation: 0x8182_8384_8586_8788,
            previous_commit_root_offset: 0x9192_9394_9596_9798,
            flags: 0xa1a2_a3a4_a5a6_a7a8,
        };
        let encoded = encode_commit_root(&root);

        assert_eq!(encoded[0], COMMIT_ROOT_VERSION);
        assert_eq!(
            &encoded[8..16],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(
            &encoded[16..24],
            &[0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]
        );
        assert_eq!(
            &encoded[24..32],
            &[0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21]
        );
        assert_eq!(
            &encoded[32..40],
            &[0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31]
        );
        assert_eq!(
            &encoded[40..48],
            &[0x48, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41]
        );
        assert_eq!(
            &encoded[48..56],
            &[0x58, 0x57, 0x56, 0x55, 0x54, 0x53, 0x52, 0x51]
        );
        assert_eq!(
            &encoded[56..64],
            &[0x68, 0x67, 0x66, 0x65, 0x64, 0x63, 0x62, 0x61]
        );
        assert_eq!(
            &encoded[64..72],
            &[0x78, 0x77, 0x76, 0x75, 0x74, 0x73, 0x72, 0x71]
        );
        assert_eq!(
            &encoded[72..80],
            &[0x88, 0x87, 0x86, 0x85, 0x84, 0x83, 0x82, 0x81]
        );
        assert_eq!(
            &encoded[80..88],
            &[0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91]
        );
        assert_eq!(
            &encoded[88..96],
            &[0xa8, 0xa7, 0xa6, 0xa5, 0xa4, 0xa3, 0xa2, 0xa1]
        );
        assert_eq!(decode_commit_root(&encoded).unwrap(), root);
    }

    #[test]
    fn commit_root_rejects_zero_toc_root() {
        let root = CommitRoot {
            sequence: 10,
            toc_root_offset: 0,
            variable_root_offset: 0,
            form_root_offset: 0,
            free_index_root_offset: 0,
            key_directory_offset: 0,
            key_directory_mirror_offsets: [0, 0],
            key_directory_generation: 0,
            previous_commit_root_offset: 0,
            flags: 0,
        };

        assert!(matches!(
            decode_commit_root(&encode_commit_root(&root)),
            Err(Error::CorruptRecord)
        ));
    }
}
