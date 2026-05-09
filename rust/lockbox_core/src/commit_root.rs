use crate::{Error, Result};

const COMMIT_ROOT_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommitRoot {
    pub(crate) sequence: u64,
    pub(crate) toc_root_offset: u64,
    pub(crate) free_index_root_offset: u64,
    pub(crate) key_directory_offset: u64,
    pub(crate) previous_commit_root_offset: u64,
    pub(crate) flags: u64,
}

pub(crate) fn encode_commit_root(root: &CommitRoot) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 7 + 8 * 6);
    out.push(COMMIT_ROOT_VERSION);
    out.extend_from_slice(&[0; 7]);
    out.extend_from_slice(&root.sequence.to_le_bytes());
    out.extend_from_slice(&root.toc_root_offset.to_le_bytes());
    out.extend_from_slice(&root.free_index_root_offset.to_le_bytes());
    out.extend_from_slice(&root.key_directory_offset.to_le_bytes());
    out.extend_from_slice(&root.previous_commit_root_offset.to_le_bytes());
    out.extend_from_slice(&root.flags.to_le_bytes());
    out
}

pub(crate) fn decode_commit_root(payload: &[u8]) -> Result<CommitRoot> {
    if payload.len() != 1 + 7 + 8 * 6 || payload[0] != COMMIT_ROOT_VERSION {
        return Err(Error::CorruptRecord);
    }
    if payload[1..8].iter().any(|byte| *byte != 0) {
        return Err(Error::CorruptRecord);
    }
    let mut offset = 8usize;
    let sequence = read_u64(payload, &mut offset);
    let toc_root_offset = read_u64(payload, &mut offset);
    let free_index_root_offset = read_u64(payload, &mut offset);
    let key_directory_offset = read_u64(payload, &mut offset);
    let previous_commit_root_offset = read_u64(payload, &mut offset);
    let flags = read_u64(payload, &mut offset);
    if toc_root_offset == 0 {
        return Err(Error::CorruptRecord);
    }
    Ok(CommitRoot {
        sequence,
        toc_root_offset,
        free_index_root_offset,
        key_directory_offset,
        previous_commit_root_offset,
        flags,
    })
}

fn read_u64(payload: &[u8], offset: &mut usize) -> u64 {
    let value = u64::from_le_bytes(payload[*offset..*offset + 8].try_into().unwrap());
    *offset += 8;
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_root_round_trips() {
        let root = CommitRoot {
            sequence: 10,
            toc_root_offset: 100,
            free_index_root_offset: 200,
            key_directory_offset: 300,
            previous_commit_root_offset: 400,
            flags: 0,
        };

        assert_eq!(
            decode_commit_root(&encode_commit_root(&root)).unwrap(),
            root
        );
    }

    #[test]
    fn commit_root_rejects_zero_toc_root() {
        let root = CommitRoot {
            sequence: 10,
            toc_root_offset: 0,
            free_index_root_offset: 0,
            key_directory_offset: 0,
            previous_commit_root_offset: 0,
            flags: 0,
        };

        assert!(matches!(
            decode_commit_root(&encode_commit_root(&root)),
            Err(Error::CorruptRecord)
        ));
    }
}
