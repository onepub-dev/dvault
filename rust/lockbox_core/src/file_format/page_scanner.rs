use crate::commit_root::{decode_commit_root, CommitRoot};
use crate::file_chunk::DecodedFileChunk;
use crate::file_format::decode_file_fragment_payload;
use crate::lockbox_id::LockboxId;
use crate::page::{
    decode_page, page_decode_slice, page_size_for_objects, scan_page_records, PageObjectKind,
    PAGE_MAGIC,
};
use crate::record::{DecodedRecord, RecordHeader, RecordKind};
use crate::scan::Scan;
use crate::{Error, Result};

pub(crate) struct PageScanner<'a> {
    bytes: &'a [u8],
    lockbox_id: LockboxId,
    key: &'a [u8],
}

impl<'a> PageScanner<'a> {
    pub(crate) fn new(bytes: &'a [u8], lockbox_id: LockboxId, key: &'a [u8]) -> Self {
        Self {
            bytes,
            lockbox_id,
            key,
        }
    }

    pub(crate) fn scan_records(&self) -> Scan {
        scan_page_records(self.bytes, self.lockbox_id, self.key)
    }

    pub(crate) fn commit_root_at(&self, offset: u64) -> Result<CommitRoot> {
        let page = self.page_at(offset).ok_or(Error::Truncated)?;
        let decoded = decode_page(page, self.lockbox_id, self.key)?;
        let Some(commit_root_object) = decoded
            .objects
            .iter()
            .find(|object| object.kind == PageObjectKind::CommitRoot)
        else {
            return Err(Error::CorruptRecord);
        };
        commit_root_object.with_payload(decode_commit_root)?
    }

    pub(crate) fn toc_node_payload_at(&self, offset: u64) -> Result<Vec<u8>> {
        if self.bytes.get(checked_range(offset, 8)?) != Some(PAGE_MAGIC.as_slice()) {
            return Err(Error::CorruptRecord);
        }
        let page = self.page_at(offset).ok_or(Error::Truncated)?;
        let decoded = decode_page(page, self.lockbox_id, self.key)?;
        let Some(toc_object) = decoded.objects.iter().find(|object| {
            matches!(
                object.kind,
                PageObjectKind::TocLeaf | PageObjectKind::TocInternal
            )
        }) else {
            return Err(Error::CorruptRecord);
        };
        toc_object.with_payload(|payload| payload.to_vec())
    }

    pub(crate) fn file_fragment_at(&self, offset: u64, object_id: u64) -> Result<DecodedFileChunk> {
        let page = self.page_at(offset).ok_or(Error::Truncated)?;
        let decoded = decode_page(page, self.lockbox_id, self.key)?;
        let Some(object) = decoded.objects.iter().find(|object| object.id == object_id) else {
            return Err(Error::CorruptRecord);
        };
        object.with_payload(decode_file_fragment_payload)?
    }

    pub(crate) fn record_at(&self, offset: u64) -> Result<DecodedRecord> {
        let page = self.page_at(offset).ok_or(Error::Truncated)?;
        let decoded = decode_page(page, self.lockbox_id, self.key)?;
        let Some(object) = decoded.objects.first() else {
            return Err(Error::CorruptRecord);
        };
        let kind = record_kind_from_page_object(object.kind)?;
        Ok(DecodedRecord {
            header: RecordHeader {
                kind,
                sequence: decoded.sequence,
                total_len: page_size_for_objects(&decoded.objects) as u64,
            },
            offset,
            object_id: object.id,
            payload: object.with_payload(|payload| payload.to_vec())?,
        })
    }

    pub(crate) fn record_object_at(&self, offset: u64, object_id: u64) -> Result<DecodedRecord> {
        let page = self.page_at(offset).ok_or(Error::Truncated)?;
        let decoded = decode_page(page, self.lockbox_id, self.key)?;
        let Some(object) = decoded.objects.iter().find(|object| object.id == object_id) else {
            return Err(Error::CorruptRecord);
        };
        let kind = record_kind_from_page_object(object.kind)?;
        Ok(DecodedRecord {
            header: RecordHeader {
                kind,
                sequence: decoded.sequence,
                total_len: page_size_for_objects(&decoded.objects) as u64,
            },
            offset,
            object_id: object.id,
            payload: object.with_payload(|payload| payload.to_vec())?,
        })
    }

    fn page_at(&self, offset: u64) -> Option<&'a [u8]> {
        page_decode_slice(self.bytes, usize::try_from(offset).ok()?)
    }
}

fn checked_range(offset: u64, len: usize) -> Result<std::ops::Range<usize>> {
    let start = usize::try_from(offset).map_err(|_| Error::CorruptRecord)?;
    let end = start.checked_add(len).ok_or(Error::CorruptRecord)?;
    Ok(start..end)
}

fn record_kind_from_page_object(kind: PageObjectKind) -> Result<RecordKind> {
    Ok(match kind {
        PageObjectKind::PackedFileData | PageObjectKind::FileData => RecordKind::FilePage,
        PageObjectKind::Symlink => RecordKind::Symlink,
        PageObjectKind::EnvSet => RecordKind::Env,
        PageObjectKind::EnvDelete => RecordKind::EnvDelete,
        PageObjectKind::Delete => RecordKind::Delete,
        PageObjectKind::TocLeaf | PageObjectKind::TocInternal => RecordKind::TocNode,
        PageObjectKind::CommitRoot => RecordKind::CommitRoot,
        PageObjectKind::FreeIndexLeaf | PageObjectKind::FreeIndexInternal => RecordKind::FreeIndex,
        PageObjectKind::KeyDirectory | PageObjectKind::EnvLeaf | PageObjectKind::EnvInternal => {
            return Err(Error::CorruptRecord);
        }
    })
}
