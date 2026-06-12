use crate::commit_root::{decode_commit_root, CommitRoot};
use crate::crypto::derive_page_content_key;
use crate::lockbox_id::LockboxId;
use crate::page::{
    decode_page, decode_single_object_page_secure, page_decode_slice,
    physical_page_size_from_page_slice, scan_page_records, PageObjectKind, PAGE_MAGIC,
};
use crate::record::{DecodedRecord, RecordHeader, RecordKind};
use crate::scan::Scan;
use crate::secret_vec::SecureVec;
use crate::{Error, Result};
use zeroize::Zeroize;

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
        let payload = self.commit_root_payload_at(offset)?;
        decode_commit_root(&payload)
    }

    pub(crate) fn commit_root_payload_at(&self, offset: u64) -> Result<Vec<u8>> {
        let page = self.page_at(offset).ok_or(Error::Truncated)?;
        let decoded = decode_page(page, self.lockbox_id, self.key)?;
        let Some(commit_root_object) = decoded
            .objects
            .iter()
            .find(|object| object.kind == PageObjectKind::CommitRoot)
        else {
            return Err(Error::CorruptRecord);
        };
        commit_root_object.with_payload(|payload| payload.to_vec())
    }

    pub(crate) fn commit_auth_payload_at(&self, offset: u64) -> Result<Vec<u8>> {
        let page = self.page_at(offset).ok_or(Error::Truncated)?;
        let decoded = decode_page(page, self.lockbox_id, self.key)?;
        let Some(auth_object) = decoded
            .objects
            .iter()
            .find(|object| object.kind == PageObjectKind::CommitAuth)
        else {
            return Err(Error::CorruptRecord);
        };
        auth_object.with_payload(|payload| payload.to_vec())
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

    pub(crate) fn secure_object_payload_at(
        &self,
        offset: u64,
        expected: &[PageObjectKind],
    ) -> Result<SecureVec> {
        if self.bytes.get(checked_range(offset, 8)?) != Some(PAGE_MAGIC.as_slice()) {
            return Err(Error::CorruptRecord);
        }
        let page = self.page_at(offset).ok_or(Error::Truncated)?;
        let mut secure_page = SecureVec::try_from_slice(page)?;
        let mut content_key = derive_page_content_key(self.key);
        let decoded =
            decode_single_object_page_secure(&mut secure_page, self.lockbox_id, &content_key)?;
        content_key.zeroize();
        let Some(object) = decoded
            .objects
            .into_iter()
            .find(|object| expected.contains(&object.kind))
        else {
            return Err(Error::CorruptRecord);
        };
        Ok(object
            .secure_payload()
            .ok_or(Error::CorruptRecord)?
            .try_clone()?)
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
                total_len: physical_page_size_from_page_slice(page)? as u64,
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
                total_len: physical_page_size_from_page_slice(page)? as u64,
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
        PageObjectKind::VariableSet => RecordKind::Variable,
        PageObjectKind::VariableDelete => RecordKind::VariableDelete,
        PageObjectKind::Delete => RecordKind::Delete,
        PageObjectKind::TocLeaf | PageObjectKind::TocInternal => RecordKind::TocNode,
        PageObjectKind::CommitRoot => RecordKind::CommitRoot,
        PageObjectKind::CommitAuth => RecordKind::CommitAuth,
        PageObjectKind::FreeIndexLeaf | PageObjectKind::FreeIndexInternal => RecordKind::FreeIndex,
        PageObjectKind::KeyDirectory
        | PageObjectKind::VariableLeaf
        | PageObjectKind::VariableInternal
        | PageObjectKind::FormLeaf
        | PageObjectKind::FormInternal => return Err(Error::CorruptRecord),
    })
}
