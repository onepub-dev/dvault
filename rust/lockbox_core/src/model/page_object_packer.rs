use crate::page::{encoded_object_len, uncompressed_objects_fit, PageObject};
use crate::{Error, Result};

#[derive(Debug, Clone)]
pub(crate) struct PackedPageObject<T> {
    pub(crate) object: PageObject,
    pub(crate) context: T,
}

#[derive(Debug, Clone)]
pub(crate) struct PageObjectPacker<T> {
    page_size: usize,
    pending: Vec<PackedPageObject<T>>,
    pending_object_stream_len: usize,
}

impl<T> PageObjectPacker<T> {
    pub(crate) fn new(page_size: usize) -> Self {
        Self {
            page_size,
            pending: Vec::new(),
            pending_object_stream_len: 4,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub(crate) fn pending(&self) -> &[PackedPageObject<T>] {
        &self.pending
    }

    pub(crate) fn clear(&mut self) {
        self.pending.clear();
        self.pending_object_stream_len = 4;
    }

    pub(crate) fn encoded_object_len(&self, object: &PageObject) -> Result<usize> {
        encoded_object_len(object)
    }

    pub(crate) fn fits_encoded_len(&self, encoded_len: usize) -> Result<bool> {
        let stream_len = self
            .pending_object_stream_len
            .checked_add(encoded_len)
            .ok_or_else(|| Error::SecurityLimitExceeded("page is too large".to_string()))?;
        Ok(uncompressed_objects_fit(self.page_size, stream_len))
    }

    pub(crate) fn push_encoded(
        &mut self,
        object: PageObject,
        context: T,
        encoded_len: usize,
    ) -> Result<()> {
        if !self.fits_encoded_len(encoded_len)? {
            return Err(Error::SecurityLimitExceeded(
                "page object does not fit in a page".to_string(),
            ));
        }
        self.pending_object_stream_len = self
            .pending_object_stream_len
            .checked_add(encoded_len)
            .ok_or_else(|| Error::SecurityLimitExceeded("page is too large".to_string()))?;
        self.pending.push(PackedPageObject { object, context });
        Ok(())
    }
}

impl<T> Default for PageObjectPacker<T> {
    fn default() -> Self {
        Self::new(crate::page::DEFAULT_PAGE_BYTES)
    }
}
