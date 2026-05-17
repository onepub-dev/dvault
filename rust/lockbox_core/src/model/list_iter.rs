use crate::{LockboxEntry, Result};

pub struct ListIter<'a> {
    inner: Box<dyn Iterator<Item = Result<LockboxEntry>> + 'a>,
}

impl<'a> ListIter<'a> {
    pub(crate) fn new(inner: Box<dyn Iterator<Item = Result<LockboxEntry>> + 'a>) -> Self {
        Self { inner }
    }
}

impl Iterator for ListIter<'_> {
    type Item = Result<LockboxEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}
