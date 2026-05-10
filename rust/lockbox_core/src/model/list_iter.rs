use crate::{Entry, Result};

pub struct ListIter<'a> {
    inner: Box<dyn Iterator<Item = Result<Entry>> + 'a>,
}

impl<'a> ListIter<'a> {
    pub(crate) fn new(inner: Box<dyn Iterator<Item = Result<Entry>> + 'a>) -> Self {
        Self { inner }
    }
}

impl Iterator for ListIter<'_> {
    type Item = Result<Entry>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}
