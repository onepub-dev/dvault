#[derive(Debug, Clone)]
pub(crate) struct FreeSlot {
    pub(crate) offset: u64,
    pub(crate) len: u64,
}
