#[derive(Clone, Copy, Debug)]
pub(crate) struct Allocation {
    pub(crate) arena: usize,
    pub(crate) slot: usize,
    pub(crate) generation: u64,
    pub(crate) offset: usize,
    pub(crate) capacity: usize,
}
