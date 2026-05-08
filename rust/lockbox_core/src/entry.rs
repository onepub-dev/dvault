#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub kind: EntryKind,
    pub len: u64,
    pub permissions: u32,
    pub symlink_target: Option<String>,
    pub is_deleted: bool,
}
