/// Public diagnostic view of one physical lockbox page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageInspection {
    /// Byte offset of the page in the lockbox file.
    pub offset: u64,
    /// Page id authenticated in the encrypted page metadata.
    pub page_id: u64,
    /// Monotonic sequence value used to order records.
    pub sequence: u64,
    /// Fixed physical page size in bytes.
    pub page_size: u32,
    /// Encrypted body length recorded in the page header.
    pub encrypted_body_len: u32,
    /// Physical page bytes not occupied by the fixed header or stored body.
    pub unused_bytes: u32,
    /// Number of decoded objects in the page.
    pub object_count: usize,
    /// Decoded object summaries.
    pub objects: Vec<PageObjectInspection>,
}

/// Public diagnostic view of one object inside a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageObjectInspection {
    /// Object id within the page.
    pub id: u64,
    /// Human-readable object kind.
    pub kind: &'static str,
    /// Payload length in bytes.
    pub payload_len: usize,
}
