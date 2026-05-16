#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageInspection {
    pub offset: u64,
    pub page_id: u64,
    pub sequence: u64,
    pub encrypted_body_len: u32,
    pub object_count: usize,
    pub objects: Vec<PageObjectInspection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageObjectInspection {
    pub id: u64,
    pub kind: &'static str,
    pub payload_len: usize,
}
