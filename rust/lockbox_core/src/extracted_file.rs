#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedFile {
    pub path: String,
    pub bytes: Vec<u8>,
    pub permissions: u32,
}
