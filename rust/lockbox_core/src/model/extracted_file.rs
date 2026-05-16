/// File content returned by in-memory extraction APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedFile {
    /// Logical path inside the lockbox.
    pub path: String,
    /// Decrypted file bytes.
    pub bytes: Vec<u8>,
    /// Stored Unix-style permission bits.
    pub permissions: u32,
}
