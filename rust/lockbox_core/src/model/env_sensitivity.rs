/// Sensitivity marker for environment variables stored in a lockbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvSensitivity {
    /// Plain environment variable value.
    Normal,
    /// Secret environment variable value stored in secure pages.
    Secret,
}
