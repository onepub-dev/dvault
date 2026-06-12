/// Sensitivity marker for variables stored in a lockbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariableSensitivity {
    /// Plain variable value.
    Normal,
    /// Secret variable value stored in secure pages.
    Secret,
}
