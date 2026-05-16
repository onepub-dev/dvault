/// Rendering options for `RecoveryReport`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReportOptions {
    /// Include individual intact file paths in rendered output.
    pub verbose: bool,
    /// Maximum intact file paths to include when verbose output is enabled.
    pub max_intact_entries: Option<usize>,
}
