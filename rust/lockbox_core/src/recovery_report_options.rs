#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReportOptions {
    pub verbose: bool,
    pub max_intact_entries: Option<usize>,
}
