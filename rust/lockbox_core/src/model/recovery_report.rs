use crate::{Entry, RecoveryReportOptions};

/// Summary produced by lockbox recovery and salvage scans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Intact file entries discovered by the scan.
    pub intact_files: Vec<Entry>,
    /// Total number of intact files, including entries omitted from
    /// `intact_files` by reporting limits.
    pub intact_file_count: usize,
    /// Number of file records that were only partially recoverable.
    pub partial_files: usize,
    /// Number of corrupt records encountered.
    pub corrupt_records: usize,
    /// Whether the latest manifest could be read.
    pub manifest_recovered: bool,
}

impl RecoveryReport {
    /// Render a human-readable report.
    pub fn render(&self, options: &RecoveryReportOptions) -> String {
        let mut out = String::new();
        out.push_str("Recovery report\n\n");
        out.push_str("Summary:\n");
        out.push_str(&format!("  Intact files: {}\n", self.intact_file_count));
        out.push_str(&format!("  Partial files: {}\n", self.partial_files));
        out.push_str(&format!("  Corrupt records: {}\n", self.corrupt_records));
        out.push_str(&format!(
            "  Latest manifest: {}\n",
            if self.manifest_recovered {
                "intact"
            } else {
                "not used or damaged"
            }
        ));

        if options.verbose {
            out.push_str("\nIntact:\n");
            let limit = options
                .max_intact_entries
                .unwrap_or(self.intact_files.len());
            for entry in self.intact_files.iter().take(limit) {
                out.push_str(&format!("  {}\n", entry.path));
            }
            if self.intact_files.len() > limit {
                out.push_str(&format!(
                    "  ... {} more intact files omitted\n",
                    self.intact_files.len() - limit
                ));
            }
        }

        if self.partial_files > 0 || self.corrupt_records > 0 {
            out.push_str("\nAttention required:\n");
            if self.partial_files > 0 {
                out.push_str(&format!(
                    "  Partial files detected: {}\n",
                    self.partial_files
                ));
            }
            if self.corrupt_records > 0 {
                out.push_str(&format!(
                    "  Corrupt records detected: {}\n",
                    self.corrupt_records
                ));
            }
        }

        out
    }
}
