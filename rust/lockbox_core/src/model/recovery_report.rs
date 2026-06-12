use crate::{LockboxEntry, RecoveryReportOptions};

/// Summary produced by lockbox recovery and salvage scans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Intact file entries discovered by the scan.
    pub intact_files: Vec<LockboxEntry>,
    /// Total number of intact files, including entries omitted from
    /// `intact_files` by reporting limits.
    pub intact_file_count: usize,
    /// Number of file records that were only partially recoverable.
    pub partial_files: usize,
    /// Number of corrupt records encountered.
    pub corrupt_records: usize,
    /// Whether the latest TOC could be read.
    pub toc_recovered: bool,
    /// Whether variable metadata was recovered from the latest commit root.
    pub variables_recovered: bool,
    /// Number of variable values recovered.
    pub variable_count: usize,
    /// Whether form metadata was recovered from the latest commit root.
    pub forms_recovered: bool,
    /// Number of latest form definitions recovered.
    pub form_definition_count: usize,
    /// Number of form records recovered.
    pub form_record_count: usize,
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
            "  Latest TOC: {}\n",
            if self.toc_recovered {
                "intact"
            } else {
                "not used or damaged"
            }
        ));
        out.push_str(&format!(
            "  Variables: {} ({})\n",
            self.variable_count,
            if self.variables_recovered {
                "recovered"
            } else {
                "not recovered"
            }
        ));
        out.push_str(&format!(
            "  Forms: {} definitions, {} items ({})\n",
            self.form_definition_count,
            self.form_record_count,
            if self.forms_recovered {
                "recovered"
            } else {
                "not recovered"
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
