use super::context::{open_existing, require_arg, Access, CliResult};
use lockbox_core::{Error, RecoveryReportOptions, RecoveryScanner};
use std::path::Path;

pub(crate) fn run(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let report = match access {
        Access::ContentKey(key) => {
            key.with_bytes(|key| RecoveryScanner::scan_path(Path::new(lockbox_path), key))?
        }
        Access::CacheOnly => open_existing(lockbox_path, access)?
            .inspector()
            .recovery_report(),
        Access::PromptPassword => {
            return Err(
                Error::InvalidInput("recover requires an unlocked lockbox".to_string()).into(),
            );
        }
    };
    print!("{}", report.render(&RecoveryReportOptions::default()));
    Ok(())
}
