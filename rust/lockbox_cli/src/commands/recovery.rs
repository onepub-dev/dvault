use super::context::{open_existing, require_arg, Access, CliResult};
use lockbox_core::{Lockbox, RecoveryReportOptions};
use std::fs;

pub(crate) fn run(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let bytes = fs::read(lockbox_path)?;
    let report = match access {
        Access::RawKey(key) => Lockbox::recover(bytes, key),
        Access::CacheOnly => open_existing(lockbox_path, access)?.recover_current(),
        Access::PromptPassword => return Err("recover requires an unlocked lockbox".into()),
    };
    print!("{}", report.render(&RecoveryReportOptions::default()));
    Ok(())
}
