use super::context::{cli_error, Access, CliResult};
use super::output::{output_format_from_args, print_records, OutputFormat};
use lockbox_core::vault_bridge::VaultUnlock;
use lockbox_core::{Error, RecoveryReport, RecoveryScanner, SecretVec};
use lockbox_vault::get as get_cached_content_key;
use std::fs;
use std::path::Path;

pub(crate) fn run(args: &[String], access: &Access) -> CliResult<()> {
    let options = RecoverOptions::parse(args)?;
    if options.report_only {
        let report = scan_report(&options.lockbox_path, access)?;
        print_report(&report, options.format)?;
        return Ok(());
    }

    let output = options
        .output
        .as_deref()
        .ok_or_else(|| Error::InvalidInput("recover requires --output or --report".to_string()))?;
    if Path::new(output).exists() && !options.overwrite {
        return Err(Error::AlreadyExists(output.to_string()).into());
    }
    let bytes = fs::read(&options.lockbox_path)
        .map_err(|err| Error::Io(format!("read lockbox {}: {err}", options.lockbox_path)))?;
    let recovered = salvage_bytes(&options.lockbox_path, bytes, access)?;
    fs::write(output, recovered.try_to_bytes()?)
        .map_err(|err| Error::Io(format!("write recovered lockbox {output}: {err}")))?;
    let report = scan_report(output, access)?;
    let rows = report_rows(&report, Some(output));
    print_records(&["field", "value"], rows, options.format)?;
    Ok(())
}

struct RecoverOptions {
    lockbox_path: String,
    output: Option<String>,
    overwrite: bool,
    report_only: bool,
    format: OutputFormat,
}

impl RecoverOptions {
    fn parse(args: &[String]) -> CliResult<Self> {
        let (args, format) = output_format_from_args(args)?;
        let mut positional = Vec::new();
        let mut output = None;
        let mut overwrite = false;
        let mut report_only = false;
        let mut index = 0usize;
        while index < args.len() {
            match args[index].as_str() {
                "--output" => {
                    index += 1;
                    output = Some(args.get(index).cloned().ok_or_else(|| {
                        Error::InvalidInput("missing --output value".to_string())
                    })?);
                }
                "--overwrite" => overwrite = true,
                "--report" => report_only = true,
                value => positional.push(value.to_string()),
            }
            index += 1;
        }
        let lockbox_path = positional
            .first()
            .cloned()
            .ok_or_else(|| Error::InvalidInput("missing lockbox".to_string()))?;
        if positional.len() > 1 {
            return Err(Error::InvalidInput(format!(
                "unexpected recover argument: {}",
                positional[1]
            ))
            .into());
        }
        if report_only && output.is_some() {
            return Err(
                Error::InvalidInput("--report cannot be used with --output".to_string()).into(),
            );
        }
        Ok(Self {
            lockbox_path,
            output,
            overwrite,
            report_only,
            format,
        })
    }
}

fn scan_report(lockbox_path: &str, access: &Access) -> CliResult<RecoveryReport> {
    match access {
        Access::ContentKey(key) => {
            Ok(key.with_bytes(|key| RecoveryScanner::scan_path(Path::new(lockbox_path), key))?)
        }
        Access::CacheOnly => {
            let key = cached_key(lockbox_path)?;
            let bytes = fs::read(lockbox_path)
                .map_err(|err| Error::Io(format!("read lockbox {lockbox_path}: {err}")))?;
            Ok(key.with_bytes(|key| RecoveryScanner::scan_bytes(bytes, key))?)
        }
        Access::PromptPassword => Err(Error::InvalidInput(
            "recover requires --key or an unlocked lockbox".to_string(),
        )
        .into()),
    }
}

fn salvage_bytes(
    lockbox_path: &str,
    bytes: Vec<u8>,
    access: &Access,
) -> CliResult<lockbox_core::Lockbox> {
    match access {
        Access::ContentKey(key) => Ok(RecoveryScanner::salvage_bytes_with_secret_key(bytes, key)?),
        Access::CacheOnly => {
            let key = cached_key(lockbox_path)?;
            Ok(RecoveryScanner::salvage_bytes_with_secret_key(bytes, &key)?)
        }
        Access::PromptPassword => Err(Error::InvalidInput(
            "recover requires --key or an unlocked lockbox".to_string(),
        )
        .into()),
    }
}

fn cached_key(lockbox_path: &str) -> CliResult<SecretVec> {
    let lockbox_id = VaultUnlock::read_lockbox_id(Path::new(lockbox_path)).map_err(|_| {
        cli_error(format!(
            "cannot read lockbox id from {lockbox_path}; run recover with --key for badly damaged headers"
        ))
    })?;
    get_cached_content_key(lockbox_id)?.ok_or_else(|| {
        cli_error(format!(
            "lockbox is locked: {lockbox_path}. Run `lockbox unlock {lockbox_path}` first or pass --key."
        ))
    })
}

fn print_report(report: &RecoveryReport, format: OutputFormat) -> CliResult<()> {
    print_records(&["field", "value"], report_rows(report, None), format)
}

fn report_rows(report: &RecoveryReport, output: Option<&str>) -> Vec<Vec<String>> {
    let mut rows = vec![
        vec![
            "intact_file_count".to_string(),
            report.intact_file_count.to_string(),
        ],
        vec![
            "partial_files".to_string(),
            report.partial_files.to_string(),
        ],
        vec![
            "corrupt_records".to_string(),
            report.corrupt_records.to_string(),
        ],
        vec![
            "toc_recovered".to_string(),
            report.toc_recovered.to_string(),
        ],
        vec![
            "env_recovered".to_string(),
            report.env_recovered.to_string(),
        ],
        vec!["env_count".to_string(), report.env_count.to_string()],
        vec![
            "forms_recovered".to_string(),
            report.forms_recovered.to_string(),
        ],
        vec![
            "form_definition_count".to_string(),
            report.form_definition_count.to_string(),
        ],
        vec![
            "form_record_count".to_string(),
            report.form_record_count.to_string(),
        ],
    ];
    if let Some(output) = output {
        rows.push(vec!["output".to_string(), output.to_string()]);
    }
    rows
}
