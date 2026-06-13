use super::context::{cli_error, Access, CliResult};
use super::output::{output_format_from_args, print_records, OutputFormat};
use lockbox_core::vault_bridge::VaultUnlock;
use lockbox_core::{Error, RecoveryReport, RecoveryScanner, SecretVec};
use lockbox_vault::get as get_cached_content_key;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn run(args: &[String], access: &Access) -> CliResult<()> {
    let options = RecoverOptions::parse(args)?;
    if options.dry_run {
        let report = scan_report(&options.lockbox_path, access)?;
        print_report(&report, options.format)?;
        return Ok(());
    }

    let output = options
        .output
        .clone()
        .unwrap_or_else(|| default_recovered_path(&options.lockbox_path));
    let output_path = Path::new(&output);
    let input_path = Path::new(&options.lockbox_path);
    let in_place = same_existing_path(input_path, output_path);
    if output_path.exists() && !options.overwrite {
        return Err(Error::AlreadyExists(output).into());
    }
    let bytes = fs::read(&options.lockbox_path)
        .map_err(|err| Error::Io(format!("read lockbox {}: {err}", options.lockbox_path)))?;
    let recovered = salvage_bytes(&options.lockbox_path, bytes, access)?;
    let damaged_original = if in_place {
        let backup = next_damaged_backup_path(input_path);
        fs::rename(input_path, &backup).map_err(|err| {
            Error::Io(format!(
                "move damaged lockbox {} to {}: {err}",
                options.lockbox_path,
                backup.display()
            ))
        })?;
        Some(backup)
    } else {
        None
    };
    fs::write(&output, recovered.try_to_bytes()?)
        .map_err(|err| Error::Io(format!("write recovered lockbox {output}: {err}")))?;
    let report = scan_report(&output, access)?;
    let rows = report_rows(&report, Some(&output), damaged_original.as_deref());
    print_records(&["field", "value"], rows, options.format)?;
    Ok(())
}

struct RecoverOptions {
    lockbox_path: String,
    output: Option<String>,
    overwrite: bool,
    dry_run: bool,
    format: OutputFormat,
}

impl RecoverOptions {
    fn parse(args: &[String]) -> CliResult<Self> {
        let (args, format) = output_format_from_args(args)?;
        let mut positional = Vec::new();
        let mut output = None;
        let mut overwrite = false;
        let mut dry_run = false;
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
                "--dry-run" => dry_run = true,
                "--report" => {
                    return Err(Error::InvalidInput(
                        "--report has been removed; use --dry-run".to_string(),
                    )
                    .into());
                }
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
        if dry_run && output.is_some() {
            return Err(
                Error::InvalidInput("--dry-run cannot be used with --output".to_string()).into(),
            );
        }
        if dry_run && overwrite {
            return Err(Error::InvalidInput(
                "--dry-run cannot be used with --overwrite".to_string(),
            )
            .into());
        }
        Ok(Self {
            lockbox_path,
            output,
            overwrite,
            dry_run,
            format,
        })
    }
}

fn scan_report(lockbox_path: &str, access: &Access) -> CliResult<RecoveryReport> {
    match access {
        Access::ContentKey(key) => {
            let bytes = fs::read(lockbox_path)
                .map_err(|err| Error::Io(format!("read lockbox {lockbox_path}: {err}")))?;
            scan_bytes_with_secret_key(bytes, key)
        }
        Access::CacheOnly => {
            let key = cached_key(lockbox_path)?;
            let bytes = fs::read(lockbox_path)
                .map_err(|err| Error::Io(format!("read lockbox {lockbox_path}: {err}")))?;
            scan_bytes_with_secret_key(bytes, &key)
        }
        Access::PromptPassword => {
            Err(Error::InvalidInput("recover requires --key or an open lockbox".to_string()).into())
        }
    }
}

fn scan_bytes_with_secret_key(bytes: Vec<u8>, key: &SecretVec) -> CliResult<RecoveryReport> {
    let mut key_bytes = key.with_bytes(|key| key.to_vec())?;
    let report = RecoveryScanner::scan_bytes(bytes, &key_bytes);
    key_bytes.fill(0);
    Ok(report)
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
        Access::PromptPassword => {
            Err(Error::InvalidInput("recover requires --key or an open lockbox".to_string()).into())
        }
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
            "lockbox is closed: {lockbox_path}. Run `lockbox open {lockbox_path}` first or pass --key."
        ))
    })
}

fn print_report(report: &RecoveryReport, format: OutputFormat) -> CliResult<()> {
    print_records(&["field", "value"], report_rows(report, None, None), format)
}

fn report_rows(
    report: &RecoveryReport,
    output: Option<&str>,
    damaged_original: Option<&Path>,
) -> Vec<Vec<String>> {
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
            "variables_recovered".to_string(),
            report.variables_recovered.to_string(),
        ],
        vec![
            "variable_count".to_string(),
            report.variable_count.to_string(),
        ],
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
    if let Some(damaged_original) = damaged_original {
        rows.push(vec![
            "damaged_original".to_string(),
            damaged_original.display().to_string(),
        ]);
    }
    rows
}

fn default_recovered_path(lockbox_path: &str) -> String {
    let path = Path::new(lockbox_path);
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or("lockbox");
    parent
        .join(format!("{stem}.recovered.lbox"))
        .display()
        .to_string()
}

fn same_existing_path(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

fn next_damaged_backup_path(input_path: &Path) -> PathBuf {
    let parent = input_path.parent().unwrap_or_else(|| Path::new(""));
    let file_name = input_path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("lockbox.lbox");
    let mut candidate = parent.join(format!("{file_name}.damaged"));
    let mut index = 1usize;
    while candidate.exists() {
        candidate = parent.join(format!("{file_name}.damaged.{index}"));
        index += 1;
    }
    candidate
}
