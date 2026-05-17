use super::context::{open_existing, open_or_create, require_arg, Access, CliResult};
use lockbox_core::{Error, ExtractPolicy, ListOptions, Lockbox, LockboxPath, WorkloadProfile};
use std::fs;
use std::io;
use std::path::Path;

pub(crate) fn add(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let source = require_arg(args, 1, "source")?;
    let path = require_arg(args, 2, "lockbox path")?;
    let creates_lockbox = !Path::new(lockbox_path).exists();
    let mut lb = open_or_create(lockbox_path, access)?;
    if creates_lockbox {
        lb.set_workload_profile(WorkloadProfile::BulkImport);
    }
    add_source_path(&mut lb, Path::new(source), path)?;
    lb.commit()?;
    Ok(())
}

pub(crate) fn extract(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let lb = open_existing(lockbox_path, access)?;
    if args.get(1).map(String::as_str) == Some("--to") {
        let dest = require_arg(args, 2, "destination")?;
        let policy = extract_policy_from_args(&args[3..]);
        lb.extract_to_directory(Path::new(dest), &policy)?;
    } else {
        let path = LockboxPath::new(require_arg(args, 1, "lockbox path")?)?;
        let dest = require_arg(args, 2, "destination")?;
        let replace = args.iter().skip(3).any(|arg| arg == "--overwrite");
        lb.extract_file_to(&path, Path::new(dest), replace)?;
    }
    Ok(())
}

pub(crate) fn cat(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let path = LockboxPath::new(require_arg(args, 1, "lockbox path")?)?;
    let lb = open_existing(lockbox_path, access)?;
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    lb.extract_file_to_writer(&path, &mut lock)?;
    Ok(())
}

pub(crate) fn list(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let path = LockboxPath::new(args.get(1).map(String::as_str).unwrap_or("/"))?;
    let lb = open_existing(lockbox_path, access)?;
    for entry in lb.list(ListOptions::new(&path))? {
        let entry = entry?;
        println!("{}\t{}\t{}", kind_name(&entry.kind), entry.len, entry.path);
    }
    Ok(())
}

pub(crate) fn remove(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let path = LockboxPath::new(require_arg(args, 1, "lockbox path")?)?;
    let mut lb = open_existing(lockbox_path, access)?;
    lb.delete(&path)?;
    lb.commit()?;
    Ok(())
}

pub(crate) fn rename(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let from = LockboxPath::new(require_arg(args, 1, "from")?)?;
    let to = LockboxPath::new(require_arg(args, 2, "to")?)?;
    let mut lb = open_existing(lockbox_path, access)?;
    lb.rename(&from, &to)?;
    lb.commit()?;
    Ok(())
}

fn kind_name(kind: &lockbox_core::LockboxEntryKind) -> &'static str {
    match kind {
        lockbox_core::LockboxEntryKind::File => "file",
        lockbox_core::LockboxEntryKind::Symlink => "symlink",
    }
}

fn extract_policy_from_args(args: &[String]) -> ExtractPolicy {
    let mut policy = ExtractPolicy::default();
    for arg in args {
        match arg.as_str() {
            "--overwrite" => policy.overwrite = true,
            "--restore-symlinks" => policy.restore_symlinks = true,
            "--restore-permissions" => policy.restore_permissions = true,
            _ => {}
        }
    }
    policy
}

fn add_source_path(lockbox: &mut Lockbox, source: &Path, lockbox_root: &str) -> CliResult<()> {
    let lockbox_root = LockboxPath::new(lockbox_root)?;
    if source.is_file() {
        lockbox.add_file_from_path(source, &lockbox_root, false)?;
        return Ok(());
    }
    if source.is_dir() {
        add_directory(lockbox, source, source, &lockbox_root)?;
        return Ok(());
    }
    Err(format!("unsupported source path: {}", source.display()).into())
}

fn add_directory(
    lockbox: &mut Lockbox,
    root: &Path,
    current: &Path,
    lockbox_root: &LockboxPath,
) -> CliResult<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            add_directory(lockbox, root, &path, lockbox_root)?;
        } else if file_type.is_file() {
            let relative = path.strip_prefix(root)?;
            let lockbox_path = join_lockbox_path(lockbox_root, relative)?;
            lockbox.add_file_from_path(&path, &lockbox_path, false)?;
        }
    }
    Ok(())
}

fn join_lockbox_path(lockbox_root: &LockboxPath, relative: &Path) -> CliResult<LockboxPath> {
    let mut out = lockbox_root.as_str().trim_end_matches('/').to_string();
    if out.is_empty() {
        out.push('/');
    }
    for component in relative.components() {
        let std::path::Component::Normal(part) = component else {
            return Err(Error::InvalidPath("unsupported source path component".to_string()).into());
        };
        let Some(part) = part.to_str() else {
            return Err(Error::InvalidPath("source path is not valid UTF-8".to_string()).into());
        };
        if !out.ends_with('/') {
            out.push('/');
        }
        out.push_str(part);
    }
    Ok(LockboxPath::new(out)?)
}
