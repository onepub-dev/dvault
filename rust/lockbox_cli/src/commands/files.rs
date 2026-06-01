use super::context::{open_existing, open_or_create, require_arg, Access, CliResult};
use lockbox_core::{
    Error, ExtractPolicy, ListOptions, Lockbox, LockboxPath, WorkerPolicy, WorkloadProfile,
};
use std::fs;
use std::io;
use std::path::Path;
use std::time::Instant;

pub(crate) fn add(args: &[String], access: &Access, worker_policy: WorkerPolicy) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let source = require_arg(args, 1, "source")?;
    let source_path = Path::new(source);
    let path = match args.get(2) {
        Some(path) => path.clone(),
        None => default_lockbox_path_for_source(source_path)?,
    };
    let creates_lockbox = !Path::new(lockbox_path).exists();
    let mut lb = open_or_create(lockbox_path, access)?;
    lb.set_worker_policy(worker_policy);
    if creates_lockbox || source_path.is_dir() {
        lb.set_workload_profile(WorkloadProfile::BulkImport);
    }
    lb.reset_import_stats();
    let add_start = Instant::now();
    add_source_path(&mut lb, source_path, &path)?;
    let add_wall = add_start.elapsed();
    let commit_start = Instant::now();
    lb.commit()?;
    let commit_wall = commit_start.elapsed();
    if std::env::var_os("LOCKBOX_IMPORT_TIMINGS").is_some() {
        let stats = lb.import_stats();
        eprintln!(
            "lockbox_import_timings\tadd_wall_s={:.6}\tcommit_wall_s={:.6}\thost_stat_s={:.6}\thost_read_s={:.6}\tframe_prepare_s={:.6}\tpage_write_s={:.6}",
            add_wall.as_secs_f64(),
            commit_wall.as_secs_f64(),
            nanos_to_secs(stats.host_stat_nanos),
            nanos_to_secs(stats.host_read_nanos),
            nanos_to_secs(stats.frame_prepare_nanos),
            nanos_to_secs(stats.page_write_nanos),
        );
    }
    Ok(())
}

pub(crate) fn extract(args: &[String], access: &Access) -> CliResult<()> {
    let lockbox_path = require_arg(args, 0, "lockbox")?;
    let mut lb = open_existing(lockbox_path, access)?;
    if args.get(1).map(String::as_str) == Some("--to") {
        let dest = require_arg(args, 2, "destination")?;
        let policy = extract_policy_from_args(&args[3..]);
        lb.set_workload_profile(WorkloadProfile::ExtractMany);
        lb.extract_to_directory(Path::new(dest), &policy)?;
    } else {
        let path = LockboxPath::new(require_arg(args, 1, "lockbox path")?)?;
        let dest = require_arg(args, 2, "destination")?;
        let replace = args.iter().skip(3).any(|arg| arg == "--overwrite");
        lb.set_workload_profile(WorkloadProfile::ReadMostly);
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
    let mut options = ListOptions::new(&path);
    options.recursive = true;
    let mut printed = false;
    for entry in lb.list(options)? {
        let entry = entry?;
        println!("{}\t{}\t{}", kind_name(&entry.kind), entry.len, entry.path);
        printed = true;
    }
    if !printed {
        println!("empty");
    }
    Ok(())
}

fn default_lockbox_path_for_source(source: &Path) -> CliResult<String> {
    if source.is_dir() {
        return Ok("/".to_string());
    }
    let Some(name) = source.file_name().and_then(|name| name.to_str()) else {
        return Err(Error::UnsupportedHostPath(format!(
            "source path is not valid UTF-8: {}",
            source.display()
        ))
        .into());
    };
    Ok(format!("/{name}"))
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

fn nanos_to_secs(nanos: u128) -> f64 {
    nanos as f64 / 1_000_000_000.0
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
    Err(Error::UnsupportedHostPath(source.display().to_string()).into())
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
            return Err(Error::UnsupportedHostPath(format!(
                "unsupported source path component in {}",
                relative.display()
            ))
            .into());
        };
        let Some(part) = part.to_str() else {
            return Err(Error::UnsupportedHostPath(format!(
                "source path is not valid UTF-8: {}",
                relative.display()
            ))
            .into());
        };
        if !out.ends_with('/') {
            out.push('/');
        }
        out.push_str(part);
    }
    Ok(LockboxPath::new(out)?)
}
