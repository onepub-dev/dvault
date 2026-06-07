use super::context::{open_existing, open_or_create, require_arg, Access, CliResult};
use super::output::{output_format_from_args, print_records};
use lockbox_core::{
    Error, ExtractPolicy, ListOptions, Lockbox, LockboxPath, WorkerPolicy, WorkloadProfile,
};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
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
    let (args, format) = output_format_from_args(args)?;
    let recursive = args.iter().any(|arg| arg == "--recursive" || arg == "-R");
    let args = args
        .iter()
        .filter(|arg| !matches!(arg.as_str(), "--recursive" | "-R"))
        .cloned()
        .collect::<Vec<_>>();
    let lockbox_path = require_arg(&args, 0, "lockbox")?;
    let target = args.get(1).map(String::as_str).unwrap_or("/");
    let glob = contains_glob(target);
    let path = if glob {
        LockboxPath::new("/")?
    } else {
        LockboxPath::new(target)?
    };
    let lb = open_existing(lockbox_path, access)?;
    if recursive || glob {
        let mut options = ListOptions::new(&path);
        options.recursive = true;
        if glob {
            options.set_glob(target.trim_start_matches('/'));
        }
        let mut rows = Vec::new();
        for entry in lb.list(options)? {
            let entry = entry?;
            rows.push(vec![
                kind_name(&entry.kind).to_string(),
                entry.len.to_string(),
                entry.path.to_string(),
            ]);
        }
        print_records(&["kind", "len", "path"], rows, format)?;
    } else {
        let rows = direct_listing_rows(&lb, &path)?;
        print_records(&["kind", "len", "name"], rows, format)?;
    }
    Ok(())
}

fn contains_glob(value: &str) -> bool {
    value.contains('*') || value.contains('?')
}

fn direct_listing_rows(lb: &Lockbox, path: &LockboxPath) -> CliResult<Vec<Vec<String>>> {
    if let Some(entry) = lb.stat(path) {
        return Ok(vec![vec![
            kind_name(&entry.kind).to_string(),
            entry.len.to_string(),
            leaf_name(entry.path.as_str()).to_string(),
        ]]);
    }

    let mut options = ListOptions::new(path);
    options.recursive = true;
    let mut rows = BTreeMap::new();
    let prefix = listing_prefix(path.as_str());
    for entry in lb.list(options)? {
        let entry = entry?;
        let rest = entry
            .path
            .as_str()
            .strip_prefix(&prefix)
            .unwrap_or(entry.path.as_str());
        let Some((name, is_directory)) = direct_child(rest) else {
            continue;
        };
        let row = if is_directory {
            vec!["directory".to_string(), "-".to_string(), format!("{name}/")]
        } else {
            vec![
                kind_name(&entry.kind).to_string(),
                entry.len.to_string(),
                name.to_string(),
            ]
        };
        rows.entry(name.to_string()).or_insert(row);
    }
    Ok(rows.into_values().collect())
}

fn listing_prefix(path: &str) -> String {
    if path == "/" {
        "/".to_string()
    } else {
        format!("{}/", path.trim_end_matches('/'))
    }
}

fn direct_child(rest: &str) -> Option<(&str, bool)> {
    let rest = rest.trim_start_matches('/');
    if rest.is_empty() {
        return None;
    }
    match rest.split_once('/') {
        Some((name, _)) if !name.is_empty() => Some((name, true)),
        None => Some((rest, false)),
        _ => None,
    }
}

fn leaf_name(path: &str) -> &str {
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or(path)
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
    let force = args.iter().any(|arg| arg == "--force" || arg == "--noask");
    let args = args
        .iter()
        .filter(|arg| !matches!(arg.as_str(), "--force" | "--noask"))
        .cloned()
        .collect::<Vec<_>>();
    let lockbox_path = require_arg(&args, 0, "lockbox")?;
    let path = LockboxPath::new(require_arg(&args, 1, "lockbox path")?)?;
    let mut lb = open_existing(lockbox_path, access)?;
    let Some(entry) = lb.stat(&path) else {
        return Err(Error::NotFound(path.to_string()).into());
    };
    if !force && !confirm_remove(path.as_str())? {
        println!("No entries removed.");
        return Ok(());
    }
    lb.delete(&path)?;
    lb.commit()?;
    println!("Removed 1 {}: {}", kind_name(&entry.kind), entry.path);
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

fn confirm_remove(path: &str) -> CliResult<bool> {
    eprint!("Remove lockbox entry '{path}'? Type yes to confirm: ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(answer.trim() == "yes")
}
