#[path = "common/probe_ruzstd.rs"]
mod probe_ruzstd;

use probe_ruzstd::ruzstd_level;
use ruzstd::encoding::compress_to_vec;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

const FRAME_TARGET_BYTES: usize = 2 * 1024 * 1024;
const LEVELS: &[i32] = &[1, 2, 3, 4, 5, 6, 9, 19];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(root) = env::args_os().nth(1) else {
        eprintln!("usage: zstd_gap_probe <fixture-root>");
        std::process::exit(2);
    };
    let root = PathBuf::from(root);
    let files = collect_files(&root)?;
    if files.is_empty() {
        return Err("no files found".into());
    }

    let mut payloads = Vec::with_capacity(files.len());
    for path in &files {
        payloads.push(fs::read(path)?);
    }
    let logical_bytes = payloads.iter().map(Vec::len).sum::<usize>();
    println!(
        "fixture\tfiles\tlogical_bytes\tbackend\tshape\tlevel\tgroups\tcompressed_bytes\tcompress_ms"
    );
    for (shape, group_target) in [
        ("2m-file-boundary", FRAME_TARGET_BYTES),
        ("solid", logical_bytes.max(1)),
    ] {
        let groups = build_groups(&payloads, group_target);
        for level in LEVELS {
            print_result(
                &root,
                files.len(),
                logical_bytes,
                "ruzstd-local",
                shape,
                *level,
                &groups,
                compress_ruzstd_group,
            )?;
            print_result(
                &root,
                files.len(),
                logical_bytes,
                "zstd-cli",
                shape,
                *level,
                &groups,
                compress_zstd_cli_group,
            )?;
        }
    }
    Ok(())
}

fn print_result(
    root: &Path,
    files: usize,
    logical_bytes: usize,
    backend: &str,
    shape: &str,
    level: i32,
    groups: &[Group],
    compress: fn(&[u8], i32) -> Result<usize, Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    let mut compressed_bytes = 0usize;
    for group in groups {
        compressed_bytes += compress(&group.bytes, level)?;
    }
    let compress_ms = started.elapsed().as_secs_f64() * 1000.0;
    println!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.3}",
        root.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("fixture"),
        files,
        logical_bytes,
        backend,
        shape,
        level,
        groups.len(),
        compressed_bytes,
        compress_ms
    );
    Ok(())
}

struct Group {
    bytes: Vec<u8>,
}

fn build_groups(payloads: &[Vec<u8>], group_target: usize) -> Vec<Group> {
    let mut groups = Vec::new();
    let mut current_len = 0usize;
    let mut group_start = 0usize;

    for (index, payload) in payloads.iter().enumerate() {
        if index > group_start && current_len.saturating_add(payload.len()) > group_target {
            groups.push(Group {
                bytes: concat_payloads(&payloads[group_start..index]),
            });
            group_start = index;
            current_len = 0;
        }
        current_len += payload.len();
    }

    if group_start < payloads.len() {
        groups.push(Group {
            bytes: concat_payloads(&payloads[group_start..]),
        });
    }
    groups
}

fn concat_payloads(payloads: &[Vec<u8>]) -> Vec<u8> {
    let total = payloads.iter().map(Vec::len).sum();
    let mut bytes = Vec::with_capacity(total);
    for payload in payloads {
        bytes.extend_from_slice(payload);
    }
    bytes
}

fn collect_files(root: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    collect_files_recursive(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_files_recursive(
    current: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_files_recursive(&path, files)?;
        } else if file_type.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn compress_ruzstd_group(payload: &[u8], level: i32) -> Result<usize, Box<dyn std::error::Error>> {
    let compressed = compress_to_vec(payload, ruzstd_level(level));
    Ok(compressed.len().min(payload.len()))
}

fn compress_zstd_cli_group(
    payload: &[u8],
    level: i32,
) -> Result<usize, Box<dyn std::error::Error>> {
    let path = env::temp_dir().join(format!(
        "revault-zstd-gap-{}-{}-{}.bin",
        std::process::id(),
        level,
        payload.len()
    ));
    fs::write(&path, payload)?;
    let output = Command::new("zstd")
        .arg("-q")
        .arg(format!("-{level}"))
        .arg("-c")
        .arg(&path)
        .output();
    let _ = fs::remove_file(&path);
    let output = output?;
    if !output.status.success() {
        return Err(format!("zstd failed with status {}", output.status).into());
    }
    Ok(output.stdout.len().min(payload.len()))
}
