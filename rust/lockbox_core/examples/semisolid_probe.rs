#[path = "common/probe_ruzstd.rs"]
mod probe_ruzstd;

use probe_ruzstd::ruzstd_level;
use ruzstd::encoding::compress_to_vec;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

const BASELINE_GROUP_BYTES: usize = 2 * 1024 * 1024;
const LEVEL: i32 = 3;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(root) = env::args_os().nth(1) else {
        eprintln!("usage: semisolid_probe <fixture-root>");
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
    let baseline = analyze_groups(&payloads, BASELINE_GROUP_BYTES)?;
    println!(
        "fixture\tfiles\tlogical_bytes\tgroup_target_bytes\tgroups\tmax_group_bytes\tcompressed_bytes\tdelta_vs_2m_bytes\tcompress_ms\tmean_file_read_amplification\tall_files_once_amplification"
    );

    let solid_target = logical_bytes.max(1);
    for group_target in [
        BASELINE_GROUP_BYTES,
        4 * 1024 * 1024,
        8 * 1024 * 1024,
        16 * 1024 * 1024,
        32 * 1024 * 1024,
        solid_target,
    ] {
        let stats = analyze_groups(&payloads, group_target)?;
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.3}\t{:.3}\t{:.3}",
            root.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("fixture"),
            files.len(),
            logical_bytes,
            group_target,
            stats.groups,
            stats.max_group_bytes,
            stats.compressed_bytes,
            baseline.compressed_bytes as i128 - stats.compressed_bytes as i128,
            stats.compress_ms,
            stats.mean_file_read_amplification,
            stats.all_files_once_amplification
        );
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct GroupStats {
    groups: usize,
    max_group_bytes: usize,
    compressed_bytes: usize,
    compress_ms: f64,
    mean_file_read_amplification: f64,
    all_files_once_amplification: f64,
}

fn analyze_groups(
    payloads: &[Vec<u8>],
    group_target: usize,
) -> Result<GroupStats, Box<dyn std::error::Error>> {
    let groups = build_groups(payloads, group_target);
    let compress_start = Instant::now();
    let mut compressed_bytes = 0usize;
    for group in &groups {
        compressed_bytes += compress_group(&group.bytes)?;
    }
    let compress_ms = compress_start.elapsed().as_secs_f64() * 1000.0;

    let max_group_bytes = groups
        .iter()
        .map(|group| group.bytes.len())
        .max()
        .unwrap_or(0);
    let mean_file_read_amplification = mean_file_read_amplification(&groups);
    let all_files_once_amplification = all_files_once_amplification(&groups);
    Ok(GroupStats {
        groups: groups.len(),
        max_group_bytes,
        compressed_bytes,
        compress_ms,
        mean_file_read_amplification,
        all_files_once_amplification,
    })
}

struct Group {
    bytes: Vec<u8>,
    file_lengths: Vec<usize>,
}

fn build_groups(payloads: &[Vec<u8>], group_target: usize) -> Vec<Group> {
    let mut groups = Vec::new();
    let mut current = Vec::new();
    let mut current_len = 0usize;
    let mut group_start = 0usize;

    for (index, payload) in payloads.iter().enumerate() {
        if !current.is_empty() && current_len.saturating_add(payload.len()) > group_target {
            let group_bytes = concat_payloads(&payloads[group_start..index]);
            groups.push(Group {
                bytes: group_bytes,
                file_lengths: std::mem::take(&mut current),
            });
            group_start = index;
            current_len = 0;
        }
        current.push(payload.len());
        current_len += payload.len();
    }

    if !current.is_empty() {
        let group_bytes = concat_payloads(&payloads[group_start..]);
        groups.push(Group {
            bytes: group_bytes,
            file_lengths: current,
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

fn mean_file_read_amplification(groups: &[Group]) -> f64 {
    let mut files = 0usize;
    let mut amplification = 0.0f64;
    for group in groups {
        let group_len = group.bytes.len() as f64;
        for file_len in &group.file_lengths {
            files += 1;
            if *file_len == 0 {
                continue;
            }
            amplification += group_len / *file_len as f64;
        }
    }
    if files == 0 {
        0.0
    } else {
        amplification / files as f64
    }
}

fn all_files_once_amplification(groups: &[Group]) -> f64 {
    let mut logical_bytes = 0usize;
    let mut decompressed_bytes = 0usize;
    for group in groups {
        let file_count = group.file_lengths.len();
        decompressed_bytes += group.bytes.len() * file_count;
        logical_bytes += group.file_lengths.iter().sum::<usize>();
    }
    if logical_bytes == 0 {
        0.0
    } else {
        decompressed_bytes as f64 / logical_bytes as f64
    }
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

fn compress_group(payload: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
    let compressed = compress_to_vec(payload, ruzstd_level(LEVEL));
    Ok(compressed.len().min(payload.len()))
}
