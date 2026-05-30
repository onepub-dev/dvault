#[path = "common/probe_ruzstd.rs"]
mod probe_ruzstd;

use probe_ruzstd::ruzstd_level;
use ruzstd::encoding::compress_to_vec;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

const FRAME_TARGET_BYTES: usize = 2 * 1024 * 1024;
const LEVEL: i32 = 3;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(root) = env::args_os().nth(1) else {
        eprintln!("usage: dedupe_probe <fixture-root>");
        std::process::exit(2);
    };
    let root = PathBuf::from(root);
    let files = collect_files(&root)?;
    if files.is_empty() {
        return Err("no files found".into());
    }

    let read_start = Instant::now();
    let mut payloads = Vec::with_capacity(files.len());
    for path in &files {
        payloads.push(fs::read(path)?);
    }
    let read_ms = read_start.elapsed().as_secs_f64() * 1000.0;

    let hash_start = Instant::now();
    let dedupe = analyze_dedupe(&payloads);
    let hash_ms = hash_start.elapsed().as_secs_f64() * 1000.0;

    let baseline = compress_frames(&payloads)?;
    let deduped = compress_deduped_frames(&payloads)?;
    let logical_bytes = payloads.iter().map(Vec::len).sum::<usize>();

    println!(
        "fixture\tfiles\tlogical_bytes\tunique_files\tunique_bytes\tduplicate_files\tduplicate_bytes\tread_ms\thash_ms\tbaseline_frame_bytes\tdeduped_frame_bytes\tframe_delta_bytes"
    );
    println!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.3}\t{:.3}\t{}\t{}\t{}",
        root.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("fixture"),
        files.len(),
        logical_bytes,
        dedupe.unique_files,
        dedupe.unique_bytes,
        files.len() - dedupe.unique_files,
        logical_bytes - dedupe.unique_bytes,
        read_ms,
        hash_ms,
        baseline,
        deduped,
        baseline as i128 - deduped as i128
    );
    Ok(())
}

#[derive(Default)]
struct DedupeStats {
    unique_files: usize,
    unique_bytes: usize,
}

fn analyze_dedupe(payloads: &[Vec<u8>]) -> DedupeStats {
    let mut seen = HashMap::<[u8; 32], usize>::new();
    let mut stats = DedupeStats::default();
    for payload in payloads {
        let digest = digest(payload);
        if seen.insert(digest, payload.len()).is_none() {
            stats.unique_files += 1;
            stats.unique_bytes += payload.len();
        }
    }
    stats
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

fn compress_frames(payloads: &[Vec<u8>]) -> Result<usize, Box<dyn std::error::Error>> {
    let mut total = 0usize;
    let mut frame = Vec::new();
    for payload in payloads {
        if !frame.is_empty() && frame.len().saturating_add(payload.len()) > FRAME_TARGET_BYTES {
            total += compress_frame(&frame)?;
            frame.clear();
        }
        frame.extend_from_slice(payload);
    }
    if !frame.is_empty() {
        total += compress_frame(&frame)?;
    }
    Ok(total)
}

fn compress_deduped_frames(payloads: &[Vec<u8>]) -> Result<usize, Box<dyn std::error::Error>> {
    let mut total = 0usize;
    let mut frame = Vec::new();
    let mut seen = HashMap::<[u8; 32], ()>::new();
    for payload in payloads {
        let digest = digest(payload);
        if seen.contains_key(&digest) {
            continue;
        }
        if !frame.is_empty() && frame.len().saturating_add(payload.len()) > FRAME_TARGET_BYTES {
            total += compress_frame(&frame)?;
            frame.clear();
        }
        frame.extend_from_slice(payload);
        seen.insert(digest, ());
    }
    if !frame.is_empty() {
        total += compress_frame(&frame)?;
    }
    Ok(total)
}

fn digest(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"lockbox-dedupe-probe-v1");
    hasher.update(payload);
    hasher.finalize().into()
}

fn compress_frame(payload: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
    let compressed = compress_to_vec(payload, ruzstd_level(LEVEL));
    Ok(compressed.len().min(payload.len()))
}
