use oxiarc_zstd::{train_dictionary, ZstdEncoder};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

const FRAME_TARGET_BYTES: usize = 2 * 1024 * 1024;
const SAMPLE_BYTES_PER_FILE: usize = 4096;
const MAX_SAMPLE_FILES: usize = 512;
const LEVEL: i32 = 3;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(root) = env::args_os().nth(1) else {
        eprintln!("usage: dict_probe <fixture-root>");
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
    let baseline = compress_frames(&payloads, None)?;
    println!(
        "fixture\tfiles\tlogical_bytes\tbaseline_frame_bytes\tdict_size\tdict_training_ms\tdict_frame_bytes\tdict_total_bytes\tdelta_vs_frame_bytes\tdelta_vs_total_bytes"
    );
    for dict_size in [4096usize, 16 * 1024, 64 * 1024, 112 * 1024] {
        let sample_storage = build_samples(&payloads);
        let samples = sample_storage.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let train_start = Instant::now();
        let dict = train_dictionary(&samples, dict_size)?;
        let training_ms = train_start.elapsed().as_secs_f64() * 1000.0;
        let dict_bytes = dict.data();
        let compressed = compress_frames(&payloads, Some(dict_bytes))?;
        let total = compressed + dict_bytes.len();
        println!(
            "{}\t{}\t{}\t{}\t{}\t{:.3}\t{}\t{}\t{}\t{}",
            root.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("fixture"),
            files.len(),
            logical_bytes,
            baseline,
            dict_bytes.len(),
            training_ms,
            compressed,
            total,
            baseline as i128 - compressed as i128,
            baseline as i128 - total as i128
        );
    }
    Ok(())
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

fn build_samples(payloads: &[Vec<u8>]) -> Vec<Vec<u8>> {
    payloads
        .iter()
        .take(MAX_SAMPLE_FILES)
        .filter(|payload| !payload.is_empty())
        .map(|payload| payload[..payload.len().min(SAMPLE_BYTES_PER_FILE)].to_vec())
        .collect()
}

fn compress_frames(
    payloads: &[Vec<u8>],
    dictionary: Option<&[u8]>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut total = 0usize;
    let mut frame = Vec::new();
    for payload in payloads {
        if !frame.is_empty() && frame.len().saturating_add(payload.len()) > FRAME_TARGET_BYTES {
            total += compress_frame(&frame, dictionary)?;
            frame.clear();
        }
        frame.extend_from_slice(payload);
    }
    if !frame.is_empty() {
        total += compress_frame(&frame, dictionary)?;
    }
    Ok(total)
}

fn compress_frame(
    payload: &[u8],
    dictionary: Option<&[u8]>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut encoder = ZstdEncoder::new();
    encoder.set_level(LEVEL);
    if let Some(dictionary) = dictionary {
        encoder.set_dictionary(dictionary);
    }
    let compressed = encoder.compress(payload)?;
    Ok(compressed.len().min(payload.len()))
}
