#[path = "common/probe_ruzstd.rs"]
mod probe_ruzstd;

use probe_ruzstd::ruzstd_level;
use ruzstd::encoding::compress_to_vec;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

const LEVEL: i32 = 3;
const DIGEST_BYTES: usize = 32;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(root) = env::args_os().nth(1) else {
        eprintln!("usage: archive_v2_probe <fixture-root>");
        std::process::exit(2);
    };
    let root = PathBuf::from(root);
    let files = collect_files(&root)?;
    if files.is_empty() {
        return Err("no files found".into());
    }

    let mut entries = Vec::with_capacity(files.len());
    for path in files {
        let rel = path
            .strip_prefix(&root)?
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = fs::read(&path)?;
        entries.push(FileEntry { path: rel, bytes });
    }
    let logical_bytes = entries.iter().map(|entry| entry.bytes.len()).sum::<usize>();

    println!(
        "fixture\tstrategy\tpack_target_bytes\tfiles\tlogical_bytes\tpacks\tmax_pack_bytes\tdata_compressed_bytes\tcurrent_manifest_bytes\tv2_metadata_bytes\tv2_pack_manifest_bytes\tv2_total_estimated_bytes\tcompress_ms\tmean_read_amp\tall_slices_once_amp"
    );

    for target in [
        512 * 1024,
        1024 * 1024,
        2 * 1024 * 1024,
        4 * 1024 * 1024,
        8 * 1024 * 1024,
    ] {
        for strategy in [
            Strategy::PathOrder,
            Strategy::Extension,
            Strategy::ContentClass,
        ] {
            let packs = build_packs(&entries, target, strategy);
            let stats = analyze(&root, &entries, &packs, target, strategy, logical_bytes)?;
            print_stats(stats);
        }
    }

    Ok(())
}

#[derive(Clone)]
struct FileEntry {
    path: String,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy)]
enum Strategy {
    PathOrder,
    Extension,
    ContentClass,
}

impl Strategy {
    fn name(self) -> &'static str {
        match self {
            Strategy::PathOrder => "path-order",
            Strategy::Extension => "extension",
            Strategy::ContentClass => "content-class",
        }
    }
}

struct Pack {
    bytes: Vec<u8>,
    slices: Vec<Slice>,
}

struct Slice {
    file_id: usize,
    file_offset: usize,
    pack_offset: usize,
    len: usize,
}

struct Stats<'a> {
    fixture: &'a str,
    strategy: &'static str,
    pack_target_bytes: usize,
    files: usize,
    logical_bytes: usize,
    packs: usize,
    max_pack_bytes: usize,
    data_compressed_bytes: usize,
    current_manifest_bytes: usize,
    v2_metadata_bytes: usize,
    v2_pack_manifest_bytes: usize,
    v2_total_estimated_bytes: usize,
    compress_ms: f64,
    mean_read_amp: f64,
    all_slices_once_amp: f64,
}

fn print_stats(stats: Stats<'_>) {
    println!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.3}\t{:.3}\t{:.3}",
        stats.fixture,
        stats.strategy,
        stats.pack_target_bytes,
        stats.files,
        stats.logical_bytes,
        stats.packs,
        stats.max_pack_bytes,
        stats.data_compressed_bytes,
        stats.current_manifest_bytes,
        stats.v2_metadata_bytes,
        stats.v2_pack_manifest_bytes,
        stats.v2_total_estimated_bytes,
        stats.compress_ms,
        stats.mean_read_amp,
        stats.all_slices_once_amp
    );
}

fn analyze<'a>(
    root: &'a Path,
    entries: &[FileEntry],
    packs: &[Pack],
    pack_target_bytes: usize,
    strategy: Strategy,
    logical_bytes: usize,
) -> Result<Stats<'a>, Box<dyn std::error::Error>> {
    let started = Instant::now();
    let mut data_compressed_bytes = 0usize;
    for pack in packs {
        data_compressed_bytes += compress_len(&pack.bytes)?;
    }
    let compress_ms = started.elapsed().as_secs_f64() * 1000.0;
    let current_manifest_bytes = encode_current_like_manifests(entries, packs).len();
    let v2_metadata_bytes = encode_v2_metadata(entries, packs).len();
    let v2_pack_manifest_bytes = encode_v2_pack_manifests(packs).len();
    let v2_total_estimated_bytes =
        data_compressed_bytes + v2_metadata_bytes + v2_pack_manifest_bytes;
    let max_pack_bytes = packs.iter().map(|pack| pack.bytes.len()).max().unwrap_or(0);
    Ok(Stats {
        fixture: root
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("fixture"),
        strategy: strategy.name(),
        pack_target_bytes,
        files: entries.len(),
        logical_bytes,
        packs: packs.len(),
        max_pack_bytes,
        data_compressed_bytes,
        current_manifest_bytes,
        v2_metadata_bytes,
        v2_pack_manifest_bytes,
        v2_total_estimated_bytes,
        compress_ms,
        mean_read_amp: mean_read_amp(packs, entries),
        all_slices_once_amp: all_slices_once_amp(packs, entries),
    })
}

fn build_packs(entries: &[FileEntry], target: usize, strategy: Strategy) -> Vec<Pack> {
    let mut ids: Vec<usize> = (0..entries.len()).collect();
    match strategy {
        Strategy::PathOrder => {
            ids.sort_by(|left, right| entries[*left].path.cmp(&entries[*right].path))
        }
        Strategy::Extension => ids.sort_by(|left, right| {
            extension_key(&entries[*left].path)
                .cmp(&extension_key(&entries[*right].path))
                .then_with(|| entries[*left].path.cmp(&entries[*right].path))
        }),
        Strategy::ContentClass => ids.sort_by(|left, right| {
            content_class(&entries[*left].bytes, &entries[*left].path)
                .cmp(&content_class(
                    &entries[*right].bytes,
                    &entries[*right].path,
                ))
                .then_with(|| {
                    extension_key(&entries[*left].path).cmp(&extension_key(&entries[*right].path))
                })
                .then_with(|| entries[*left].path.cmp(&entries[*right].path))
        }),
    }

    let mut packs = Vec::new();
    let mut current = Pack {
        bytes: Vec::new(),
        slices: Vec::new(),
    };
    for file_id in ids {
        let entry = &entries[file_id];
        let mut file_offset = 0usize;
        while file_offset < entry.bytes.len() || (entry.bytes.is_empty() && file_offset == 0) {
            let remaining = entry.bytes.len().saturating_sub(file_offset);
            let chunk_len = if entry.bytes.is_empty() {
                0
            } else {
                remaining.min(target)
            };
            if !current.bytes.is_empty() && current.bytes.len().saturating_add(chunk_len) > target {
                packs.push(current);
                current = Pack {
                    bytes: Vec::new(),
                    slices: Vec::new(),
                };
            }
            let pack_offset = current.bytes.len();
            current
                .bytes
                .extend_from_slice(&entry.bytes[file_offset..file_offset + chunk_len]);
            current.slices.push(Slice {
                file_id,
                file_offset,
                pack_offset,
                len: chunk_len,
            });
            file_offset += chunk_len;
            if entry.bytes.is_empty() {
                break;
            }
        }
    }
    if !current.slices.is_empty() {
        packs.push(current);
    }
    packs
}

fn encode_current_like_manifests(entries: &[FileEntry], packs: &[Pack]) -> Vec<u8> {
    let mut out = Vec::new();
    for (pack_id, pack) in packs.iter().enumerate() {
        put_varint(pack_id as u64, &mut out);
        put_varint(1, &mut out);
        put_varint(pack.bytes.len() as u64, &mut out);
        put_varint(pack.bytes.len() as u64, &mut out);
        out.extend_from_slice(&[0; DIGEST_BYTES]);
        put_varint(pack.slices.len() as u64, &mut out);
        for slice in &pack.slices {
            let path = entries[slice.file_id].path.as_bytes();
            put_varint(path.len() as u64, &mut out);
            out.extend_from_slice(path);
            put_varint(0o644, &mut out);
            put_varint(entries[slice.file_id].bytes.len() as u64, &mut out);
            put_varint(slice.file_offset as u64, &mut out);
            put_varint(slice.pack_offset as u64, &mut out);
            put_varint(slice.len as u64, &mut out);
        }
    }
    out
}

fn encode_v2_metadata(entries: &[FileEntry], packs: &[Pack]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut components = BTreeMap::<String, usize>::new();
    let mut paths = Vec::<Vec<usize>>::new();
    for entry in entries {
        let mut ids = Vec::new();
        for component in entry.path.split('/') {
            let next = components.len();
            let id = *components.entry(component.to_string()).or_insert(next);
            ids.push(id);
        }
        paths.push(ids);
    }

    put_varint(components.len() as u64, &mut out);
    for component in components.keys() {
        put_varint(component.len() as u64, &mut out);
        out.extend_from_slice(component.as_bytes());
    }

    put_varint(paths.len() as u64, &mut out);
    for ids in &paths {
        put_varint(ids.len() as u64, &mut out);
        let mut previous = 0usize;
        for id in ids {
            put_varint(id.saturating_sub(previous) as u64, &mut out);
            previous = *id;
        }
    }

    put_varint(entries.len() as u64, &mut out);
    for (file_id, entry) in entries.iter().enumerate() {
        put_varint(file_id as u64, &mut out);
        put_varint(file_id as u64, &mut out);
        put_varint(entry.bytes.len() as u64, &mut out);
        put_varint(0o644, &mut out);
    }

    let mut previous_file = 0usize;
    for pack in packs {
        for slice in &pack.slices {
            put_varint(slice.file_id.saturating_sub(previous_file) as u64, &mut out);
            put_varint(slice.file_offset as u64, &mut out);
            put_varint(slice.len as u64, &mut out);
            previous_file = slice.file_id;
        }
    }
    out
}

fn encode_v2_pack_manifests(packs: &[Pack]) -> Vec<u8> {
    let mut out = Vec::new();
    for (pack_id, pack) in packs.iter().enumerate() {
        put_varint(pack_id as u64, &mut out);
        put_varint(1, &mut out);
        put_varint(pack.bytes.len() as u64, &mut out);
        put_varint(pack.bytes.len() as u64, &mut out);
        out.extend_from_slice(&[0; DIGEST_BYTES]);
        put_varint(pack.slices.len() as u64, &mut out);
        let mut previous_file = 0usize;
        let mut previous_file_offset = 0usize;
        let mut previous_pack_offset = 0usize;
        for slice in &pack.slices {
            put_varint(slice.file_id.saturating_sub(previous_file) as u64, &mut out);
            put_varint(
                slice.file_offset.saturating_sub(previous_file_offset) as u64,
                &mut out,
            );
            put_varint(
                slice.pack_offset.saturating_sub(previous_pack_offset) as u64,
                &mut out,
            );
            put_varint(slice.len as u64, &mut out);
            put_varint(0, &mut out);
            previous_file = slice.file_id;
            previous_file_offset = slice.file_offset;
            previous_pack_offset = slice.pack_offset;
        }
    }
    out
}

fn mean_read_amp(packs: &[Pack], entries: &[FileEntry]) -> f64 {
    let mut total = 0.0f64;
    let mut count = 0usize;
    for pack in packs {
        for slice in &pack.slices {
            let file_len = entries[slice.file_id].bytes.len().max(1);
            total += pack.bytes.len() as f64 / file_len as f64;
            count += 1;
        }
    }
    if count == 0 {
        0.0
    } else {
        total / count as f64
    }
}

fn all_slices_once_amp(packs: &[Pack], entries: &[FileEntry]) -> f64 {
    let logical = entries.iter().map(|entry| entry.bytes.len()).sum::<usize>();
    let mut decompressed = 0usize;
    for pack in packs {
        decompressed += pack.bytes.len() * pack.slices.len();
    }
    if logical == 0 {
        0.0
    } else {
        decompressed as f64 / logical as f64
    }
}

fn content_class(bytes: &[u8], path: &str) -> String {
    if bytes.is_empty() {
        return format!("empty:{}", extension_key(path));
    }
    let sample = &bytes[..bytes.len().min(4096)];
    let nul = sample.iter().filter(|byte| **byte == 0).count();
    let printable = sample
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
        .count();
    if nul > sample.len() / 64 {
        "binary-nul".to_string()
    } else if printable * 100 / sample.len() > 90 {
        format!("text:{}", extension_key(path))
    } else {
        format!("binary:{}", extension_key(path))
    }
}

fn extension_key(path: &str) -> String {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn compress_len(payload: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
    let compressed = compress_to_vec(payload, ruzstd_level(LEVEL));
    Ok(compressed.len().min(payload.len()))
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

fn put_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}
