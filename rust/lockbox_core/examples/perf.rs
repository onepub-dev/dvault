use lockbox_core::{ExtractPolicy, ListOptions, Lockbox};
use std::io::{Read, Result as IoResult};
use std::time::{Duration, Instant};

const KEY: &[u8] = b"performance key";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = std::env::var("LOCKBOX_PERF_SCENARIO").unwrap_or_else(|_| "small".to_string());
    match scenario.as_str() {
        "small" => small_files()?,
        "large" => large_file()?,
        "append-delete" => append_delete()?,
        "all" => {
            small_files()?;
            large_file()?;
            append_delete()?;
        }
        _ => {
            eprintln!("unknown LOCKBOX_PERF_SCENARIO: {scenario}");
            eprintln!("expected one of: small, large, append-delete, all");
            std::process::exit(2);
        }
    }
    Ok(())
}

fn small_files() -> Result<(), Box<dyn std::error::Error>> {
    let file_count = std::env::var("LOCKBOX_PERF_FILES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(10_000usize);
    let file_size = std::env::var("LOCKBOX_PERF_FILE_BYTES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1024usize);

    let mut lockbox = Lockbox::create(KEY);
    let payload = vec![b'x'; file_size];

    let start = Instant::now();
    for i in 0..file_count {
        lockbox.put_file(&format!("/tree/file-{i:06}.bin"), &payload)?;
    }
    let add = start.elapsed();

    let start = Instant::now();
    lockbox.commit()?;
    let commit = start.elapsed();

    let start = Instant::now();
    let listed = lockbox
        .list_iter(ListOptions {
            recursive: true,
            ..ListOptions::new("/")
        })?
        .count();
    let list = start.elapsed();

    let out_dir = std::env::temp_dir().join(format!("lockbox-perf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out_dir);
    let policy = ExtractPolicy {
        overwrite: true,
        max_files: file_count + 1,
        ..ExtractPolicy::default()
    };

    let start = Instant::now();
    lockbox.extract_to_directory(&out_dir, &policy)?;
    let extract = start.elapsed();
    let _ = std::fs::remove_dir_all(&out_dir);

    let total_bytes = file_count as u64 * file_size as u64;
    print_report(Report {
        scenario: "small",
        files: file_count,
        listed,
        logical_bytes: total_bytes,
        vault_bytes: lockbox.to_bytes().len() as u64,
        add,
        commit,
        list,
        extract,
        read_range: Duration::ZERO,
    });
    Ok(())
}

fn large_file() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::env::var("LOCKBOX_PERF_LARGE_BYTES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1024usize * 1024 * 1024);
    let pattern = std::env::var("LOCKBOX_PERF_PATTERN").unwrap_or_else(|_| "randomish".into());

    let mut lockbox = Lockbox::create(KEY);
    let start = Instant::now();
    lockbox.put_file_from_reader("/large/blob.bin", PatternReader::new(bytes, &pattern))?;
    let add = start.elapsed();

    let start = Instant::now();
    lockbox.commit()?;
    let commit = start.elapsed();

    let range_offset = (bytes / 2) as u64;
    let start = Instant::now();
    let range = lockbox.read_file_range("/large/blob.bin", range_offset, 1024 * 1024)?;
    let read_range = start.elapsed();
    assert_eq!(
        range.len(),
        (1024 * 1024).min(bytes.saturating_sub(bytes / 2))
    );

    let out_dir = std::env::temp_dir().join(format!("lockbox-large-perf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out_dir);
    let policy = ExtractPolicy {
        overwrite: true,
        max_file_bytes: bytes as u64 + 1,
        max_total_bytes: bytes as u64 + 1,
        ..ExtractPolicy::default()
    };
    let start = Instant::now();
    lockbox.extract_to_directory(&out_dir, &policy)?;
    let extract = start.elapsed();
    let _ = std::fs::remove_dir_all(&out_dir);

    print_report(Report {
        scenario: "large",
        files: 1,
        listed: 1,
        logical_bytes: bytes as u64,
        vault_bytes: lockbox.to_bytes().len() as u64,
        add,
        commit,
        list: Duration::ZERO,
        extract,
        read_range,
    });
    Ok(())
}

fn append_delete() -> Result<(), Box<dyn std::error::Error>> {
    let initial_files = std::env::var("LOCKBOX_PERF_INITIAL_FILES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(5_000usize);
    let appended_files = std::env::var("LOCKBOX_PERF_APPEND_FILES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_000usize);
    let file_size = std::env::var("LOCKBOX_PERF_FILE_BYTES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2048usize);
    let payload = vec![b'a'; file_size];
    let replacement = vec![b'b'; file_size];

    let mut lockbox = Lockbox::create(KEY);
    for i in 0..initial_files {
        lockbox.put_file(&format!("/set/file-{i:06}.bin"), &payload)?;
    }
    lockbox.commit()?;

    let start = Instant::now();
    for i in initial_files..initial_files + appended_files {
        lockbox.put_file(&format!("/set/file-{i:06}.bin"), &payload)?;
    }
    let add = start.elapsed();

    let start = Instant::now();
    for i in 0..appended_files {
        lockbox.delete(&format!("/set/file-{i:06}.bin"))?;
    }
    for i in 0..appended_files {
        lockbox.put_file(&format!("/set/replacement-{i:06}.bin"), &replacement)?;
    }
    let delete_replace = start.elapsed();

    let start = Instant::now();
    lockbox.commit()?;
    let commit = start.elapsed();

    let start = Instant::now();
    let listed = lockbox
        .list_iter(ListOptions {
            recursive: true,
            ..ListOptions::new("/")
        })?
        .count();
    let list = start.elapsed();

    print_report(Report {
        scenario: "append-delete",
        files: initial_files + appended_files,
        listed,
        logical_bytes: ((initial_files + appended_files) * file_size) as u64,
        vault_bytes: lockbox.to_bytes().len() as u64,
        add,
        commit,
        list,
        extract: delete_replace,
        read_range: Duration::ZERO,
    });
    Ok(())
}

struct PatternReader {
    remaining: usize,
    offset: usize,
    pattern: Pattern,
}

enum Pattern {
    Zero,
    Randomish,
}

impl PatternReader {
    fn new(bytes: usize, pattern: &str) -> Self {
        let pattern = match pattern {
            "zero" | "zeros" => Pattern::Zero,
            _ => Pattern::Randomish,
        };
        Self {
            remaining: bytes,
            offset: 0,
            pattern,
        }
    }
}

impl Read for PatternReader {
    fn read(&mut self, out: &mut [u8]) -> IoResult<usize> {
        let len = out.len().min(self.remaining);
        if len == 0 {
            return Ok(0);
        }
        match self.pattern {
            Pattern::Zero => out[..len].fill(0),
            Pattern::Randomish => {
                for (i, byte) in out[..len].iter_mut().enumerate() {
                    let n = self.offset + i;
                    *byte = (n.wrapping_mul(31).wrapping_add(n >> 7) % 251) as u8;
                }
            }
        }
        self.offset += len;
        self.remaining -= len;
        Ok(len)
    }
}

struct Report {
    scenario: &'static str,
    files: usize,
    listed: usize,
    logical_bytes: u64,
    vault_bytes: u64,
    add: Duration,
    commit: Duration,
    list: Duration,
    extract: Duration,
    read_range: Duration,
}

fn print_report(report: Report) {
    println!("scenario: {}", report.scenario);
    println!("files: {}", report.files);
    println!("listed: {}", report.listed);
    println!("logical bytes: {}", report.logical_bytes);
    println!("vault bytes: {}", report.vault_bytes);
    println!("add: {:?}", report.add);
    println!("commit: {:?}", report.commit);
    println!("list: {:?}", report.list);
    println!("extract/delete_replace: {:?}", report.extract);
    println!("read range: {:?}", report.read_range);
    if report.logical_bytes > 0 {
        println!(
            "vault/logical ratio: {:.3}",
            report.vault_bytes as f64 / report.logical_bytes as f64
        );
    }
}
