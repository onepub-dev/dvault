use lockbox_core::{
    EnvName, ExtractPolicy, ListOptions, Lockbox, LockboxCreate, LockboxPath, SecretVec,
};
use std::io::{Read, Result as IoResult};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const KEY: &[u8] = b"performance key";

fn p(path: impl AsRef<str>) -> LockboxPath {
    LockboxPath::new(path).unwrap()
}

fn env(name: impl AsRef<str>) -> EnvName {
    EnvName::new(name).unwrap()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = std::env::var("LOCKBOX_PERF_SCENARIO").unwrap_or_else(|_| "small".to_string());
    match scenario.as_str() {
        "small" => small_files()?,
        "large" => large_file()?,
        "append-delete" => append_delete()?,
        "metadata" => metadata_operations()?,
        "all" => {
            small_files()?;
            large_file()?;
            append_delete()?;
            metadata_operations()?;
        }
        _ => {
            eprintln!("unknown LOCKBOX_PERF_SCENARIO: {scenario}");
            eprintln!("expected one of: small, large, append-delete, metadata, all");
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

    let mut bench = BenchLockbox::create("small")?;
    let lockbox = &mut bench.lockbox;
    let payload = vec![b'x'; file_size];

    let start = Instant::now();
    for i in 0..file_count {
        lockbox.add_file(&p(format!("/tree/file-{i:06}.bin")), &payload, false)?;
    }
    let add = start.elapsed();

    let start = Instant::now();
    lockbox.commit()?;
    let commit = start.elapsed();

    let start = Instant::now();
    let listed = lockbox
        .list_iter(ListOptions {
            recursive: true,
            ..ListOptions::new(&p("/"))
        })?
        .count();
    let list = start.elapsed();

    let policy = ExtractPolicy {
        max_files: file_count + 1,
        ..ExtractPolicy::default()
    };
    let extract = run_extract(lockbox, "small", &policy)?;

    let total_bytes = file_count as u64 * file_size as u64;
    print_report(Report {
        scenario: "small",
        backend: bench.backend.clone(),
        files: file_count,
        listed,
        logical_bytes: total_bytes,
        lockbox_bytes: bench.lockbox_bytes()?,
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

    let mut bench = BenchLockbox::create("large")?;
    let lockbox = &mut bench.lockbox;
    let start = Instant::now();
    lockbox.add_file_from_reader(
        &p("/large/blob.bin"),
        PatternReader::new(bytes, &pattern),
        false,
    )?;
    let add = start.elapsed();

    let start = Instant::now();
    lockbox.commit()?;
    let commit = start.elapsed();

    let range_offset = (bytes / 2) as u64;
    let start = Instant::now();
    let range = lockbox.read_file_range(&p("/large/blob.bin"), range_offset, 1024 * 1024)?;
    let read_range = start.elapsed();
    assert_eq!(
        range.len(),
        (1024 * 1024).min(bytes.saturating_sub(bytes / 2))
    );

    let policy = ExtractPolicy {
        max_file_bytes: bytes as u64 + 1,
        max_total_bytes: bytes as u64 + 1,
        ..ExtractPolicy::default()
    };
    let extract = run_extract(lockbox, "large", &policy)?;

    print_report(Report {
        scenario: "large",
        backend: bench.backend.clone(),
        files: 1,
        listed: 1,
        logical_bytes: bytes as u64,
        lockbox_bytes: bench.lockbox_bytes()?,
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

    let mut bench = BenchLockbox::create("append-delete")?;
    let lockbox = &mut bench.lockbox;
    for i in 0..initial_files {
        lockbox.add_file(&p(format!("/set/file-{i:06}.bin")), &payload, false)?;
    }
    lockbox.commit()?;

    let start = Instant::now();
    for i in initial_files..initial_files + appended_files {
        lockbox.add_file(&p(format!("/set/file-{i:06}.bin")), &payload, false)?;
    }
    let add = start.elapsed();

    let start = Instant::now();
    for i in 0..appended_files {
        lockbox.delete(&p(format!("/set/file-{i:06}.bin")))?;
    }
    for i in 0..appended_files {
        lockbox.add_file(
            &p(format!("/set/replacement-{i:06}.bin")),
            &replacement,
            false,
        )?;
    }
    let delete_replace = start.elapsed();

    let start = Instant::now();
    lockbox.commit()?;
    let commit = start.elapsed();

    let start = Instant::now();
    let listed = lockbox
        .list_iter(ListOptions {
            recursive: true,
            ..ListOptions::new(&p("/"))
        })?
        .count();
    let list = start.elapsed();

    print_report(Report {
        scenario: "append-delete",
        backend: bench.backend.clone(),
        files: initial_files + appended_files,
        listed,
        logical_bytes: ((initial_files + appended_files) * file_size) as u64,
        lockbox_bytes: bench.lockbox_bytes()?,
        add,
        commit,
        list,
        extract: delete_replace,
        read_range: Duration::ZERO,
    });
    Ok(())
}

fn metadata_operations() -> Result<(), Box<dyn std::error::Error>> {
    let large_bytes = std::env::var("LOCKBOX_PERF_LARGE_BYTES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(256usize * 1024 * 1024);
    let env_count = std::env::var("LOCKBOX_PERF_ENV_VARS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(10_000usize);
    let pattern = std::env::var("LOCKBOX_PERF_PATTERN").unwrap_or_else(|_| "randomish".into());

    let mut bench = BenchLockbox::create("metadata")?;
    let lockbox = &mut bench.lockbox;
    lockbox.add_file_from_reader(
        &p("/large/source.bin"),
        PatternReader::new(large_bytes, &pattern),
        false,
    )?;
    for i in 0..env_count {
        lockbox.set_env(&env(format!("LOCKBOX_ENV_{i:06}")), "value")?;
    }
    lockbox.add_file(&p("/delete-me.txt"), b"delete", false)?;
    lockbox.commit()?;

    let start = Instant::now();
    lockbox.rename(&p("/large/source.bin"), &p("/archive/renamed.bin"))?;
    let rename = start.elapsed();

    let start = Instant::now();
    let listed = lockbox.list_env()?.len();
    let list_env = start.elapsed();

    lockbox.delete(&p("/delete-me.txt"))?;
    let start = Instant::now();
    lockbox.commit()?;
    let compact = start.elapsed();

    let start = Instant::now();
    lockbox.commit()?;
    let commit = start.elapsed();

    print_report(Report {
        scenario: "metadata",
        backend: bench.backend.clone(),
        files: 1,
        listed,
        logical_bytes: large_bytes as u64,
        lockbox_bytes: bench.lockbox_bytes()?,
        add: rename,
        commit,
        list: list_env,
        extract: compact,
        read_range: Duration::ZERO,
    });
    Ok(())
}

fn run_extract(
    lockbox: &Lockbox,
    name: &str,
    policy: &ExtractPolicy,
) -> Result<Duration, Box<dyn std::error::Error>> {
    let mode = std::env::var("LOCKBOX_PERF_EXTRACT").unwrap_or_else(|_| "directory".to_string());
    let repeat = std::env::var("LOCKBOX_PERF_EXTRACT_REPEAT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1usize);
    let start = Instant::now();
    for i in 0..repeat {
        match mode.as_str() {
            "stream" => {
                let mut count = 0usize;
                for entry in lockbox.list_iter(ListOptions {
                    recursive: true,
                    ..ListOptions::new(&p("/"))
                })? {
                    let entry = entry?;
                    if entry.kind == lockbox_core::LockboxEntryKind::File
                        && entry.len <= policy.max_file_bytes
                    {
                        lockbox.extract_file_to_writer(&entry.path, std::io::sink())?;
                        count += 1;
                    }
                }
                let _ = count;
            }
            "directory" => {
                let out_dir = perf_scratch_dir()?
                    .join(format!("lockbox-{name}-perf-{}-{i}", std::process::id()));
                let _ = std::fs::remove_dir_all(&out_dir);
                lockbox.extract_to_directory(&out_dir, policy)?;
                let _ = std::fs::remove_dir_all(&out_dir);
            }
            other => {
                return Err(format!("unknown LOCKBOX_PERF_EXTRACT: {other}").into());
            }
        }
    }
    Ok(start.elapsed())
}

struct BenchLockbox {
    lockbox: Lockbox,
    path: Option<PathBuf>,
    backend: String,
}

impl BenchLockbox {
    fn create(name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let backend =
            std::env::var("LOCKBOX_PERF_BACKEND").unwrap_or_else(|_| "memory".to_string());
        if backend == "file" {
            let path =
                perf_scratch_dir()?.join(format!("lockbox-perf-{name}-{}.lbx", std::process::id()));
            let _ = std::fs::remove_file(&path);
            Ok(Self {
                lockbox: Lockbox::create_file(
                    &path,
                    LockboxCreate::ContentKey(SecretVec::try_from_slice(KEY).unwrap()),
                )?,
                path: Some(path),
                backend,
            })
        } else {
            let path =
                perf_scratch_dir()?.join(format!("lockbox-perf-{name}-{}.lbx", std::process::id()));
            let _ = std::fs::remove_file(&path);
            Ok(Self {
                lockbox: Lockbox::create_file(
                    &path,
                    LockboxCreate::ContentKey(SecretVec::try_from_slice(KEY).unwrap()),
                )?,
                path: Some(path),
                backend,
            })
        }
    }

    fn lockbox_bytes(&self) -> Result<u64, Box<dyn std::error::Error>> {
        Ok(self.lockbox.inspector().storage_len()?)
    }
}

fn perf_scratch_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = std::env::var_os("LOCKBOX_PERF_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

impl Drop for BenchLockbox {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = std::fs::remove_file(path);
        }
    }
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
                    let n = (self.offset + i) as u64;
                    let mut x = n.wrapping_add(0x9e3779b97f4a7c15);
                    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
                    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
                    *byte = (x ^ (x >> 31)) as u8;
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
    backend: String,
    files: usize,
    listed: usize,
    logical_bytes: u64,
    lockbox_bytes: u64,
    add: Duration,
    commit: Duration,
    list: Duration,
    extract: Duration,
    read_range: Duration,
}

fn print_report(report: Report) {
    println!("scenario: {}", report.scenario);
    println!("backend: {}", report.backend);
    println!("files: {}", report.files);
    println!("listed: {}", report.listed);
    println!("logical bytes: {}", report.logical_bytes);
    println!("lockbox bytes: {}", report.lockbox_bytes);
    println!("add: {:?}", report.add);
    println!("commit: {:?}", report.commit);
    println!("list: {:?}", report.list);
    println!("extract/delete_replace: {:?}", report.extract);
    println!("read range: {:?}", report.read_range);
    if report.logical_bytes > 0 {
        println!(
            "lockbox/logical ratio: {:.3}",
            report.lockbox_bytes as f64 / report.logical_bytes as f64
        );
    }
}
