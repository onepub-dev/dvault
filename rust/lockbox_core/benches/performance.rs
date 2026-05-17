use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use lockbox_core::{
    EnvName, ExtractPolicy, ListOptions, Lockbox, LockboxPath, LockboxProtection, SecretString,
    SecretVec,
};
use lockbox_secure::read_access as secure_read_access;
use std::fs;
use std::io::{sink, Read, Result as IoResult};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const KEY: &[u8] = b"criterion performance key";
static LOCKBOX_COUNTER: AtomicU64 = AtomicU64::new(0);

fn p(path: impl AsRef<str>) -> LockboxPath {
    LockboxPath::new(path).unwrap()
}

fn env(name: impl AsRef<str>) -> EnvName {
    EnvName::new(name).unwrap()
}

fn bench_small_files(c: &mut Criterion) {
    let mut group = c.benchmark_group("small_files");
    group.sample_size(10);

    group.bench_function("add_commit_1000x1k", |b| {
        b.iter_batched(
            || vec![b'x'; 1024],
            |payload| {
                let mut lockbox = new_lockbox();
                for i in 0..1000 {
                    lockbox
                        .add_file(&p(format!("/tree/file-{i:06}.bin")), &payload, false)
                        .unwrap();
                }
                lockbox.commit().unwrap();
                black_box(lockbox.inspector().storage_len().unwrap() as usize);
            },
            BatchSize::SmallInput,
        );
    });

    let lockbox = prepared_small_lockbox(1000, 1024);
    let policy = ExtractPolicy {
        max_files: 1001,
        ..ExtractPolicy::default()
    };
    group.bench_function("extract_stream_1000x1k", |b| {
        b.iter(|| {
            let mut count = 0usize;
            for entry in lockbox
                .list_iter(ListOptions {
                    recursive: true,
                    ..ListOptions::new(&p("/"))
                })
                .unwrap()
            {
                let entry = entry.unwrap();
                lockbox.extract_file_to_writer(&entry.path, sink()).unwrap();
                count += 1;
            }
            black_box(count);
        });
    });

    group.bench_function("extract_directory_1000x1k", |b| {
        b.iter_batched(
            temp_output_dir,
            |out_dir| {
                lockbox.extract_to_directory(&out_dir, &policy).unwrap();
                black_box(fs::metadata(&out_dir).unwrap().is_dir());
                let _ = fs::remove_dir_all(&out_dir);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_mixed_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("mixed_tree");
    group.sample_size(10);

    group.bench_function("add_commit_mixed", |b| {
        b.iter(|| {
            let mut lockbox = new_lockbox();
            add_mixed_tree(&mut lockbox);
            lockbox.commit().unwrap();
            black_box(lockbox.inspector().storage_len().unwrap() as usize);
        });
    });

    let mut lockbox = new_lockbox();
    add_mixed_tree(&mut lockbox);
    lockbox.commit().unwrap();

    group.bench_function("list_recursive_mixed", |b| {
        b.iter(|| {
            let count = lockbox
                .list_iter(ListOptions {
                    recursive: true,
                    ..ListOptions::new(&p("/"))
                })
                .unwrap()
                .count();
            black_box(count);
        });
    });

    let policy = ExtractPolicy {
        max_files: 512,
        max_file_bytes: 2 * 1024 * 1024,
        max_total_bytes: 64 * 1024 * 1024,
        ..ExtractPolicy::default()
    };
    group.bench_function("extract_directory_mixed", |b| {
        b.iter_batched(
            temp_output_dir,
            |out_dir| {
                lockbox.extract_to_directory(&out_dir, &policy).unwrap();
                black_box(fs::metadata(&out_dir).unwrap().is_dir());
                let _ = fs::remove_dir_all(&out_dir);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_large_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("large_file");
    group.sample_size(10);

    group.bench_function("add_commit_16m_randomish", |b| {
        b.iter(|| {
            let mut lockbox = new_lockbox();
            lockbox
                .add_file_from_reader(
                    &p("/large/blob.bin"),
                    PatternReader::new(16 * 1024 * 1024, Pattern::Randomish),
                    false,
                )
                .unwrap();
            lockbox.commit().unwrap();
            black_box(lockbox.inspector().storage_len().unwrap() as usize);
        });
    });

    let mut lockbox = new_lockbox();
    lockbox
        .add_file_from_reader(
            &p("/large/blob.bin"),
            PatternReader::new(16 * 1024 * 1024, Pattern::Randomish),
            false,
        )
        .unwrap();
    lockbox.commit().unwrap();

    group.bench_function("range_read_1m_middle", |b| {
        b.iter(|| {
            let data = lockbox
                .read_file_range(&p("/large/blob.bin"), 8 * 1024 * 1024, 1024 * 1024)
                .unwrap();
            black_box(data.len());
        });
    });

    group.finish();
}

fn bench_append_delete(c: &mut Criterion) {
    let mut group = c.benchmark_group("append_delete");
    group.sample_size(10);

    group.bench_function("append_delete_replace_commit", |b| {
        b.iter_batched(
            || {
                let payload = vec![b'a'; 2048];
                let mut lockbox = new_lockbox();
                for i in 0..1000 {
                    lockbox
                        .add_file(&p(format!("/set/file-{i:06}.bin")), &payload, false)
                        .unwrap();
                }
                lockbox.commit().unwrap();
                lockbox
            },
            |mut lockbox| {
                let payload = vec![b'b'; 2048];
                for i in 1000..1200 {
                    lockbox
                        .add_file(&p(format!("/set/file-{i:06}.bin")), &payload, false)
                        .unwrap();
                }
                for i in 0..200 {
                    lockbox.delete(&p(format!("/set/file-{i:06}.bin"))).unwrap();
                    lockbox
                        .add_file(&p(format!("/set/replacement-{i:06}.bin")), &payload, false)
                        .unwrap();
                }
                lockbox.commit().unwrap();
                black_box(lockbox.inspector().storage_len().unwrap() as usize);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_toc_structure(c: &mut Criterion) {
    let mut group = c.benchmark_group("toc_structure");
    group.sample_size(10);

    group.bench_function("separator_update_5000", |b| {
        b.iter_batched(
            || prepared_small_lockbox(5000, 256),
            |mut lockbox| {
                lockbox
                    .add_file(&p("/tree/file-000000.bin"), black_box(b"changed"), true)
                    .unwrap();
                lockbox.commit().unwrap();
                black_box(lockbox.inspector().storage_len().unwrap() as usize);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("leaf_split_append_5000", |b| {
        b.iter_batched(
            || prepared_small_lockbox(5000, 256),
            |mut lockbox| {
                for i in 5000..5500 {
                    lockbox
                        .add_file(&p(format!("/tree/file-{i:06}.bin")), b"new", false)
                        .unwrap();
                }
                lockbox.commit().unwrap();
                black_box(lockbox.inspector().storage_len().unwrap() as usize);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("leaf_merge_delete_5000", |b| {
        b.iter_batched(
            || prepared_small_lockbox(5000, 256),
            |mut lockbox| {
                for i in 0..500 {
                    lockbox
                        .delete(&p(format!("/tree/file-{i:06}.bin")))
                        .unwrap();
                }
                lockbox.commit().unwrap();
                black_box(lockbox.inspector().storage_len().unwrap() as usize);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_metadata_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("metadata_operations");
    group.sample_size(10);

    group.bench_function("rename_16m_file_commit", |b| {
        b.iter_batched(
            || {
                let mut lockbox = new_lockbox();
                lockbox
                    .add_file_from_reader(
                        &p("/large/source.bin"),
                        PatternReader::new(16 * 1024 * 1024, Pattern::Randomish),
                        false,
                    )
                    .unwrap();
                lockbox.commit().unwrap();
                lockbox
            },
            |mut lockbox| {
                lockbox
                    .rename(&p("/large/source.bin"), &p("/archive/renamed.bin"))
                    .unwrap();
                lockbox.commit().unwrap();
                black_box(lockbox.stat(&p("/archive/renamed.bin")).unwrap().len);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("list_env_1000", |b| {
        b.iter_batched(
            || {
                let mut lockbox = new_lockbox();
                for i in 0..1000 {
                    lockbox
                        .set_env(&env(format!("LOCKBOX_ENV_{i:04}")), "value")
                        .unwrap();
                }
                lockbox.commit().unwrap();
                lockbox
            },
            |lockbox| {
                let names = lockbox.list_env().unwrap();
                black_box(names.len());
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("compact_16m_file_after_delete", |b| {
        b.iter_batched(
            || {
                let mut lockbox = new_lockbox();
                lockbox
                    .add_file_from_reader(
                        &p("/large/blob.bin"),
                        PatternReader::new(16 * 1024 * 1024, Pattern::Randomish),
                        false,
                    )
                    .unwrap();
                lockbox
                    .add_file(&p("/delete-me.txt"), b"delete", false)
                    .unwrap();
                lockbox.commit().unwrap();
                lockbox.delete(&p("/delete-me.txt")).unwrap();
                lockbox
            },
            |mut lockbox| {
                lockbox.commit().unwrap();
                lockbox.commit().unwrap();
                black_box(lockbox.stat(&p("/large/blob.bin")).unwrap().len);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_secure_string_store(c: &mut Criterion) {
    let mut group = c.benchmark_group("secure_string_store");
    group.sample_size(10);

    group.bench_function("from_bytes_1000x64", |b| {
        b.iter_batched(
            || secure_payloads(1000, 64),
            |payloads| {
                let secrets = payloads
                    .into_iter()
                    .map(|payload| SecretString::try_from_bytes(payload).unwrap())
                    .collect::<Vec<_>>();
                black_box(secrets.len());
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("push_byte_64", |b| {
        b.iter_batched(
            || secure_payload(64),
            |payload| {
                let mut secret = SecretString::new();
                for byte in payload {
                    secret.try_push_byte(byte).unwrap();
                }
                black_box(secret);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("extend_slice_64", |b| {
        b.iter_batched(
            || secure_payload(64),
            |payload| {
                let mut secret = SecretString::new();
                secret.try_extend_from_slice(&payload).unwrap();
                black_box(secret);
            },
            BatchSize::SmallInput,
        );
    });

    let secrets = secure_strings(1000, 64);
    group.bench_function("read_1000x64_individual_guard", |b| {
        b.iter(|| {
            let mut total = 0usize;
            for secret in &secrets {
                total += secret.with_str(str::len).unwrap();
            }
            black_box(total);
        });
    });

    group.bench_function("read_1000x64_shared_guard", |b| {
        b.iter(|| {
            let total = secure_read_access(|access| {
                let mut total = 0usize;
                for secret in &secrets {
                    total += access.with_str(secret, str::len).unwrap();
                }
                total
            });
            black_box(total);
        });
    });

    group.finish();
}

fn prepared_small_lockbox(files: usize, file_size: usize) -> Lockbox {
    let payload = vec![b'x'; file_size];
    let mut lockbox = new_lockbox();
    for i in 0..files {
        lockbox
            .add_file(&p(format!("/tree/file-{i:06}.bin")), &payload, false)
            .unwrap();
    }
    lockbox.commit().unwrap();
    lockbox
}

fn new_lockbox() -> Lockbox {
    let index = LOCKBOX_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path =
        std::env::temp_dir().join(format!("lockbox-bench-{}-{index}.lbx", std::process::id()));
    let _ = fs::remove_file(&path);
    Lockbox::create_file(
        &path,
        LockboxProtection::ContentKey(SecretVec::try_from_slice(KEY).unwrap()),
    )
    .unwrap()
}

fn add_mixed_tree(lockbox: &mut Lockbox) {
    let tiny = vec![b't'; 512];
    let medium = vec![b'm'; 128 * 1024];
    for dir in 0..8 {
        for file in 0..25 {
            lockbox
                .add_file(
                    &p(format!("/mixed/dir-{dir:02}/tiny-{file:03}.txt")),
                    &tiny,
                    false,
                )
                .unwrap();
        }
        for file in 0..4 {
            lockbox
                .add_file(
                    &p(format!("/mixed/dir-{dir:02}/medium-{file:03}.bin")),
                    &medium,
                    false,
                )
                .unwrap();
        }
    }
}

fn temp_output_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "lockbox-criterion-{}-{}",
        std::process::id(),
        next_id()
    ))
}

fn next_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

struct PatternReader {
    remaining: usize,
    offset: usize,
    pattern: Pattern,
}

enum Pattern {
    Randomish,
}

impl PatternReader {
    fn new(remaining: usize, pattern: Pattern) -> Self {
        Self {
            remaining,
            offset: 0,
            pattern,
        }
    }
}

impl Read for PatternReader {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let len = self.remaining.min(buf.len());
        match self.pattern {
            Pattern::Randomish => fill_randomish(&mut buf[..len], self.offset),
        }
        self.offset += len;
        self.remaining -= len;
        Ok(len)
    }
}

fn fill_randomish(buf: &mut [u8], offset: usize) {
    for (i, byte) in buf.iter_mut().enumerate() {
        let mut value = (offset + i) as u64;
        value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        *byte = (value ^ (value >> 31)) as u8;
    }
}

fn secure_payloads(count: usize, len: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|index| {
            let mut payload = secure_payload(len);
            payload[0] = b'a' + (index % 26) as u8;
            payload
        })
        .collect()
}

fn secure_payload(len: usize) -> Vec<u8> {
    (0..len).map(|index| b'a' + (index % 26) as u8).collect()
}

fn secure_strings(count: usize, len: usize) -> Vec<SecretString> {
    secure_payloads(count, len)
        .into_iter()
        .map(|payload| SecretString::try_from_bytes(payload).unwrap())
        .collect()
}

criterion_group!(
    benches,
    bench_small_files,
    bench_mixed_tree,
    bench_large_file,
    bench_append_delete,
    bench_toc_structure,
    bench_metadata_operations,
    bench_secure_string_store
);
criterion_main!(benches);
