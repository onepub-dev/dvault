use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use lockbox_core::{ExtractPolicy, ListOptions, Lockbox};
use std::fs;
use std::io::{Read, Result as IoResult};
use std::path::PathBuf;

const KEY: &[u8] = b"criterion performance key";

fn bench_small_files(c: &mut Criterion) {
    let mut group = c.benchmark_group("small_files");
    group.sample_size(10);

    group.bench_function("add_commit_1000x1k", |b| {
        b.iter_batched(
            || vec![b'x'; 1024],
            |payload| {
                let mut lockbox = Lockbox::create(KEY);
                for i in 0..1000 {
                    lockbox
                        .put_file(&format!("/tree/file-{i:06}.bin"), &payload)
                        .unwrap();
                }
                lockbox.commit().unwrap();
                black_box(lockbox.to_bytes().len());
            },
            BatchSize::SmallInput,
        );
    });

    let lockbox = prepared_small_lockbox(1000, 1024);
    let policy = ExtractPolicy {
        max_files: 1001,
        ..ExtractPolicy::default()
    };
    group.bench_function("extract_memory_1000x1k", |b| {
        b.iter(|| {
            let files = lockbox.extract_all(&policy).unwrap();
            black_box(files.len());
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
            let mut lockbox = Lockbox::create(KEY);
            add_mixed_tree(&mut lockbox);
            lockbox.commit().unwrap();
            black_box(lockbox.to_bytes().len());
        });
    });

    let mut lockbox = Lockbox::create(KEY);
    add_mixed_tree(&mut lockbox);
    lockbox.commit().unwrap();

    group.bench_function("list_recursive_mixed", |b| {
        b.iter(|| {
            let count = lockbox
                .list_iter(ListOptions {
                    recursive: true,
                    ..ListOptions::new("/")
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
            let mut lockbox = Lockbox::create(KEY);
            lockbox
                .put_file_from_reader(
                    "/large/blob.bin",
                    PatternReader::new(16 * 1024 * 1024, Pattern::Randomish),
                )
                .unwrap();
            lockbox.commit().unwrap();
            black_box(lockbox.to_bytes().len());
        });
    });

    let mut lockbox = Lockbox::create(KEY);
    lockbox
        .put_file_from_reader(
            "/large/blob.bin",
            PatternReader::new(16 * 1024 * 1024, Pattern::Randomish),
        )
        .unwrap();
    lockbox.commit().unwrap();

    group.bench_function("range_read_1m_middle", |b| {
        b.iter(|| {
            let data = lockbox
                .read_file_range("/large/blob.bin", 8 * 1024 * 1024, 1024 * 1024)
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
                let mut lockbox = Lockbox::create(KEY);
                for i in 0..1000 {
                    lockbox
                        .put_file(&format!("/set/file-{i:06}.bin"), &payload)
                        .unwrap();
                }
                lockbox.commit().unwrap();
                lockbox
            },
            |mut lockbox| {
                let payload = vec![b'b'; 2048];
                for i in 1000..1200 {
                    lockbox
                        .put_file(&format!("/set/file-{i:06}.bin"), &payload)
                        .unwrap();
                }
                for i in 0..200 {
                    lockbox.delete(&format!("/set/file-{i:06}.bin")).unwrap();
                    lockbox
                        .put_file(&format!("/set/replacement-{i:06}.bin"), &payload)
                        .unwrap();
                }
                lockbox.commit().unwrap();
                black_box(lockbox.to_bytes().len());
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
                    .put_file("/tree/file-000000.bin", black_box(b"changed"))
                    .unwrap();
                lockbox.commit().unwrap();
                black_box(lockbox.to_bytes().len());
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
                        .put_file(&format!("/tree/file-{i:06}.bin"), b"new")
                        .unwrap();
                }
                lockbox.commit().unwrap();
                black_box(lockbox.to_bytes().len());
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("leaf_merge_delete_5000", |b| {
        b.iter_batched(
            || prepared_small_lockbox(5000, 256),
            |mut lockbox| {
                for i in 0..500 {
                    lockbox.delete(&format!("/tree/file-{i:06}.bin")).unwrap();
                }
                lockbox.commit().unwrap();
                black_box(lockbox.to_bytes().len());
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn prepared_small_lockbox(files: usize, file_size: usize) -> Lockbox {
    let payload = vec![b'x'; file_size];
    let mut lockbox = Lockbox::create(KEY);
    for i in 0..files {
        lockbox
            .put_file(&format!("/tree/file-{i:06}.bin"), &payload)
            .unwrap();
    }
    lockbox.commit().unwrap();
    lockbox
}

fn add_mixed_tree(lockbox: &mut Lockbox) {
    let tiny = vec![b't'; 512];
    let medium = vec![b'm'; 128 * 1024];
    for dir in 0..8 {
        for file in 0..25 {
            lockbox
                .put_file(&format!("/mixed/dir-{dir:02}/tiny-{file:03}.txt"), &tiny)
                .unwrap();
        }
        for file in 0..4 {
            lockbox
                .put_file(
                    &format!("/mixed/dir-{dir:02}/medium-{file:03}.bin"),
                    &medium,
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

criterion_group!(
    benches,
    bench_small_files,
    bench_mixed_tree,
    bench_large_file,
    bench_append_delete,
    bench_toc_structure
);
criterion_main!(benches);
