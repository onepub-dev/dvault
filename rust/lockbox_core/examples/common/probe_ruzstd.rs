use ruzstd::encoding::CompressionLevel;

pub(crate) fn ruzstd_level(level: i32) -> CompressionLevel {
    // TODO: replace this lossy mapping if ruzstd exposes finer-grained numeric
    // levels. Today several zstd CLI level labels collapse to the same backend
    // mode, so probe output should be read as profile buckets.
    match level {
        i32::MIN..=0 => CompressionLevel::Uncompressed,
        1 => CompressionLevel::Fastest,
        2..=3 => CompressionLevel::Default,
        4..=6 => CompressionLevel::Better,
        _ => CompressionLevel::Best,
    }
}
