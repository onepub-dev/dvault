#![no_main]

use libfuzzer_sys::fuzz_target;
use lockbox_core::Lockbox;
use std::sync::atomic::{AtomicU64, Ordering};

static LOCKBOX_COUNTER: AtomicU64 = AtomicU64::new(0);

fuzz_target!(|data: &[u8]| {
    let index = LOCKBOX_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "lockbox-header-fuzz-{}-{index}.lbox",
        std::process::id()
    ));
    if std::fs::write(&path, data).is_ok() {
        let _ = Lockbox::read_lockbox_id_path(&path);
        let _ = std::fs::remove_file(path);
    }
});
