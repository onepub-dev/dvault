#![no_main]

use libfuzzer_sys::fuzz_target;
use lockbox_core::{Lockbox, LockboxPath, LockboxProtection, SecretVec};
use std::sync::atomic::{AtomicU64, Ordering};

static LOCKBOX_COUNTER: AtomicU64 = AtomicU64::new(0);

fuzz_target!(|data: &[u8]| {
    if let Ok(path) = std::str::from_utf8(data) {
        let Ok(path) = LockboxPath::new(path) else {
            return;
        };
        let index = LOCKBOX_COUNTER.fetch_add(1, Ordering::Relaxed);
        let storage_path = std::env::temp_dir().join(format!(
            "lockbox-path-fuzz-{}-{index}.lbox",
            std::process::id()
        ));
        let mut lockbox = Lockbox::create_file(
            &storage_path,
            LockboxProtection::ContentKey(SecretVec::try_from_slice(b"fuzz key").unwrap()),
        )
        .unwrap();
        let _ = lockbox.add_file(&path, b"x", false);
        let _ = lockbox.add_symlink(&path, &LockboxPath::new("/target").unwrap(), false);
        let _ = lockbox.list(&path);
        let _ = std::fs::remove_file(storage_path);
    }
});
