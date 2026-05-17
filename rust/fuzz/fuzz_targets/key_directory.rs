#![no_main]

use libfuzzer_sys::fuzz_target;
use lockbox_core::{Lockbox, SecretString};
use std::sync::atomic::{AtomicU64, Ordering};

static LOCKBOX_COUNTER: AtomicU64 = AtomicU64::new(0);

fuzz_target!(|data: &[u8]| {
    let password = SecretString::try_from_bytes(b"password".to_vec()).unwrap();
    let index = LOCKBOX_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "lockbox-key-directory-fuzz-{}-{index}.lbox",
        std::process::id()
    ));
    if std::fs::write(&path, data).is_ok() {
        let _ = Lockbox::unlock_path_with_password(&path, &password);
        let _ = std::fs::remove_file(path);
    }
});
