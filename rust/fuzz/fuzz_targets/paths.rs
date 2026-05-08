#![no_main]

use libfuzzer_sys::fuzz_target;
use lockbox_core::Lockbox;

fuzz_target!(|data: &[u8]| {
    if let Ok(path) = std::str::from_utf8(data) {
        let mut lockbox = Lockbox::create(b"fuzz key");
        let _ = lockbox.put_file(path, b"x");
        let _ = lockbox.put_symlink(path, "/target");
        let _ = lockbox.list(path);
    }
});
