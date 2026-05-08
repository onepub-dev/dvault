#![no_main]

use libfuzzer_sys::fuzz_target;
use lockbox_core::Lockbox;

fuzz_target!(|data: &[u8]| {
    let _ = Lockbox::recover(data.to_vec(), b"fuzz key");
    let _ = Lockbox::salvage(data.to_vec(), b"fuzz key");
});
