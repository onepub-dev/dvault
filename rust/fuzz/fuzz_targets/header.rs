#![no_main]

use libfuzzer_sys::fuzz_target;
use lockbox_core::Lockbox;

fuzz_target!(|data: &[u8]| {
    let _ = Lockbox::read_lockbox_id(data);
});
