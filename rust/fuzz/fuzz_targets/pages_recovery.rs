#![no_main]

use libfuzzer_sys::fuzz_target;
use lockbox_core::RecoveryScanner;

fuzz_target!(|data: &[u8]| {
    let _ = RecoveryScanner::scan_bytes(data.to_vec(), b"fuzz key");
    let _ = RecoveryScanner::salvage_bytes(data.to_vec(), b"fuzz key");
});
