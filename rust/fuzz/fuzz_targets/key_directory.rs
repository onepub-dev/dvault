#![no_main]

use libfuzzer_sys::fuzz_target;
use lockbox_core::{Lockbox, SecretString};

fuzz_target!(|data: &[u8]| {
    let password = SecretString::try_from_bytes(b"password".to_vec()).unwrap();
    let _ = Lockbox::open_with_password(data.to_vec(), &password);
});
