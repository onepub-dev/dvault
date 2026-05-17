#[cfg(not(target_arch = "wasm32"))]
use std::{
    env,
    process::{Command, Stdio},
};

use crate::{
    allocation_chunk_bytes, read_access, secure_memory_capabilities,
    set_weakened_allocation_allowed, weakened_allocation_allowed, AllocationSecurity, Error,
    SecureString, SecureVec,
};

#[cfg(any(unix, windows))]
use crate::memory_region::{page_size, MemoryRegion};

#[test]
fn secure_string_round_trips_utf8() {
    let mut secret = SecureString::new();
    secret.try_push_byte(b'a').unwrap();
    secret.try_push_utf8_char('b').unwrap();
    secret.try_push_utf8_char('c').unwrap();

    assert_eq!(secret.with_str(|text| text.to_owned()).unwrap(), "abc");
    secret
        .with_bytes(|bytes| assert_eq!(bytes, b"abc"))
        .unwrap();
    assert!(format!("{secret:?}").contains("redacted"));
}

#[test]
fn nested_access_reuses_one_guard() {
    let first = SecureString::try_from_bytes(b"alpha".to_vec()).unwrap();
    let second = SecureString::try_from_bytes(b"bravo".to_vec()).unwrap();

    let combined = read_access(|access| {
        access.with_str(&first, |left| {
            read_access(|nested| {
                nested
                    .with_str(&second, |right| format!("{left}:{right}"))
                    .unwrap()
            })
        })
    })
    .unwrap();

    assert_eq!(combined, "alpha:bravo");
}

#[test]
fn mutation_fails_while_read_access_is_active() {
    let secret = SecureString::try_from_bytes(b"alpha".to_vec()).unwrap();
    let mut other = SecureString::new();

    let err = read_access(|access| {
        access
            .with_str(&secret, |_| other.try_push_byte(b'!'))
            .unwrap()
    })
    .unwrap_err();

    assert_eq!(err, Error::ReadAccessActive);
}

#[test]
fn drop_during_read_access_is_deferred() {
    let secret = SecureString::try_from_bytes(b"alpha".to_vec()).unwrap();
    let mut temporary = Some(SecureString::try_from_bytes(b"temporary".to_vec()).unwrap());

    read_access(|access| {
        access
            .with_str(&secret, |_| {
                drop(temporary.take().unwrap());
            })
            .unwrap();
    });

    let replacement = SecureString::try_from_bytes(b"replacement".to_vec()).unwrap();
    assert_eq!(replacement.with_str(str::to_owned).unwrap(), "replacement");
}

#[test]
fn secure_vec_grow_and_zeroize() {
    let mut bytes = SecureVec::new();
    for index in 0..200 {
        bytes.try_push(index as u8).unwrap();
    }

    assert_eq!(bytes.len(), 200);
    assert_eq!(bytes.capacity_for_test(), 256);
    assert_eq!(bytes.try_pop().unwrap(), Some(199));
    bytes.zeroize().unwrap();
    assert!(bytes.is_empty());
    bytes.with_bytes(|bytes| assert!(bytes.is_empty())).unwrap();
}

#[test]
fn secure_vec_uses_smallest_secure_size_class() {
    assert_eq!(SecureVec::new().capacity_for_test(), 0);
    assert_secure_vec_capacity(1, 64);
    assert_secure_vec_capacity(64, 64);
    assert_secure_vec_capacity(65, 128);
    assert_secure_vec_capacity(128, 128);
    assert_secure_vec_capacity(129, 256);
    assert_secure_vec_capacity(255, 256);
    assert_secure_vec_capacity(257, 512);
    assert_secure_vec_capacity(4096, 4096);
    assert_secure_vec_capacity(4097, page_size() * 2);
}

fn assert_secure_vec_capacity(len: usize, expected_capacity: usize) {
    let bytes = SecureVec::try_from_slice(&vec![0xa5; len]).unwrap();
    assert_eq!(bytes.len(), len);
    assert_eq!(bytes.capacity_for_test(), expected_capacity);
}

#[test]
fn secure_vec_support_values_at_default_chunk_boundary() {
    assert_secure_vec_round_trip_with_len(allocation_chunk_bytes());
}

#[test]
fn secure_vec_support_values_larger_than_default_chunk() {
    assert_secure_vec_round_trip_with_len(allocation_chunk_bytes() + 8192);
}

fn assert_secure_vec_round_trip_with_len(len: usize) {
    let payload = (0..len)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();

    let mut bytes = SecureVec::try_from_vec(payload.clone()).unwrap();
    assert_eq!(bytes.len(), len);
    bytes
        .with_bytes(|stored| {
            assert_eq!(stored.len(), len);
            assert_eq!(&stored[..64], &payload[..64]);
            assert_eq!(&stored[len - 64..], &payload[len - 64..]);
        })
        .unwrap();

    let cloned = bytes.try_clone().unwrap();
    cloned
        .with_bytes(|stored| assert_eq!(stored, payload.as_slice()))
        .unwrap();

    {
        read_access(|access| {
            access
                .with_bytes(&bytes, |stored| assert_eq!(stored[4096], payload[4096]))
                .unwrap();
        });
    }

    bytes.zeroize().unwrap();
    assert!(bytes.is_empty());
    bytes
        .with_bytes(|stored| assert!(stored.is_empty()))
        .unwrap();
}

#[test]
fn allocation_chunk_defaults_to_64k() {
    assert_eq!(allocation_chunk_bytes(), 64 * 1024);
}

#[test]
fn weakened_allocation_is_explicit_opt_in() {
    let original = weakened_allocation_allowed();
    set_weakened_allocation_allowed(true);
    assert!(weakened_allocation_allowed());
    set_weakened_allocation_allowed(original);

    let capabilities = secure_memory_capabilities();
    assert_eq!(capabilities.memory_locked, cfg!(any(unix, windows)));
}

#[test]
fn capabilities_match_target_family() {
    let capabilities = secure_memory_capabilities();

    if cfg!(any(unix, windows)) {
        assert_eq!(capabilities.security, AllocationSecurity::Hardened);
        assert!(capabilities.memory_locked);
        assert!(capabilities.page_protected);
        assert!(capabilities.guard_pages);
    } else {
        assert_eq!(capabilities.security, AllocationSecurity::Weakened);
        assert!(!capabilities.memory_locked);
        assert!(!capabilities.page_protected);
        assert!(!capabilities.guard_pages);
    }

    assert_eq!(capabilities.dump_excluded, cfg!(target_os = "linux"));
    assert_eq!(capabilities.fork_excluded, cfg!(target_os = "linux"));
}

#[test]
#[cfg(not(any(unix, windows)))]
fn weakened_targets_require_explicit_opt_in() {
    let original = weakened_allocation_allowed();
    set_weakened_allocation_allowed(false);
    assert_eq!(
        SecureString::try_from_bytes(b"secret".to_vec()).unwrap_err(),
        Error::WeakAllocationDisabled
    );

    set_weakened_allocation_allowed(true);
    let secret = SecureString::try_from_bytes(b"secret".to_vec()).unwrap();
    assert_eq!(secret.with_str(str::to_owned).unwrap(), "secret");
    set_weakened_allocation_allowed(original);
}

#[test]
fn canary_corruption_is_detected() {
    let mut bytes = SecureVec::try_from_vec(b"canary-check".to_vec()).unwrap();

    assert!(bytes.canaries_intact_for_test());
    bytes.corrupt_after_canary_for_test();
    assert!(!bytes.canaries_intact_for_test());

    bytes.restore_canaries_for_test();
    assert!(bytes.canaries_intact_for_test());
    bytes.zeroize().unwrap();
    assert!(bytes.is_empty());
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn canary_corruption_fails_scoped_read() {
    assert_child_fails(
        "canary-scoped-read",
        "tests::canary_scoped_read_failure_child",
    );
}

#[test]
#[cfg(any(unix, windows))]
fn protected_page_faults_after_access_guard_drops() {
    assert_child_faults("protected-page-read", "tests::protected_page_fault_child");
}

#[test]
#[cfg(any(unix, windows))]
fn guard_pages_fault_on_direct_access() {
    assert_child_faults("guard-before-read", "tests::guard_page_fault_child");
    assert_child_faults("guard-after-read", "tests::guard_page_fault_child");
}

#[test]
#[cfg(any(unix, windows))]
fn protected_page_fault_child() {
    if env::var("LOCKBOX_SECURE_FAULT_TEST").as_deref() != Ok("protected-page-read") {
        return;
    }

    let bytes = SecureVec::try_from_vec(vec![42]).unwrap();
    let ptr = bytes.protected_ptr_for_test();
    // SAFETY: this child-process test deliberately reads a protected page to
    // verify that page protection is active. The parent process asserts that
    // this process terminates unsuccessfully.
    unsafe {
        std::ptr::read_volatile(ptr);
    }
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn canary_scoped_read_failure_child() {
    if env::var("LOCKBOX_SECURE_FAULT_TEST").as_deref() != Ok("canary-scoped-read") {
        return;
    }

    let bytes = SecureVec::try_from_vec(b"corrupt me".to_vec()).unwrap();
    bytes.corrupt_after_canary_for_test();
    bytes.with_bytes(|_| {}).unwrap();
}

#[test]
#[cfg(any(unix, windows))]
fn guard_page_fault_child() {
    let Ok(action) = env::var("LOCKBOX_SECURE_FAULT_TEST") else {
        return;
    };
    if action != "guard-before-read" && action != "guard-after-read" {
        return;
    }

    let region = MemoryRegion::new(page_size()).expect("secure memory region");
    let ptr = if action == "guard-before-read" {
        region.guard_before_ptr_for_test()
    } else {
        region.guard_after_ptr_for_test()
    };
    // SAFETY: this child-process test deliberately reads a guard page to verify
    // that guard pages are inaccessible. The parent process asserts that this
    // process terminates unsuccessfully.
    unsafe {
        std::ptr::read_volatile(ptr);
    }
}

#[cfg(any(unix, windows))]
fn assert_child_faults(action: &str, test_name: &str) {
    assert_child_fails(action, test_name);
}

#[cfg(not(target_arch = "wasm32"))]
fn assert_child_fails(action: &str, test_name: &str) {
    let status = Command::new(env::current_exe().expect("current test binary"))
        .args(["--exact", test_name, "--nocapture"])
        .env("LOCKBOX_SECURE_FAULT_TEST", action)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("fault-test child process");

    assert!(
        !status.success(),
        "expected child process for {action} to fail, got {status:?}"
    );
}
