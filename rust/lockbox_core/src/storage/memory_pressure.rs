#[cfg(target_os = "linux")]
pub(crate) fn available_memory_bytes() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("MemAvailable:") else {
            continue;
        };
        let kb = rest.split_whitespace().next()?.parse::<u64>().ok()?;
        return kb.checked_mul(1024);
    }
    None
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "macos", target_os = "ios"))
))]
pub(crate) fn available_memory_bytes() -> Option<u64> {
    // SAFETY: `sysconf` reads process-global configuration and does not retain
    // pointers or require additional invariants from Rust.
    let pages = unsafe { libc::sysconf(libc::_SC_AVPHYS_PAGES) };
    // SAFETY: same as above; this is a side-effect-free OS query.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if pages <= 0 || page_size <= 0 {
        return None;
    }
    (pages as u64).checked_mul(page_size as u64)
}

#[cfg(target_os = "ios")]
pub(crate) fn available_memory_bytes() -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
pub(crate) fn available_memory_bytes() -> Option<u64> {
    // SAFETY: `vm_statistics64_data_t` is a plain C data buffer that is
    // immediately initialized by `host_statistics64` before being read.
    let mut stats = unsafe { std::mem::zeroed::<libc::vm_statistics64_data_t>() };
    let mut count = libc::HOST_VM_INFO64_COUNT;
    // SAFETY: `mach_host_self` returns a send right for the current host and
    // does not interact with Rust-managed memory.
    let host = unsafe { mach2::mach_init::mach_host_self() };
    // SAFETY: `stats` points to a valid writable buffer and `count` points to a
    // valid element count as required by `host_statistics64`.
    let result = unsafe {
        libc::host_statistics64(
            host,
            libc::HOST_VM_INFO64,
            (&mut stats as *mut libc::vm_statistics64_data_t).cast(),
            &mut count,
        )
    };
    if result != libc::KERN_SUCCESS {
        return None;
    }
    // SAFETY: `sysconf` is a side-effect-free OS query.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return None;
    }
    macos_reclaimable_bytes(
        u64::from(stats.free_count),
        u64::from(stats.inactive_count),
        u64::from(stats.speculative_count),
        page_size as u64,
    )
}

#[cfg(any(target_os = "macos", test))]
fn macos_reclaimable_bytes(
    free_pages: u64,
    inactive_pages: u64,
    speculative_pages: u64,
    page_size: u64,
) -> Option<u64> {
    free_pages
        .saturating_add(inactive_pages)
        .saturating_add(speculative_pages)
        .checked_mul(page_size)
}

#[cfg(windows)]
pub(crate) fn available_memory_bytes() -> Option<u64> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    let mut status = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        dwMemoryLoad: 0,
        ullTotalPhys: 0,
        ullAvailPhys: 0,
        ullTotalPageFile: 0,
        ullAvailPageFile: 0,
        ullTotalVirtual: 0,
        ullAvailVirtual: 0,
        ullAvailExtendedVirtual: 0,
    };
    // SAFETY: `status` has the documented `dwLength` and points to a valid
    // writable `MEMORYSTATUSEX` for the duration of the call.
    let ok = unsafe { GlobalMemoryStatusEx(&mut status) };
    if ok == 0 {
        None
    } else {
        Some(status.ullAvailPhys)
    }
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn available_memory_bytes() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_reclaimable_bytes_counts_reclaimable_pages() {
        assert_eq!(macos_reclaimable_bytes(10, 20, 30, 4096), Some(245_760));
    }
}
