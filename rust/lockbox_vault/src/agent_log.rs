use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn agent_log_path() -> PathBuf {
    if let Ok(path) = env::var("LOCKBOX_SESSION_AGENT_LOG") {
        return PathBuf::from(path);
    }
    fallback_log_path()
}

pub fn agent_log_destination() -> String {
    if let Ok(path) = env::var("LOCKBOX_SESSION_AGENT_LOG") {
        return format!("{}", PathBuf::from(path).display());
    }
    platform_log_destination().to_string()
}

pub(crate) fn log_agent_event(message: impl AsRef<str>) {
    let message = message.as_ref();
    if let Ok(path) = env::var("LOCKBOX_SESSION_AGENT_LOG") {
        write_file_log(PathBuf::from(path), message);
        return;
    }
    if write_platform_log(message).is_ok() {
        return;
    }
    write_file_log(fallback_log_path(), message);
}

fn write_file_log(path: PathBuf, message: &str) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) else {
        return;
    };
    let _ = writeln!(file, "{}\t{}", unix_time_millis(), message);
}

fn unix_time_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

fn fallback_log_path() -> PathBuf {
    platform_log_dir().join("agent.log")
}

#[cfg(windows)]
fn platform_log_destination() -> &'static str {
    "Windows Event Log source reVault Agent"
}

#[cfg(target_os = "macos")]
fn platform_log_destination() -> &'static str {
    "macOS system log source lockbox-agent"
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_log_destination() -> &'static str {
    "system log source lockbox-agent"
}

#[cfg(not(any(unix, windows)))]
fn platform_log_destination() -> &'static str {
    "agent.log"
}

#[cfg(unix)]
fn write_platform_log(message: &str) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::sync::Once;

    static INIT: Once = Once::new();
    static IDENT: &[u8] = b"lockbox-agent\0";
    static FORMAT: &[u8] = b"%s\0";

    let message = CString::new(message.replace('\0', "\\0")).map_err(std::io::Error::other)?;
    INIT.call_once(|| {
        // SAFETY: `IDENT` is a static null-terminated C string retained for the
        // process lifetime, which is required because `openlog` stores it.
        unsafe {
            libc::openlog(
                IDENT.as_ptr().cast(),
                libc::LOG_PID | libc::LOG_NDELAY,
                libc::LOG_USER,
            );
        }
    });
    // SAFETY: `FORMAT` and `message` are valid null-terminated C strings. The
    // format string is constant and only contains one `%s` argument.
    unsafe {
        libc::syslog(libc::LOG_INFO, FORMAT.as_ptr().cast(), message.as_ptr());
    }
    Ok(())
}

#[cfg(windows)]
fn write_platform_log(message: &str) -> std::io::Result<()> {
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::System::EventLog::{
        DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_INFORMATION_TYPE,
    };

    let source = to_wide("reVault Agent");
    // SAFETY: `source` is a null-terminated UTF-16 string and the local
    // computer argument is intentionally null.
    let handle = unsafe { RegisterEventSourceW(null(), source.as_ptr()) };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let message = to_wide(message);
    let strings = [message.as_ptr()];
    // SAFETY: `handle` is valid on success from `RegisterEventSourceW`;
    // `strings` points to one null-terminated UTF-16 message for the duration
    // of the call, and no raw data or SID is supplied.
    let reported = unsafe {
        ReportEventW(
            handle,
            EVENTLOG_INFORMATION_TYPE,
            0,
            0,
            null_mut(),
            1,
            0,
            strings.as_ptr(),
            null::<c_void>(),
        )
    };
    // SAFETY: The event source handle is closed exactly once after the report
    // attempt.
    unsafe {
        DeregisterEventSource(handle);
    }
    if reported == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
fn write_platform_log(_message: &str) -> std::io::Result<()> {
    Err(std::io::Error::other("platform logging is unsupported"))
}

#[cfg(windows)]
fn platform_log_dir() -> PathBuf {
    env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|_| env::var("APPDATA").map(PathBuf::from))
        .unwrap_or_else(|_| env::temp_dir())
        .join("reVault")
        .join("Logs")
}

#[cfg(target_os = "macos")]
fn platform_log_dir() -> PathBuf {
    home_dir()
        .unwrap_or_else(env::temp_dir)
        .join("Library")
        .join("Logs")
        .join("reVault")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_log_dir() -> PathBuf {
    env::var("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            home_dir()
                .map(|home| home.join(".local").join("state"))
                .unwrap_or_else(env::temp_dir)
        })
        .join("lockbox")
}

#[cfg(not(any(unix, windows)))]
fn platform_log_dir() -> PathBuf {
    env::temp_dir().join("lockbox")
}

#[cfg(unix)]
fn home_dir() -> Option<PathBuf> {
    env::var("HOME").ok().map(PathBuf::from)
}

#[cfg(windows)]
fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
