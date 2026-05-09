use super::{
    decode_hex, encode_forget, encode_forget_all, encode_get, encode_hex, encode_put,
    parse_request, AgentRequest, SecretBytes, DEFAULT_TTL_SECONDS,
};
use lockbox_core::VaultId;
use std::collections::BTreeMap;
use std::env;
use std::ffi::c_void;
use std::io;
use std::process::{Command, Stdio};
use std::ptr::{null, null_mut};
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_FILE_NOT_FOUND, ERROR_NO_TOKEN, ERROR_PIPE_BUSY,
    ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, RevertToSelf, TokenUser, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, ImpersonateNamedPipeClient,
    WaitNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

const IDLE_EXIT_SECONDS: u64 = 10 * 60;
const PIPE_OPEN_TIMEOUT: Duration = Duration::from_secs(3);
const PIPE_BUFFER_BYTES: u32 = 64 * 1024;

struct CacheEntry {
    key: SecretBytes,
    expires_at: Instant,
}

pub(crate) fn serve_agent() -> io::Result<()> {
    let current_user_sid = current_process_user_sid()?;
    let mut cache = BTreeMap::<String, CacheEntry>::new();
    let mut last_activity = Instant::now();

    loop {
        prune_expired(&mut cache);
        if cache.is_empty() && last_activity.elapsed() > Duration::from_secs(IDLE_EXIT_SECONDS) {
            return Ok(());
        }

        let pipe = create_pipe()?;
        let connected = connect_pipe(pipe);
        if let Err(err) = connected {
            unsafe {
                CloseHandle(pipe);
            }
            return Err(err);
        }

        last_activity = Instant::now();
        let _ = handle_client(pipe, &current_user_sid, &mut cache);
        unsafe {
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
        }
    }
}

pub(crate) fn get(vault_id: VaultId) -> io::Result<Option<Vec<u8>>> {
    let response = request(&encode_get(vault_id))?;
    if response == "MISS" {
        return Ok(None);
    }
    let Some(hex) = response.strip_prefix("KEY ") else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid agent response",
        ));
    };
    decode_hex(hex).map(Some)
}

pub(crate) fn put(vault_id: VaultId, key: &[u8]) -> io::Result<()> {
    let response = request(&encode_put(vault_id, key))?;
    expect_ok(&response)
}

pub(crate) fn forget(vault_id: VaultId) -> io::Result<()> {
    let response = request(&encode_forget(vault_id))?;
    expect_ok(&response)
}

pub(crate) fn forget_all() -> io::Result<()> {
    let response = request(encode_forget_all())?;
    expect_ok(&response)
}

fn request(message: &str) -> io::Result<String> {
    ensure_agent()?;
    let pipe_name = wide_pipe_name();
    let handle = open_pipe(&pipe_name)?;
    write_all(handle, message.as_bytes())?;
    let response = read_to_string(handle)?;
    unsafe {
        CloseHandle(handle);
    }
    Ok(response.trim_end_matches(['\r', '\n']).to_string())
}

fn ensure_agent() -> io::Result<()> {
    let pipe_name = wide_pipe_name();
    if open_pipe(&pipe_name)
        .map(|handle| unsafe { CloseHandle(handle) })
        .is_ok()
    {
        return Ok(());
    }

    let exe = env::current_exe()?;
    Command::new(exe)
        .arg("__agent")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if open_pipe(&pipe_name)
            .map(|handle| unsafe { CloseHandle(handle) })
            .is_ok()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "lockbox agent did not start",
    ))
}

fn create_pipe() -> io::Result<HANDLE> {
    let name = wide_pipe_name();
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            0,
            null(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(handle)
    }
}

fn connect_pipe(pipe: HANDLE) -> io::Result<()> {
    let ok = unsafe { ConnectNamedPipe(pipe, null_mut()) };
    if ok != 0 {
        return Ok(());
    }
    let err = unsafe { GetLastError() };
    if err == ERROR_PIPE_CONNECTED {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(err as i32))
    }
}

fn open_pipe(pipe_name: &[u16]) -> io::Result<HANDLE> {
    let deadline = Instant::now() + PIPE_OPEN_TIMEOUT;
    loop {
        let handle = unsafe {
            CreateFileW(
                pipe_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            return Ok(handle);
        }
        let err = unsafe { GetLastError() };
        if err == ERROR_FILE_NOT_FOUND {
            if Instant::now() >= deadline {
                return Err(io::Error::from_raw_os_error(err as i32));
            }
            thread::sleep(Duration::from_millis(25));
            continue;
        }
        if err != ERROR_PIPE_BUSY {
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        let waited = unsafe { WaitNamedPipeW(pipe_name.as_ptr(), 3000) };
        if waited == 0 {
            return Err(io::Error::last_os_error());
        }
    }
}

fn handle_client(
    pipe: HANDLE,
    current_user_sid: &[u8],
    cache: &mut BTreeMap<String, CacheEntry>,
) -> io::Result<()> {
    let request = read_to_string(pipe)?;
    if request.trim().is_empty() || !client_matches_current_user(pipe, current_user_sid)? {
        return Ok(());
    }
    let response = match parse_request(&request) {
        Ok(AgentRequest::Get(vault_id)) => {
            let now = Instant::now();
            match cache.get_mut(&vault_id) {
                Some(entry) if entry.expires_at > now => {
                    entry.expires_at = now + Duration::from_secs(DEFAULT_TTL_SECONDS);
                    format!("KEY {}", encode_hex(entry.key.expose()))
                }
                _ => "MISS".to_string(),
            }
        }
        Ok(AgentRequest::Put(vault_id, key)) => {
            let key = SecretBytes::new(key);
            cache.insert(
                vault_id,
                CacheEntry {
                    key,
                    expires_at: Instant::now() + Duration::from_secs(DEFAULT_TTL_SECONDS),
                },
            );
            "OK".to_string()
        }
        Ok(AgentRequest::Forget(vault_id)) => {
            cache.remove(&vault_id);
            "OK".to_string()
        }
        Ok(AgentRequest::ForgetAll) => {
            cache.clear();
            "OK".to_string()
        }
        Err(_) => "ERR invalid request".to_string(),
    };
    write_all(pipe, format!("{response}\n").as_bytes())
}

fn client_matches_current_user(pipe: HANDLE, current_user_sid: &[u8]) -> io::Result<bool> {
    let impersonated = unsafe { ImpersonateNamedPipeClient(pipe) };
    if impersonated == 0 {
        return Err(io::Error::last_os_error());
    }

    let result = (|| {
        let mut token: HANDLE = null_mut();
        let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &mut token) };
        if opened == 0 {
            let err = unsafe { GetLastError() };
            if err == ERROR_NO_TOKEN {
                return Ok(false);
            }
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        let client_sid = token_user_sid(token);
        unsafe {
            CloseHandle(token);
        }
        let client_sid = client_sid?;
        Ok(equal_sid(&client_sid, current_user_sid))
    })();

    unsafe {
        RevertToSelf();
    }
    result
}

fn current_process_user_sid() -> io::Result<Vec<u8>> {
    let mut token: HANDLE = null_mut();
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid = token_user_sid(token);
    unsafe {
        CloseHandle(token);
    }
    sid
}

fn token_user_sid(token: HANDLE) -> io::Result<Vec<u8>> {
    let mut needed = 0u32;
    unsafe {
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = vec![0u8; needed as usize];
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr() as *mut c_void,
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let token_user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
    let sid = token_user.User.Sid;
    let sid_len = unsafe { sid_length(sid) }?;
    let mut out = vec![0u8; sid_len];
    unsafe {
        std::ptr::copy_nonoverlapping(sid as *const u8, out.as_mut_ptr(), sid_len);
    }
    Ok(out)
}

unsafe fn sid_length(sid: *mut c_void) -> io::Result<usize> {
    if sid.is_null() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "null SID"));
    }
    let revision_ptr = sid as *const u8;
    let sub_authority_count = *revision_ptr.add(1) as usize;
    Ok(8 + sub_authority_count * 4)
}

fn equal_sid(left: &[u8], right: &[u8]) -> bool {
    unsafe { EqualSid(left.as_ptr() as *mut c_void, right.as_ptr() as *mut c_void) != 0 }
}

fn write_all(handle: HANDLE, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let mut written = 0u32;
        let chunk_len = bytes.len().min(PIPE_BUFFER_BYTES as usize) as u32;
        let ok = unsafe { WriteFile(handle, bytes.as_ptr(), chunk_len, &mut written, null_mut()) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

fn read_to_string(handle: HANDLE) -> io::Result<String> {
    let mut out = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let mut read = 0u32;
        let ok = unsafe {
            ReadFile(
                handle,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &mut read,
                null_mut(),
            )
        };
        if ok == 0 {
            let err = io::Error::last_os_error();
            if !out.is_empty() {
                break;
            }
            return Err(err);
        }
        if read == 0 {
            break;
        }
        out.extend_from_slice(&buffer[..read as usize]);
        if out.ends_with(b"\n") {
            break;
        }
    }
    String::from_utf8(out).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "utf8"))
}

fn prune_expired(cache: &mut BTreeMap<String, CacheEntry>) {
    let now = Instant::now();
    cache.retain(|_, entry| entry.expires_at > now);
}

fn expect_ok(response: &str) -> io::Result<()> {
    if response == "OK" {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("agent rejected request: {response}"),
        ))
    }
}

fn wide_pipe_name() -> Vec<u16> {
    to_wide(&format!(
        r"\\.\pipe\lockbox-agent-{}",
        sanitize_name(&current_user())
    ))
}

fn current_user() -> String {
    env::var("USERNAME")
        .or_else(|_| env::var("USER"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
