use super::{
    decode_hex, encode_forget, encode_forget_all, encode_get, encode_hex, encode_put,
    parse_request, AgentRequest, SecretBytes, DEFAULT_TTL_SECONDS,
};
use lockbox_core::VaultId;
use std::collections::BTreeMap;
use std::env;
use std::ffi::c_void;
use std::fs::OpenOptions;
use std::io::{self, Write};
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
    trace("agent serve start");
    let mut cache = BTreeMap::<String, CacheEntry>::new();
    let mut last_activity = Instant::now();

    loop {
        prune_expired(&mut cache);
        if cache.is_empty() && last_activity.elapsed() > Duration::from_secs(IDLE_EXIT_SECONDS) {
            trace("agent idle exit");
            return Ok(());
        }

        trace("agent creating pipe");
        let pipe = create_pipe()?;
        trace("agent connecting pipe");
        let connected = connect_pipe(pipe);
        if let Err(err) = connected {
            trace(format!("agent connect failed: {err}"));
            unsafe {
                CloseHandle(pipe);
            }
            return Err(err);
        }

        trace("agent client connected");
        last_activity = Instant::now();
        match handle_client(pipe, &current_user_sid, &mut cache) {
            Ok(()) => trace("agent handled client"),
            Err(err) => trace(format!("agent handle client failed: {err}")),
        }
        unsafe {
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
        }
        trace("agent disconnected client");
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
    trace(format!("client request start op={}", request_op(message)));
    let pipe_name = wide_pipe_name();
    let handle = match open_pipe(&pipe_name) {
        Ok(handle) => {
            trace("client opened existing pipe");
            handle
        }
        Err(err) => {
            trace(format!("client open pipe failed before start: {err}"));
            start_agent()?;
            trace("client started agent");
            open_pipe(&pipe_name)?
        }
    };
    trace("client writing request");
    write_all(handle, message.as_bytes())?;
    trace("client reading response");
    let response = read_to_string(handle)?;
    unsafe {
        CloseHandle(handle);
    }
    trace(format!(
        "client request done op={} response={}",
        request_op(message),
        response_op(&response)
    ));
    Ok(response.trim_end_matches(['\r', '\n']).to_string())
}

fn start_agent() -> io::Result<()> {
    let exe = env::current_exe()?;
    trace(format!("client spawning agent {}", exe.display()));
    let child = Command::new(exe)
        .arg("__agent")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    trace(format!("client spawned agent pid={}", child.id()));

    Ok(())
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
        let err = io::Error::last_os_error();
        trace(format!("agent create pipe failed: {err}"));
        Err(err)
    } else {
        trace("agent created pipe");
        Ok(handle)
    }
}

fn connect_pipe(pipe: HANDLE) -> io::Result<()> {
    let ok = unsafe { ConnectNamedPipe(pipe, null_mut()) };
    if ok != 0 {
        trace("agent connect pipe ok");
        return Ok(());
    }
    let err = unsafe { GetLastError() };
    if err == ERROR_PIPE_CONNECTED {
        trace("agent pipe already connected");
        Ok(())
    } else {
        trace(format!("agent connect pipe error={err}"));
        Err(io::Error::from_raw_os_error(err as i32))
    }
}

fn open_pipe(pipe_name: &[u16]) -> io::Result<HANDLE> {
    trace("client opening pipe");
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
            trace("client open pipe ok");
            return Ok(handle);
        }
        let err = unsafe { GetLastError() };
        if err == ERROR_FILE_NOT_FOUND {
            if Instant::now() >= deadline {
                trace("client open pipe timed out waiting for pipe");
                return Err(io::Error::from_raw_os_error(err as i32));
            }
            trace("client open pipe not found; retrying");
            thread::sleep(Duration::from_millis(25));
            continue;
        }
        if err != ERROR_PIPE_BUSY {
            trace(format!("client open pipe error={err}"));
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        trace("client open pipe busy; waiting");
        let waited = unsafe { WaitNamedPipeW(pipe_name.as_ptr(), 3000) };
        if waited == 0 {
            let err = io::Error::last_os_error();
            trace(format!("client wait pipe failed: {err}"));
            return Err(err);
        }
    }
}

fn handle_client(
    pipe: HANDLE,
    current_user_sid: &[u8],
    cache: &mut BTreeMap<String, CacheEntry>,
) -> io::Result<()> {
    trace("agent reading request");
    let request = read_to_string(pipe)?;
    trace(format!("agent read request op={}", request_op(&request)));
    if request.trim().is_empty() {
        trace("agent empty request");
        return Ok(());
    }
    if !client_matches_current_user(pipe, current_user_sid)? {
        trace("agent rejected client sid");
        return Ok(());
    }
    trace("agent accepted client sid");
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
    trace(format!("agent writing response {}", response_op(&response)));
    write_all(pipe, format!("{response}\n").as_bytes())
}

fn client_matches_current_user(pipe: HANDLE, current_user_sid: &[u8]) -> io::Result<bool> {
    trace("agent impersonating client");
    let impersonated = unsafe { ImpersonateNamedPipeClient(pipe) };
    if impersonated == 0 {
        let err = io::Error::last_os_error();
        trace(format!("agent impersonation failed: {err}"));
        return Err(err);
    }

    let result = (|| {
        let mut token: HANDLE = null_mut();
        let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &mut token) };
        if opened == 0 {
            let err = unsafe { GetLastError() };
            if err == ERROR_NO_TOKEN {
                trace("agent open thread token found no token");
                return Ok(false);
            }
            trace(format!("agent open thread token error={err}"));
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        let client_sid = token_user_sid(token);
        unsafe {
            CloseHandle(token);
        }
        let client_sid = client_sid?;
        let matches = equal_sid(&client_sid, current_user_sid);
        trace(format!("agent sid match={matches}"));
        Ok(matches)
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
    trace(format!("write_all start bytes={}", bytes.len()));
    while !bytes.is_empty() {
        let mut written = 0u32;
        let chunk_len = bytes.len().min(PIPE_BUFFER_BYTES as usize) as u32;
        let ok = unsafe { WriteFile(handle, bytes.as_ptr(), chunk_len, &mut written, null_mut()) };
        if ok == 0 {
            let err = io::Error::last_os_error();
            trace(format!("write_all failed: {err}"));
            return Err(err);
        }
        trace(format!("write_all wrote {written} bytes"));
        bytes = &bytes[written as usize..];
    }
    trace("write_all done");
    Ok(())
}

fn read_to_string(handle: HANDLE) -> io::Result<String> {
    trace("read_to_string start");
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
                trace(format!("read_to_string ended after partial read: {err}"));
                break;
            }
            trace(format!("read_to_string failed: {err}"));
            return Err(err);
        }
        if read == 0 {
            trace("read_to_string read zero bytes");
            break;
        }
        trace(format!("read_to_string read {read} bytes"));
        out.extend_from_slice(&buffer[..read as usize]);
        if out.ends_with(b"\n") {
            trace("read_to_string saw newline");
            break;
        }
    }
    let result =
        String::from_utf8(out).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "utf8"));
    if let Ok(text) = &result {
        trace(format!("read_to_string done bytes={}", text.len()));
    }
    result
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

fn request_op(message: &str) -> &str {
    message.split_whitespace().nth(1).unwrap_or("<unknown>")
}

fn response_op(response: &str) -> &str {
    response.split_whitespace().next().unwrap_or("<empty>")
}

fn trace(message: impl AsRef<str>) {
    let Ok(path) = env::var("LOCKBOX_AGENT_TRACE") else {
        return;
    };
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    let _ = writeln!(file, "pid={} {}", std::process::id(), message.as_ref());
}
