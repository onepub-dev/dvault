use super::{
    encode_forget, encode_forget_all, encode_get, encode_key_response, encode_list,
    encode_list_response, encode_put, encode_response_line, max_message_bytes, parse_request,
    parse_response, AgentRequest, AgentResponse, SecretVec, DEFAULT_TTL_SECONDS,
};
use lockbox_core::LockboxId;
use std::collections::BTreeMap;
use std::env;
use std::ffi::c_void;
use std::io;
use std::process::{Command, Stdio};
use std::ptr::{null, null_mut};
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_FILE_NOT_FOUND, ERROR_NO_TOKEN, ERROR_PIPE_BUSY,
    ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, RevertToSelf, TokenUser, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
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
    key: SecretVec,
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
        let connected = connect_pipe(pipe.as_raw());
        if let Err(err) = connected {
            return Err(err);
        }

        last_activity = Instant::now();
        let _ = handle_client(pipe.as_raw(), &current_user_sid, &mut cache);
        disconnect_pipe(pipe.as_raw());
    }
}

pub(crate) fn verify_agent_transport_security() -> io::Result<()> {
    let _security = PipeSecurity::current_owner_only()?;
    let _sid = current_process_user_sid()?;
    Ok(())
}

pub(crate) fn get(lockbox_id: LockboxId) -> io::Result<Option<SecretVec>> {
    if open_pipe(&wide_pipe_name()).is_err() {
        return Ok(None);
    }
    match request(&encode_get(lockbox_id)?)? {
        AgentResponse::Key(key) => Ok(Some(key)),
        AgentResponse::Miss => Ok(None),
        response => invalid_agent_response(response),
    }
}

pub(crate) fn put(lockbox_id: LockboxId, key: &SecretVec) -> io::Result<()> {
    expect_ok(request(&encode_put(lockbox_id, key)?)?)
}

pub(crate) fn forget(lockbox_id: LockboxId) -> io::Result<()> {
    if open_pipe(&wide_pipe_name()).is_err() {
        return Ok(());
    }
    expect_ok(request(&encode_forget(lockbox_id)?)?)
}

pub(crate) fn forget_all() -> io::Result<()> {
    if open_pipe(&wide_pipe_name()).is_err() {
        return Ok(());
    }
    expect_ok(request(&encode_forget_all()?)?)
}

pub(crate) fn list() -> io::Result<Vec<String>> {
    if open_pipe(&wide_pipe_name()).is_err() {
        return Ok(Vec::new());
    }
    match request(&encode_list()?)? {
        AgentResponse::List(ids) => Ok(ids),
        response => invalid_agent_response(response),
    }
}

fn request(message: &SecretVec) -> io::Result<AgentResponse> {
    let pipe_name = wide_pipe_name();
    let handle = match open_pipe(&pipe_name) {
        Ok(handle) => handle,
        Err(_) => {
            start_agent()?;
            open_pipe(&pipe_name)?
        }
    };
    message
        .with_bytes(|message| write_all(handle.as_raw(), message))
        .map_err(io::Error::other)??;
    parse_response(read_frame(handle.as_raw(), max_message_bytes())?)
}

fn start_agent() -> io::Result<()> {
    let exe = env::current_exe()?;
    Command::new(exe)
        .arg("__agent")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    Ok(())
}

fn create_pipe() -> io::Result<OwnedHandle> {
    let name = wide_pipe_name();
    let mut security = PipeSecurity::current_owner_only()?;
    // SAFETY: `name` is a null-terminated UTF-16 string, `security` owns a
    // valid `SECURITY_ATTRIBUTES` for the duration of the call, and no pointer
    // is retained by Rust after the OS returns.
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            0,
            security.as_mut_ptr(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(OwnedHandle::new(handle))
    }
}

struct OwnedHandle {
    handle: HANDLE,
}

impl OwnedHandle {
    fn new(handle: HANDLE) -> Self {
        Self { handle }
    }

    fn as_raw(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        close_handle(self.handle);
    }
}

fn close_handle(handle: HANDLE) {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return;
    }
    // SAFETY: `handle` is owned by an `OwnedHandle` or explicit close site and
    // is not used after this call.
    unsafe {
        CloseHandle(handle);
    }
}

struct PipeSecurity {
    descriptor: PSECURITY_DESCRIPTOR,
    attributes: SECURITY_ATTRIBUTES,
}

impl PipeSecurity {
    fn current_owner_only() -> io::Result<Self> {
        let sddl = to_wide("D:P(A;;GA;;;OW)");
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `sddl` is a null-terminated UTF-16 SDDL string and
        // `descriptor` is a valid out pointer initialized by the OS on success.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            descriptor,
            attributes: SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.cast(),
                bInheritHandle: 0,
            },
        })
    }

    fn as_mut_ptr(&mut self) -> *mut SECURITY_ATTRIBUTES {
        &mut self.attributes
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            // SAFETY: `descriptor` was allocated by
            // `ConvertStringSecurityDescriptorToSecurityDescriptorW` and is
            // released exactly once by this owner.
            unsafe {
                LocalFree(self.descriptor.cast());
            }
        }
    }
}

fn connect_pipe(pipe: HANDLE) -> io::Result<()> {
    // SAFETY: `pipe` is a named-pipe handle returned by `CreateNamedPipeW`;
    // `null_mut` means synchronous operation without overlapped state.
    let ok = unsafe { ConnectNamedPipe(pipe, null_mut()) };
    if ok != 0 {
        return Ok(());
    }
    let err = last_error();
    if err == ERROR_PIPE_CONNECTED {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(err as i32))
    }
}

fn disconnect_pipe(pipe: HANDLE) {
    // SAFETY: `pipe` is a connected named-pipe handle owned by the server loop.
    // Disconnection does not close the handle; `OwnedHandle` closes it later.
    unsafe {
        DisconnectNamedPipe(pipe);
    }
}

fn last_error() -> u32 {
    // SAFETY: `GetLastError` reads thread-local OS error state and has no
    // Rust-side memory invariants.
    unsafe { GetLastError() }
}

fn open_pipe(pipe_name: &[u16]) -> io::Result<OwnedHandle> {
    let deadline = Instant::now() + PIPE_OPEN_TIMEOUT;
    loop {
        // SAFETY: `pipe_name` is a null-terminated UTF-16 string and all
        // pointer arguments either reference valid data for the call or are
        // intentionally null per the Windows API contract.
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
            return Ok(OwnedHandle::new(handle));
        }
        let err = last_error();
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
        // SAFETY: `pipe_name` is a null-terminated UTF-16 string valid for the
        // duration of the wait call.
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
    let request = read_frame(pipe, max_message_bytes())?;
    if request.is_empty() {
        return Ok(());
    }
    if !client_matches_current_user(pipe, current_user_sid)? {
        return Ok(());
    }
    let response = match parse_request(&request) {
        Ok(AgentRequest::Get(lockbox_id)) => {
            let now = Instant::now();
            match cache.get_mut(&lockbox_id) {
                Some(entry) if entry.expires_at > now => {
                    entry.expires_at = now + Duration::from_secs(DEFAULT_TTL_SECONDS);
                    encode_key_response(&entry.key)?
                }
                _ => encode_response_line(b"MISS\n")?,
            }
        }
        Ok(AgentRequest::Put(lockbox_id, key)) => {
            cache.insert(
                lockbox_id,
                CacheEntry {
                    key,
                    expires_at: Instant::now() + Duration::from_secs(DEFAULT_TTL_SECONDS),
                },
            );
            encode_response_line(b"OK\n")?
        }
        Ok(AgentRequest::Forget(lockbox_id)) => {
            cache.remove(&lockbox_id);
            encode_response_line(b"OK\n")?
        }
        Ok(AgentRequest::ForgetAll) => {
            cache.clear();
            encode_response_line(b"OK\n")?
        }
        Ok(AgentRequest::List) => encode_list_response(cache.keys().cloned())?,
        Err(_) => encode_response_line(b"ERR invalid request\n")?,
    };
    response
        .with_bytes(|response| write_all(pipe, response))
        .map_err(io::Error::other)?
}

fn client_matches_current_user(pipe: HANDLE, current_user_sid: &[u8]) -> io::Result<bool> {
    let _impersonation = ImpersonationGuard::new(pipe)?;
    let Some(token) = open_thread_token()? else {
        return Ok(false);
    };
    let client_sid = token_user_sid(token.as_raw())?;
    Ok(equal_sid(&client_sid, current_user_sid))
}

fn current_process_user_sid() -> io::Result<Vec<u8>> {
    let token = open_process_token()?;
    token_user_sid(token.as_raw())
}

struct ImpersonationGuard;

impl ImpersonationGuard {
    fn new(pipe: HANDLE) -> io::Result<Self> {
        // SAFETY: `pipe` is the connected named-pipe server handle for the
        // current client request.
        let impersonated = unsafe { ImpersonateNamedPipeClient(pipe) };
        if impersonated == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self)
        }
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        // SAFETY: If this guard exists, the current thread successfully
        // impersonated a pipe client and must be reverted before leaving scope.
        unsafe {
            RevertToSelf();
        }
    }
}

fn open_thread_token() -> io::Result<Option<OwnedHandle>> {
    let mut token: HANDLE = null_mut();
    // SAFETY: `token` is a valid out pointer and the current thread may have
    // an impersonation token after `ImpersonateNamedPipeClient`.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &mut token) };
    if opened == 0 {
        let err = last_error();
        if err == ERROR_NO_TOKEN {
            Ok(None)
        } else {
            Err(io::Error::from_raw_os_error(err as i32))
        }
    } else {
        Ok(Some(OwnedHandle::new(token)))
    }
}

fn open_process_token() -> io::Result<OwnedHandle> {
    let mut token: HANDLE = null_mut();
    // SAFETY: `token` is a valid out pointer and the process pseudo-handle is
    // valid for querying the current process token.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(OwnedHandle::new(token))
    }
}

fn token_user_sid(token: HANDLE) -> io::Result<Vec<u8>> {
    let mut needed = 0u32;
    // SAFETY: This first call intentionally passes a null buffer to query the
    // required size in `needed`, which is the documented Windows API pattern.
    unsafe {
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = vec![0u8; needed as usize];
    // SAFETY: `buffer` has `needed` bytes of writable storage and `needed`
    // points to the size value for the duration of the call.
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
    // SAFETY: On success, `buffer` contains a valid `TOKEN_USER` structure as
    // documented for `GetTokenInformation(TokenUser, ...)`.
    let token_user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
    let sid = token_user.User.Sid;
    let sid_len = sid_length(sid)?;
    let mut out = vec![0u8; sid_len];
    // SAFETY: `sid` points inside the successful token information buffer and
    // `out` has exactly `sid_len` writable bytes. The ranges do not overlap.
    unsafe {
        std::ptr::copy_nonoverlapping(sid as *const u8, out.as_mut_ptr(), sid_len);
    }
    Ok(out)
}

fn sid_length(sid: *mut c_void) -> io::Result<usize> {
    if sid.is_null() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "null SID"));
    }
    let revision_ptr = sid as *const u8;
    // SAFETY: `sid` is expected to point to a valid SID returned by Windows.
    // The second byte is the SID sub-authority count in the documented layout.
    let sub_authority_count = unsafe { *revision_ptr.add(1) as usize };
    Ok(8 + sub_authority_count * 4)
}

fn equal_sid(left: &[u8], right: &[u8]) -> bool {
    // SAFETY: `left` and `right` are SID byte buffers copied from Windows token
    // data and remain valid for the duration of the comparison call.
    unsafe { EqualSid(left.as_ptr() as *mut c_void, right.as_ptr() as *mut c_void) != 0 }
}

fn write_all(handle: HANDLE, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let mut written = 0u32;
        let chunk_len = bytes.len().min(PIPE_BUFFER_BYTES as usize) as u32;
        // SAFETY: `bytes` points to at least `chunk_len` readable bytes,
        // `written` is a valid out pointer, and the pipe handle is valid for
        // writing while this function owns the operation.
        let ok = unsafe { WriteFile(handle, bytes.as_ptr(), chunk_len, &mut written, null_mut()) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

fn read_frame(handle: HANDLE, max_bytes: usize) -> io::Result<SecretVec> {
    let mut out = SecretVec::new();
    let mut header = Vec::new();
    loop {
        let byte = read_one_byte(handle)?;
        header.push(byte);
        if header.len() > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message too large",
            ));
        }
        out.try_push(byte).map_err(io::Error::other)?;
        if byte == b'\n' {
            break;
        }
    }
    let body_len = frame_body_len(&header)?;
    let Some(frame_len) = out.len().checked_add(body_len) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    };
    if frame_len > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    read_exact_secure(handle, body_len, &mut out)?;
    Ok(out)
}

fn read_exact_secure(handle: HANDLE, mut remaining: usize, out: &mut SecretVec) -> io::Result<()> {
    let mut buffer = [0u8; 4096];
    while remaining > 0 {
        let read = read_chunk(handle, &mut buffer[..remaining.min(4096)])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "message ended before frame body",
            ));
        }
        out.try_extend_from_slice(&buffer[..read])
            .map_err(io::Error::other)?;
        buffer[..read].fill(0);
        remaining -= read;
    }
    Ok(())
}

fn read_one_byte(handle: HANDLE) -> io::Result<u8> {
    let mut byte = [0u8; 1];
    match read_chunk(handle, &mut byte)? {
        1 => Ok(byte[0]),
        _ => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "message ended before frame header",
        )),
    }
}

fn read_chunk(handle: HANDLE, buffer: &mut [u8]) -> io::Result<usize> {
    let mut read = 0u32;
    // SAFETY: `buffer` and `read` are valid writable storage for the duration
    // of the call, and the pipe handle is valid for reading.
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
        return Err(io::Error::last_os_error());
    }
    Ok(read as usize)
}

fn frame_body_len(header: &[u8]) -> io::Result<usize> {
    let header = std::str::from_utf8(header)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame header is not UTF-8"))?;
    let header = header.trim_end_matches(['\r', '\n']);
    let parts: Vec<&str> = header.split_whitespace().collect();
    match parts.as_slice() {
        ["LBX1", "PUT", _, len] | ["KEY", len] => len
            .parse::<usize>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid frame body length")),
        _ => Ok(0),
    }
}

fn prune_expired(cache: &mut BTreeMap<String, CacheEntry>) {
    let now = Instant::now();
    cache.retain(|_, entry| entry.expires_at > now);
}

fn expect_ok(response: AgentResponse) -> io::Result<()> {
    match response {
        AgentResponse::Ok => Ok(()),
        AgentResponse::Err(message) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("agent rejected request: {message}"),
        )),
        other => invalid_agent_response(other),
    }
}

fn invalid_agent_response<T>(response: AgentResponse) -> io::Result<T> {
    let label = match response {
        AgentResponse::Ok => "OK",
        AgentResponse::Miss => "MISS",
        AgentResponse::Key(_) => "KEY",
        AgentResponse::List(_) => "LIST",
        AgentResponse::Err(_) => "ERR",
    };
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unexpected agent response: {label}"),
    ))
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

#[cfg(test)]
mod tests {
    #[test]
    fn pipe_security_descriptor_can_be_built() {
        super::verify_agent_transport_security().unwrap();
    }
}
