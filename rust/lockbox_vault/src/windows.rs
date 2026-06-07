use super::{
    encode_control_err_response, encode_control_ok_response, encode_err_response, encode_forget,
    encode_forget_all, encode_get, encode_key_response, encode_list, encode_list_response,
    encode_miss_response, encode_ok_response, encode_put, encode_register_secret_activity,
    encode_registered_response, encode_stop, encode_unregister_secret_activity, frame_header_len,
    frame_message_type, frame_payload_len, is_control_message_type, max_message_bytes,
    parse_control_request, parse_control_response, parse_request, parse_response, AgentRequest,
    AgentResponse, CachedLockbox, ControlRequest, ControlResponse, SecretActivityKind, SecretVec,
    DEFAULT_TTL_SECONDS,
};
use crate::active_secret::ActiveSecretRegistry;
use crate::agent_config::AgentConfig;
use crate::agent_log::log_agent_event;
use crate::sleep_watcher::{SleepEvent, SleepWatcher};
use lockbox_core::LockboxId;
use std::collections::hash_map::DefaultHasher;
use std::collections::BTreeMap;
use std::env;
use std::ffi::c_void;
use std::hash::{Hash, Hasher};
use std::io;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::process::{Command, Stdio};
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex};
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
    path: Option<String>,
    ttl_seconds: u64,
    expires_at: Instant,
}

pub(crate) fn serve_agent() -> io::Result<()> {
    log_agent_event("agent starting");
    let current_user_sid = current_process_user_sid()?;
    let cache = Arc::new(Mutex::new(BTreeMap::<String, CacheEntry>::new()));
    let config = AgentConfig::load();
    log_agent_event(format!(
        "agent config prevent_sleep={} terminate_on_suspend={}",
        config.prevent_sleep, config.terminate_on_suspend
    ));
    let active = Arc::new(Mutex::new(ActiveSecretRegistry::new(config)));
    let mut last_activity = Instant::now();
    start_sleep_cache_clearer(cache.clone(), active.clone());

    loop {
        {
            let mut cache = lock_cache(&cache)?;
            log_pruned_expired(&mut cache);
            let active_empty = lock_active(&active)?.is_empty();
            if cache.is_empty()
                && active_empty
                && last_activity.elapsed() > Duration::from_secs(IDLE_EXIT_SECONDS)
            {
                log_agent_event("agent exiting after idle timeout");
                return Ok(());
            }
        }

        let pipe = create_pipe()?;
        let connected = connect_pipe(pipe.as_raw());
        if let Err(err) = connected {
            return Err(err);
        }
        log_agent_event("agent client connected");

        last_activity = Instant::now();
        let stop = {
            let mut cache = match lock_cache(&cache) {
                Ok(cache) => cache,
                Err(err) => {
                    log_agent_event(format!("agent cache lock failed: {err}"));
                    return Err(err);
                }
            };
            log_agent_event("agent cache locked");
            match catch_unwind(AssertUnwindSafe(|| {
                handle_client(pipe.as_raw(), &current_user_sid, &mut cache, &active)
            })) {
                Ok(Ok(stop)) => {
                    log_agent_event("agent request handled");
                    stop
                }
                Ok(Err(err)) => {
                    log_agent_event(format!("agent request failed: {err}"));
                    false
                }
                Err(_) => {
                    log_agent_event("agent request panicked");
                    false
                }
            }
        };
        disconnect_pipe(pipe.as_raw());
        if stop {
            log_agent_event("agent stopped by request");
            return Ok(());
        }
    }
}

fn start_sleep_cache_clearer(
    cache: Arc<Mutex<BTreeMap<String, CacheEntry>>>,
    active: Arc<Mutex<ActiveSecretRegistry>>,
) {
    let Ok(watcher) = SleepWatcher::start() else {
        log_agent_event("sleep watcher unavailable");
        return;
    };
    log_agent_event("sleep watcher started");
    let _ = thread::Builder::new()
        .name("lockbox-sleep-cache-clearer".to_string())
        .spawn(move || {
            while let Ok(event) = watcher.recv() {
                if event == SleepEvent::SuspendRequested {
                    if let Ok(mut cache) = cache.lock() {
                        let count = cache.len();
                        cache.clear();
                        log_agent_event(format!(
                            "suspend requested; cleared {count} cached lockboxes"
                        ));
                    }
                    if let Ok(mut active) = active.lock() {
                        active.suspend_requested();
                    }
                } else if event == SleepEvent::Resumed {
                    log_agent_event("resume observed");
                }
            }
        });
}

fn lock_cache(
    cache: &Arc<Mutex<BTreeMap<String, CacheEntry>>>,
) -> io::Result<std::sync::MutexGuard<'_, BTreeMap<String, CacheEntry>>> {
    cache
        .lock()
        .map_err(|_| io::Error::other("session agent cache lock was poisoned"))
}

fn lock_active(
    active: &Arc<Mutex<ActiveSecretRegistry>>,
) -> io::Result<std::sync::MutexGuard<'_, ActiveSecretRegistry>> {
    active
        .lock()
        .map_err(|_| io::Error::other("session agent activity lock was poisoned"))
}

pub(crate) fn verify_agent_transport_security() -> io::Result<()> {
    let _security = PipeSecurity::current_owner_only()?;
    let _sid = current_process_user_sid()?;
    Ok(())
}

pub(crate) fn get(lockbox_id: LockboxId) -> io::Result<Option<SecretVec>> {
    match request_existing(&encode_get(lockbox_id)?)? {
        Some(AgentResponse::Key(key)) => Ok(Some(key)),
        Some(AgentResponse::Miss) | None => Ok(None),
        Some(response) => invalid_agent_response(response),
    }
}

pub(crate) fn put(
    lockbox_id: LockboxId,
    key: &SecretVec,
    path: Option<&str>,
    ttl_seconds: Option<u64>,
) -> io::Result<()> {
    expect_ok(request(&encode_put(lockbox_id, key, path, ttl_seconds)?)?)
}

pub(crate) fn forget(lockbox_id: LockboxId) -> io::Result<()> {
    match request_existing(&encode_forget(lockbox_id)?)? {
        Some(response) => expect_ok(response),
        None => Ok(()),
    }
}

pub(crate) fn forget_all() -> io::Result<()> {
    match request_existing(&encode_forget_all()?)? {
        Some(response) => expect_ok(response),
        None => Ok(()),
    }
}

pub(crate) fn stop() -> io::Result<()> {
    match request_existing(&encode_stop()?)? {
        Some(response) => expect_ok(response),
        None => Ok(()),
    }
}

pub(crate) fn list() -> io::Result<Vec<CachedLockbox>> {
    match request_existing(&encode_list()?)? {
        Some(AgentResponse::List(ids)) => Ok(ids),
        None => Ok(Vec::new()),
        Some(response) => invalid_agent_response(response),
    }
}

pub(crate) fn register_secret_activity(kind: SecretActivityKind) -> io::Result<u64> {
    match request_control(&encode_register_secret_activity(std::process::id(), kind)?)? {
        ControlResponse::Registered(token) => Ok(token),
        response => invalid_control_response(response),
    }
}

pub(crate) fn unregister_secret_activity(pid: u32, token: u64) -> io::Result<()> {
    match request_control_existing(&encode_unregister_secret_activity(pid, token)?)? {
        Some(response) => expect_control_ok(response),
        None => Ok(()),
    }
}

pub(crate) fn is_running() -> bool {
    open_pipe(&wide_pipe_name()).is_ok()
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
    request_with_handle(handle, message)
}

fn request_existing(message: &SecretVec) -> io::Result<Option<AgentResponse>> {
    let pipe_name = wide_pipe_name();
    let Ok(handle) = open_pipe(&pipe_name) else {
        return Ok(None);
    };
    request_with_handle(handle, message).map(Some)
}

fn request_control(message: &[u8]) -> io::Result<ControlResponse> {
    let pipe_name = wide_pipe_name();
    let handle = match open_pipe(&pipe_name) {
        Ok(handle) => handle,
        Err(_) => {
            start_agent()?;
            open_pipe(&pipe_name)?
        }
    };
    request_control_with_handle(handle, message)
}

fn request_control_existing(message: &[u8]) -> io::Result<Option<ControlResponse>> {
    let pipe_name = wide_pipe_name();
    let Ok(handle) = open_pipe(&pipe_name) else {
        return Ok(None);
    };
    request_control_with_handle(handle, message).map(Some)
}

fn request_with_handle(handle: OwnedHandle, message: &SecretVec) -> io::Result<AgentResponse> {
    message
        .with_bytes(|message| write_all(handle.as_raw(), message))
        .map_err(io::Error::other)?
        .map_err(|err| io::Error::new(err.kind(), format!("agent pipe write failed: {err}")))?;
    parse_response(
        read_secure_frame(handle.as_raw(), max_message_bytes())
            .map_err(|err| io::Error::new(err.kind(), format!("agent pipe read failed: {err}")))?,
    )
}

fn request_control_with_handle(handle: OwnedHandle, message: &[u8]) -> io::Result<ControlResponse> {
    write_all(handle.as_raw(), message)
        .map_err(|err| io::Error::new(err.kind(), format!("agent pipe write failed: {err}")))?;
    parse_control_response(
        &read_plain_frame(handle.as_raw(), max_message_bytes())
            .map_err(|err| io::Error::new(err.kind(), format!("agent pipe read failed: {err}")))?,
    )
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
    // SAFETY: Disconnection does not close the handle; `OwnedHandle` closes it
    // later. The response frame has already been written synchronously; forcing
    // a server-side flush can deadlock with clients that issue a follow-up
    // control request while the agent is still waiting for the pipe to drain.
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
    active: &Arc<Mutex<ActiveSecretRegistry>>,
) -> io::Result<bool> {
    let request = read_agent_frame(pipe, max_message_bytes())?;
    if !client_matches_current_user(pipe, current_user_sid)? {
        log_agent_event("rejected agent request from different user");
        return Ok(false);
    }
    log_agent_event("agent request user accepted");
    let mut stop = false;
    let response = match request {
        AgentFrame::Cache(request) => {
            let response = handle_cache_request(&request, cache, &mut stop)?;
            AgentReply::Cache(response)
        }
        AgentFrame::Control(request) => {
            let response = handle_control_request(&request, active)?;
            AgentReply::Control(response)
        }
    };
    write_agent_reply(pipe, response)?;
    Ok(stop)
}

fn handle_cache_request(
    request: &SecretVec,
    cache: &mut BTreeMap<String, CacheEntry>,
    stop: &mut bool,
) -> io::Result<SecretVec> {
    let response = match parse_request(request) {
        Ok(AgentRequest::Get(lockbox_id)) => {
            log_agent_event(format!("agent request get {lockbox_id}"));
            let now = Instant::now();
            match cache.get_mut(&lockbox_id) {
                Some(entry) if entry.expires_at > now => {
                    entry.expires_at = now + Duration::from_secs(entry.ttl_seconds);
                    log_agent_event(format!("cache hit {lockbox_id}"));
                    encode_key_response(&entry.key)?
                }
                _ => {
                    log_agent_event(format!("cache miss {lockbox_id}"));
                    encode_miss_response()?
                }
            }
        }
        Ok(AgentRequest::Put(lockbox_id, key, path, ttl_seconds)) => {
            log_agent_event(format!("agent request put {lockbox_id}"));
            let ttl_seconds = ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
            log_agent_event(format!(
                "cached lockbox {lockbox_id} ttl_seconds={ttl_seconds} path={}",
                path.as_deref().unwrap_or("")
            ));
            cache.insert(
                lockbox_id.clone(),
                CacheEntry {
                    key,
                    path,
                    ttl_seconds,
                    expires_at: Instant::now() + Duration::from_secs(ttl_seconds),
                },
            );
            encode_ok_response()?
        }
        Ok(AgentRequest::Forget(lockbox_id)) => {
            log_agent_event(format!("agent request forget {lockbox_id}"));
            cache.remove(&lockbox_id);
            log_agent_event(format!("forgot lockbox {lockbox_id}"));
            encode_ok_response()?
        }
        Ok(AgentRequest::ForgetAll) => {
            log_agent_event("agent request forget-all");
            let count = cache.len();
            cache.clear();
            log_agent_event(format!("forgot all cached lockboxes count={count}"));
            encode_ok_response()?
        }
        Ok(AgentRequest::Stop) => {
            log_agent_event("agent request stop");
            let count = cache.len();
            cache.clear();
            *stop = true;
            log_agent_event(format!("stop requested; cleared {count} cached lockboxes"));
            encode_ok_response()?
        }
        Ok(AgentRequest::List) => {
            log_agent_event("agent request list");
            log_agent_event(format!("listed cached lockboxes count={}", cache.len()));
            encode_list_response(cache.iter().map(|(id, entry)| CachedLockbox {
                id: id.clone(),
                path: entry.path.clone(),
            }))?
        }
        Err(err) => {
            log_agent_event(format!("agent request parse failed: {err}"));
            encode_err_response("invalid request")?
        }
    };
    Ok(response)
}

fn handle_control_request(
    request: &[u8],
    active: &Arc<Mutex<ActiveSecretRegistry>>,
) -> io::Result<Vec<u8>> {
    match parse_control_request(request) {
        Ok(ControlRequest::RegisterSecretActivity(pid, kind)) => {
            log_agent_event("agent request register-secret-activity");
            let token = lock_active(active)?.register(pid, kind)?;
            encode_registered_response(token)
        }
        Ok(ControlRequest::UnregisterSecretActivity(pid, token)) => {
            log_agent_event("agent request unregister-secret-activity");
            lock_active(active)?.unregister(pid, token);
            encode_control_ok_response()
        }
        Err(err) => {
            log_agent_event(format!("agent control request parse failed: {err}"));
            encode_control_err_response("invalid control request")
        }
    }
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
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
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

enum AgentFrame {
    Cache(SecretVec),
    Control(Vec<u8>),
}

enum AgentReply {
    Cache(SecretVec),
    Control(Vec<u8>),
}

fn read_agent_frame(handle: HANDLE, max_bytes: usize) -> io::Result<AgentFrame> {
    let mut header = vec![0u8; frame_header_len()];
    read_exact_plain(handle, &mut header)?;
    let payload_len = frame_payload_len(&header)?;
    let frame_len = checked_frame_len(header.len(), payload_len, max_bytes)?;
    let message_type = frame_message_type(&header)?;
    if is_control_message_type(message_type) {
        let mut frame = header;
        frame.resize(frame_len, 0);
        read_exact_plain(handle, &mut frame[frame_header_len()..])?;
        Ok(AgentFrame::Control(frame))
    } else {
        let mut out = SecretVec::new();
        out.try_extend_from_slice(&header)
            .map_err(io::Error::other)?;
        read_exact_secure(handle, payload_len, &mut out)?;
        Ok(AgentFrame::Cache(out))
    }
}

fn read_secure_frame(handle: HANDLE, max_bytes: usize) -> io::Result<SecretVec> {
    let mut header = vec![0u8; frame_header_len()];
    read_exact_plain(handle, &mut header)?;
    let payload_len = frame_payload_len(&header)?;
    checked_frame_len(header.len(), payload_len, max_bytes)?;
    let mut out = SecretVec::new();
    out.try_extend_from_slice(&header)
        .map_err(io::Error::other)?;
    read_exact_secure(handle, payload_len, &mut out)?;
    Ok(out)
}

fn read_plain_frame(handle: HANDLE, max_bytes: usize) -> io::Result<Vec<u8>> {
    let mut header = vec![0u8; frame_header_len()];
    read_exact_plain(handle, &mut header)?;
    let payload_len = frame_payload_len(&header)?;
    let frame_len = checked_frame_len(header.len(), payload_len, max_bytes)?;
    let mut frame = header;
    frame.resize(frame_len, 0);
    read_exact_plain(handle, &mut frame[frame_header_len()..])?;
    Ok(frame)
}

fn checked_frame_len(header_len: usize, payload_len: usize, max_bytes: usize) -> io::Result<usize> {
    let frame_len = header_len
        .checked_add(payload_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "message too large"))?;
    if frame_len > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    Ok(frame_len)
}

fn write_agent_reply(pipe: HANDLE, response: AgentReply) -> io::Result<()> {
    match response {
        AgentReply::Cache(response) => response
            .with_bytes(|response| write_all(pipe, response))
            .map_err(io::Error::other)?,
        AgentReply::Control(response) => write_all(pipe, &response),
    }
}

fn read_exact_plain(handle: HANDLE, mut out: &mut [u8]) -> io::Result<()> {
    while !out.is_empty() {
        let read = read_chunk(handle, out)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "message ended before frame header",
            ));
        }
        let remaining = out.split_at_mut(read).1;
        out = remaining;
    }
    Ok(())
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

fn prune_expired(cache: &mut BTreeMap<String, CacheEntry>) {
    let now = Instant::now();
    cache.retain(|_, entry| entry.expires_at > now);
}

fn log_pruned_expired(cache: &mut BTreeMap<String, CacheEntry>) {
    let before = cache.len();
    prune_expired(cache);
    let pruned = before.saturating_sub(cache.len());
    if pruned != 0 {
        log_agent_event(format!("pruned expired cached lockboxes count={pruned}"));
    }
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

fn expect_control_ok(response: ControlResponse) -> io::Result<()> {
    match response {
        ControlResponse::Ok => Ok(()),
        ControlResponse::Err(message) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("agent rejected control request: {message}"),
        )),
        other => invalid_control_response(other),
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

fn invalid_control_response<T>(response: ControlResponse) -> io::Result<T> {
    let label = match response {
        ControlResponse::Ok => "OK",
        ControlResponse::Registered(_) => "REGISTERED",
        ControlResponse::Err(_) => "ERR",
    };
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unexpected agent control response: {label}"),
    ))
}

fn wide_pipe_name() -> Vec<u16> {
    to_wide(&format!(r"\\.\pipe\lockbox-agent-{}", pipe_scope()))
}

fn pipe_scope() -> String {
    let user = sanitize_name(&current_user());
    let Ok(agent_dir) = env::var("LOCKBOX_SESSION_AGENT_DIR") else {
        return user;
    };
    format!("{user}-{:016x}", hash_value(&agent_dir))
}

fn hash_value(value: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
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
