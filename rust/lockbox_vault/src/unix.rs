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
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const IDLE_EXIT_SECONDS: u64 = 10 * 60;

struct CacheEntry {
    key: SecretVec,
    path: Option<String>,
    ttl_seconds: u64,
    expires_at: Instant,
}

pub(crate) fn serve_agent() -> io::Result<()> {
    log_agent_event("agent starting");
    let socket = socket_path();
    prepare_socket_dir()?;
    if socket.exists() {
        let _ = fs::remove_file(&socket);
    }
    let listener = UnixListener::bind(&socket)?;
    listener.set_nonblocking(true)?;

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
        }
        match listener.accept() {
            Ok((stream, _)) => {
                last_activity = Instant::now();
                let stop = {
                    let mut cache = lock_cache(&cache)?;
                    handle_client(stream, &mut cache, &active).unwrap_or(false)
                };
                if stop {
                    let _ = fs::remove_file(&socket);
                    log_agent_event("agent stopped by request");
                    return Ok(());
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                let cache_empty = lock_cache(&cache)?.is_empty();
                let active_empty = lock_active(&active)?.is_empty();
                if cache_empty
                    && active_empty
                    && last_activity.elapsed() > Duration::from_secs(IDLE_EXIT_SECONDS)
                {
                    let _ = fs::remove_file(&socket);
                    log_agent_event("agent exiting after idle timeout");
                    return Ok(());
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(err) => return Err(err),
        }
    }
}

fn start_sleep_cache_clearer(
    cache: Arc<Mutex<BTreeMap<String, CacheEntry>>>,
    active: Arc<Mutex<ActiveSecretRegistry>>,
) {
    let result = SleepWatcher::start_handler(move |event| match event {
        SleepEvent::SuspendRequested => {
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
        }
        SleepEvent::Resumed => {
            log_agent_event("resume observed");
        }
    });
    match result {
        Ok(()) => log_agent_event("sleep watcher started"),
        Err(err) => log_agent_event(format!("sleep watcher unavailable: {err}")),
    }
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

#[cfg(test)]
fn sleep_watcher_has_suspend(watcher: &Option<SleepWatcher>) -> bool {
    watcher
        .as_ref()
        .is_some_and(|watcher| watcher.drain().contains(&SleepEvent::SuspendRequested))
}

pub(crate) fn verify_agent_transport_security() -> io::Result<()> {
    Ok(())
}

pub(crate) fn get(lockbox_id: LockboxId) -> io::Result<Option<SecretVec>> {
    if UnixStream::connect(socket_path()).is_err() {
        return Ok(None);
    }
    match request(&encode_get(lockbox_id)?)? {
        AgentResponse::Key(key) => Ok(Some(key)),
        AgentResponse::Miss => Ok(None),
        response => invalid_agent_response(response),
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
    if UnixStream::connect(socket_path()).is_err() {
        return Ok(());
    }
    expect_ok(request(&encode_forget(lockbox_id)?)?)
}

pub(crate) fn forget_all() -> io::Result<()> {
    if UnixStream::connect(socket_path()).is_err() {
        return Ok(());
    }
    expect_ok(request(&encode_forget_all()?)?)
}

pub(crate) fn stop() -> io::Result<()> {
    if UnixStream::connect(socket_path()).is_err() {
        return Ok(());
    }
    expect_ok(request(&encode_stop()?)?)
}

pub(crate) fn list() -> io::Result<Vec<CachedLockbox>> {
    if UnixStream::connect(socket_path()).is_err() {
        return Ok(Vec::new());
    }
    match request(&encode_list()?)? {
        AgentResponse::List(ids) => Ok(ids),
        response => invalid_agent_response(response),
    }
}

pub(crate) fn register_secret_activity(kind: SecretActivityKind) -> io::Result<u64> {
    match request_control(&encode_register_secret_activity(std::process::id(), kind)?)? {
        ControlResponse::Registered(token) => Ok(token),
        response => invalid_control_response(response),
    }
}

pub(crate) fn unregister_secret_activity(pid: u32, token: u64) -> io::Result<()> {
    if UnixStream::connect(socket_path()).is_err() {
        return Ok(());
    }
    expect_control_ok(request_control(&encode_unregister_secret_activity(
        pid, token,
    )?)?)
}

pub(crate) fn is_running() -> bool {
    UnixStream::connect(socket_path()).is_ok()
}

fn request(message: &SecretVec) -> io::Result<AgentResponse> {
    ensure_agent()?;
    let mut stream = UnixStream::connect(socket_path())?;
    message
        .with_bytes(|message| stream.write_all(message))
        .map_err(io::Error::other)??;
    stream.shutdown(std::net::Shutdown::Write)?;
    parse_response(read_secure_frame(stream, max_message_bytes())?)
}

fn request_control(message: &[u8]) -> io::Result<ControlResponse> {
    ensure_agent()?;
    let mut stream = UnixStream::connect(socket_path())?;
    stream.write_all(message)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    parse_control_response(&read_plain_frame(stream, max_message_bytes())?)
}

fn ensure_agent() -> io::Result<()> {
    if UnixStream::connect(socket_path()).is_ok() {
        return Ok(());
    }
    prepare_socket_dir()?;
    let exe = env::current_exe()?;
    Command::new(exe)
        .arg("__agent")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if UnixStream::connect(socket_path()).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "lockbox session agent did not start",
    ))
}

fn handle_client(
    mut stream: UnixStream,
    cache: &mut BTreeMap<String, CacheEntry>,
    active: &Arc<Mutex<ActiveSecretRegistry>>,
) -> io::Result<bool> {
    let request = read_agent_frame(stream.try_clone()?, max_message_bytes())?;
    let (stop, response) = match request {
        AgentFrame::Cache(request) => {
            let (stop, response) = handle_agent_request(&request, cache)?;
            (stop, AgentReply::Cache(response))
        }
        AgentFrame::Control(request) => {
            let response = handle_control_request(&request, active)?;
            (false, AgentReply::Control(response))
        }
    };
    write_agent_reply(&mut stream, response)?;
    Ok(stop)
}

fn handle_agent_request(
    request: &SecretVec,
    cache: &mut BTreeMap<String, CacheEntry>,
) -> io::Result<(bool, SecretVec)> {
    let mut stop = false;
    let response = match parse_request(&request) {
        Ok(AgentRequest::Get(lockbox_id)) => {
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
            cache.remove(&lockbox_id);
            log_agent_event(format!("forgot lockbox {lockbox_id}"));
            encode_ok_response()?
        }
        Ok(AgentRequest::ForgetAll) => {
            let count = cache.len();
            cache.clear();
            log_agent_event(format!("forgot all cached lockboxes count={count}"));
            encode_ok_response()?
        }
        Ok(AgentRequest::Stop) => {
            let count = cache.len();
            cache.clear();
            stop = true;
            log_agent_event(format!("stop requested; cleared {count} cached lockboxes"));
            encode_ok_response()?
        }
        Ok(AgentRequest::List) => {
            log_agent_event(format!("listed cached lockboxes count={}", cache.len()));
            encode_list_response(cache.iter().map(|(id, entry)| CachedLockbox {
                id: id.clone(),
                path: entry.path.clone(),
            }))?
        }
        Err(_) => encode_err_response("invalid request")?,
    };
    Ok((stop, response))
}

fn handle_control_request(
    request: &[u8],
    active: &Arc<Mutex<ActiveSecretRegistry>>,
) -> io::Result<Vec<u8>> {
    match parse_control_request(request) {
        Ok(ControlRequest::RegisterSecretActivity(pid, kind)) => {
            let token = lock_active(active)?.register(pid, kind)?;
            encode_registered_response(token)
        }
        Ok(ControlRequest::UnregisterSecretActivity(pid, token)) => {
            lock_active(active)?.unregister(pid, token);
            encode_control_ok_response()
        }
        Err(_) => encode_control_err_response("invalid control request"),
    }
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

enum AgentFrame {
    Cache(SecretVec),
    Control(Vec<u8>),
}

enum AgentReply {
    Cache(SecretVec),
    Control(Vec<u8>),
}

fn read_agent_frame(mut reader: impl Read, max_bytes: usize) -> io::Result<AgentFrame> {
    let mut header = vec![0u8; frame_header_len()];
    reader.read_exact(&mut header)?;
    let payload_len = frame_payload_len(&header)?;
    let frame_len = checked_frame_len(header.len(), payload_len, max_bytes)?;
    let message_type = frame_message_type(&header)?;
    if is_control_message_type(message_type) {
        let mut frame = header;
        frame.resize(frame_len, 0);
        reader.read_exact(&mut frame[frame_header_len()..])?;
        Ok(AgentFrame::Control(frame))
    } else {
        let mut frame = SecretVec::new();
        frame
            .try_extend_from_slice(&header)
            .map_err(io::Error::other)?;
        read_secure_payload(reader, payload_len, &mut frame)?;
        Ok(AgentFrame::Cache(frame))
    }
}

fn read_secure_frame(mut reader: impl Read, max_bytes: usize) -> io::Result<SecretVec> {
    let mut header = vec![0u8; frame_header_len()];
    reader.read_exact(&mut header)?;
    let payload_len = frame_payload_len(&header)?;
    checked_frame_len(header.len(), payload_len, max_bytes)?;
    let mut frame = SecretVec::new();
    frame
        .try_extend_from_slice(&header)
        .map_err(io::Error::other)?;
    read_secure_payload(reader, payload_len, &mut frame)?;
    Ok(frame)
}

fn read_plain_frame(mut reader: impl Read, max_bytes: usize) -> io::Result<Vec<u8>> {
    let mut header = vec![0u8; frame_header_len()];
    reader.read_exact(&mut header)?;
    let payload_len = frame_payload_len(&header)?;
    let frame_len = checked_frame_len(header.len(), payload_len, max_bytes)?;
    let mut frame = header;
    frame.resize(frame_len, 0);
    reader.read_exact(&mut frame[frame_header_len()..])?;
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

fn write_agent_reply(stream: &mut UnixStream, response: AgentReply) -> io::Result<()> {
    match response {
        AgentReply::Cache(response) => response
            .with_bytes(|response| stream.write_all(response))
            .map_err(io::Error::other)?,
        AgentReply::Control(response) => stream.write_all(&response),
    }
}

fn read_secure_payload(
    mut reader: impl Read,
    mut remaining: usize,
    out: &mut SecretVec,
) -> io::Result<()> {
    let mut buffer = [0u8; 4096];
    while remaining != 0 {
        let read = reader.read(&mut buffer[..remaining.min(4096)])?;
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

fn prepare_socket_dir() -> io::Result<()> {
    let dir = socket_dir();
    fs::create_dir_all(&dir)?;
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    Ok(())
}

fn socket_path() -> PathBuf {
    socket_dir().join("agent.sock")
}

fn socket_dir() -> PathBuf {
    if let Ok(dir) = env::var("LOCKBOX_SESSION_AGENT_DIR") {
        return PathBuf::from(dir);
    }
    if let Ok(dir) = env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir).join("lockbox");
    }
    env::temp_dir().join(format!("lockbox-{}", current_user()))
}

fn current_user() -> String {
    env::var("USER").unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sleep_watcher_suspend_event_is_detected() {
        let watcher = SleepWatcher::from_events([SleepEvent::Resumed]);
        assert!(!sleep_watcher_has_suspend(&Some(watcher)));

        let watcher = SleepWatcher::from_events([SleepEvent::SuspendRequested]);
        assert!(sleep_watcher_has_suspend(&Some(watcher)));
        assert!(!sleep_watcher_has_suspend(&None));
    }

    #[test]
    fn cached_requests_work_without_sleep_watcher() {
        let mut cache = BTreeMap::<String, CacheEntry>::new();
        let lockbox_id = LockboxId::from_bytes([7; 16]);
        let key = SecretVec::try_from_slice(b"0123456789abcdef0123456789abcdef").unwrap();

        let (stop, response) = round_trip(
            &mut cache,
            encode_put(lockbox_id, &key, Some("/tmp/test.lbox"), Some(60)).unwrap(),
        );
        assert!(!stop);
        assert_ok(response);

        let (stop, response) = round_trip(&mut cache, encode_get(lockbox_id).unwrap());
        assert!(!stop);
        match response {
            AgentResponse::Key(stored_key) => assert_secret_eq(&stored_key, &key),
            _ => panic!("expected cached key response"),
        }

        let (_, response) = round_trip(&mut cache, encode_list().unwrap());
        match response {
            AgentResponse::List(lockboxes) => {
                assert_eq!(lockboxes.len(), 1);
                assert_eq!(lockboxes[0].id, lockbox_id.to_string());
                assert_eq!(lockboxes[0].path.as_deref(), Some("/tmp/test.lbox"));
            }
            _ => panic!("expected list response"),
        }

        let (_, response) = round_trip(&mut cache, encode_forget(lockbox_id).unwrap());
        assert_ok(response);

        let (_, response) = round_trip(&mut cache, encode_get(lockbox_id).unwrap());
        assert!(matches!(response, AgentResponse::Miss));

        let (_, response) = round_trip(
            &mut cache,
            encode_put(lockbox_id, &key, Some("/tmp/test.lbox"), Some(60)).unwrap(),
        );
        assert_ok(response);

        let (_, response) = round_trip(&mut cache, encode_forget_all().unwrap());
        assert_ok(response);

        let (stop, response) = round_trip(&mut cache, encode_stop().unwrap());
        assert!(stop);
        assert_ok(response);
    }

    #[test]
    fn suspend_event_clears_cached_lockboxes() {
        let mut cache = BTreeMap::<String, CacheEntry>::new();
        cache.insert(
            LockboxId::from_bytes([9; 16]).to_string(),
            CacheEntry {
                key: SecretVec::try_from_slice(b"cached-key").unwrap(),
                path: Some("/tmp/test.lbox".to_string()),
                ttl_seconds: 60,
                expires_at: Instant::now() + Duration::from_secs(60),
            },
        );

        let sleep_watcher = Some(SleepWatcher::from_events([SleepEvent::SuspendRequested]));
        if sleep_watcher_has_suspend(&sleep_watcher) {
            cache.clear();
        }

        assert!(cache.is_empty());
    }

    fn round_trip(
        cache: &mut BTreeMap<String, CacheEntry>,
        request: SecretVec,
    ) -> (bool, AgentResponse) {
        let (stop, response) = handle_agent_request(&request, cache).unwrap();
        (stop, parse_response(response).unwrap())
    }

    fn assert_ok(response: AgentResponse) {
        match response {
            AgentResponse::Ok => {}
            _ => panic!("expected OK response"),
        }
    }

    fn assert_secret_eq(left: &SecretVec, right: &SecretVec) {
        left.with_bytes(|left| {
            right.with_bytes(|right| {
                assert_eq!(left, right);
            })
        })
        .unwrap()
        .unwrap();
    }
}
