use super::{
    encode_forget, encode_forget_all, encode_get, encode_key_response, encode_put,
    encode_response_line, max_message_bytes, parse_request, parse_response, AgentRequest,
    AgentResponse, SecretVec, DEFAULT_TTL_SECONDS,
};
use lockbox_core::LockboxId;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const IDLE_EXIT_SECONDS: u64 = 10 * 60;

struct CacheEntry {
    key: SecretVec,
    expires_at: Instant,
}

pub(crate) fn serve_agent() -> io::Result<()> {
    let socket = socket_path();
    prepare_socket_dir()?;
    if socket.exists() {
        let _ = fs::remove_file(&socket);
    }
    let listener = UnixListener::bind(&socket)?;
    listener.set_nonblocking(true)?;

    let mut cache = BTreeMap::<String, CacheEntry>::new();
    let mut last_activity = Instant::now();
    loop {
        prune_expired(&mut cache);
        match listener.accept() {
            Ok((stream, _)) => {
                last_activity = Instant::now();
                let _ = handle_client(stream, &mut cache);
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                if cache.is_empty()
                    && last_activity.elapsed() > Duration::from_secs(IDLE_EXIT_SECONDS)
                {
                    let _ = fs::remove_file(&socket);
                    return Ok(());
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(err) => return Err(err),
        }
    }
}

pub(crate) fn verify_agent_transport_security() -> io::Result<()> {
    Ok(())
}

pub(crate) fn get(lockbox_id: LockboxId) -> io::Result<Option<SecretVec>> {
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
    expect_ok(request(&encode_forget(lockbox_id)?)?)
}

pub(crate) fn forget_all() -> io::Result<()> {
    expect_ok(request(&encode_forget_all()?)?)
}

fn request(message: &SecretVec) -> io::Result<AgentResponse> {
    ensure_agent()?;
    let mut stream = UnixStream::connect(socket_path())?;
    message
        .with_bytes(|message| stream.write_all(message))
        .map_err(io::Error::other)??;
    stream.shutdown(std::net::Shutdown::Write)?;
    parse_response(read_secure(stream, max_message_bytes())?)
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
        "lockbox agent did not start",
    ))
}

fn handle_client(
    mut stream: UnixStream,
    cache: &mut BTreeMap<String, CacheEntry>,
) -> io::Result<()> {
    let request = read_secure(stream.try_clone()?, max_message_bytes())?;
    if request.is_empty() {
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
        Err(_) => encode_response_line(b"ERR invalid request\n")?,
    };
    response
        .with_bytes(|response| stream.write_all(response))
        .map_err(io::Error::other)??;
    Ok(())
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
        AgentResponse::Err(_) => "ERR",
    };
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unexpected agent response: {label}"),
    ))
}

fn read_secure(mut reader: impl Read, max_bytes: usize) -> io::Result<SecretVec> {
    let mut out = SecretVec::new();
    let mut buffer = [0u8; 4096];
    let mut total = 0usize;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "message too large"))?;
        if total > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message too large",
            ));
        }
        out.try_extend_from_slice(&buffer[..read])
            .map_err(io::Error::other)?;
        buffer[..read].fill(0);
    }
    Ok(out)
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
    if let Ok(dir) = env::var("LOCKBOX_AGENT_DIR") {
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
