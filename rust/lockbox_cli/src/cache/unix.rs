use super::{
    decode_hex, encode_forget, encode_forget_all, encode_get, encode_hex, encode_put,
    max_request_bytes, parse_request, AgentRequest, SecretBytes, DEFAULT_TTL_SECONDS,
};
use lockbox_core::VaultId;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const IDLE_EXIT_SECONDS: u64 = 10 * 60;

struct CacheEntry {
    key: SecretBytes,
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
    let mut stream = UnixStream::connect(socket_path())?;
    stream.write_all(message.as_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
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
    let mut request = String::new();
    BufReader::new(stream.try_clone()?)
        .take((max_request_bytes() + 1) as u64)
        .read_line(&mut request)?;
    if request.is_empty() {
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
    writeln!(stream, "{response}")?;
    Ok(())
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
