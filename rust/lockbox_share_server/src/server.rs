use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::server_log::log_server_event;
use crate::store::{ServerConfig, ShareStore};
use lockbox_share_protocol::payload;
use lockbox_share_protocol::protocol::{self, Operation, Status};
use lockbox_share_protocol::status;
use lockbox_share_protocol::topology;

const MAX_HTTP_HEADER: usize = 16 * 1024;
const MAX_WIRE_OVERHEAD: usize = 128;

pub fn run_server(bind: &str, store: Arc<ShareStore>) -> std::io::Result<()> {
    let listener = TcpListener::bind(bind)?;
    run_listener(listener, store)
}

pub fn run_listener(listener: TcpListener, store: Arc<ShareStore>) -> std::io::Result<()> {
    let local_addr = listener.local_addr()?;
    log_server_event(format!("lockbox-share-server listening on {local_addr}"));
    let purge_store = Arc::clone(&store);
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(1));
        purge_store.purge_expired();
    });
    let compact_store = Arc::clone(&store);
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(30));
        if let Err(err) = compact_store.compact_if_needed() {
            log_server_event(format!("compaction failed: {err}"));
        }
    });

    let worker_count = worker_count();
    let (tx, rx) = mpsc::sync_channel::<TcpStream>(worker_count * 1024);
    let rx = Arc::new(Mutex::new(rx));
    let limiter = Arc::new(RateLimiter::new(
        store.rate_limit_per_minute(),
        store.rate_limit_burst(),
    ));
    for worker_id in 0..worker_count {
        let store = Arc::clone(&store);
        let rx = Arc::clone(&rx);
        let limiter = Arc::clone(&limiter);
        thread::Builder::new()
            .name(format!("share-http-{worker_id}"))
            .stack_size(256 * 1024)
            .spawn(move || loop {
                let stream = {
                    let guard = rx.lock().unwrap();
                    guard.recv()
                };
                match stream {
                    Ok(stream) => {
                        let _ = handle_stream(stream, Arc::clone(&store), Arc::clone(&limiter));
                    }
                    Err(_) => break,
                }
            })?;
    }

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if tx.send(stream).is_err() {
                    break;
                }
            }
            Err(err) => log_server_event(format!("accept failed: {err}")),
        }
    }
    Ok(())
}

pub fn local_addr(listener: &TcpListener) -> std::io::Result<SocketAddr> {
    listener.local_addr()
}

fn worker_count() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4)
        .saturating_mul(4)
        .clamp(4, 64)
}

pub struct RateLimiter {
    per_minute: u32,
    burst: u32,
    clients: Mutex<HashMap<IpAddr, ClientBucket>>,
}

struct ClientBucket {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    fn new(per_minute: u32, burst: u32) -> Self {
        Self {
            per_minute,
            burst: burst.max(1),
            clients: Mutex::new(HashMap::new()),
        }
    }

    fn allow(&self, peer_ip: Option<IpAddr>) -> bool {
        if self.per_minute == 0 {
            return true;
        }
        let Some(peer_ip) = peer_ip else {
            return false;
        };
        let now = Instant::now();
        let refill_per_second = self.per_minute as f64 / 60.0;
        let mut clients = self.clients.lock().unwrap();
        let bucket = clients.entry(peer_ip).or_insert(ClientBucket {
            tokens: self.burst as f64,
            last_refill: now,
        });
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_per_second).min(self.burst as f64);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub fn handle_stream(
    mut stream: TcpStream,
    store: Arc<ShareStore>,
    limiter: Arc<RateLimiter>,
) -> std::io::Result<()> {
    let mut buffer = Vec::with_capacity(MAX_HTTP_HEADER);
    let mut chunk = [0_u8; 1024];
    let peer_ip = stream.peer_addr().ok().map(|addr| addr.ip());
    loop {
        let header_end = loop {
            if let Some(pos) = find_header_end(&buffer) {
                break pos;
            }
            let read = stream.read(&mut chunk)?;
            if read == 0 {
                return Ok(());
            }
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.len() > MAX_HTTP_HEADER + store.max_payload_bytes() + MAX_WIRE_OVERHEAD {
                write_response(
                    &mut stream,
                    protocol::encode_error(Operation::Share, Status::PayloadTooLarge, "too large"),
                    true,
                )?;
                return Ok(());
            }
        };
        let headers = String::from_utf8_lossy(&buffer[..header_end]);
        let close = wants_close(&headers);
        let mut lines = headers.lines();
        let request_line = lines.next().unwrap_or_default();
        if request_line.starts_with("GET /v1/topology ") {
            match topology::encode_topology(&store.topology()) {
                Ok(body) => write_binary(&mut stream, 200, &body)?,
                Err(err) => write_plain(&mut stream, 500, err.to_string().as_bytes())?,
            }
            return Ok(());
        }
        if request_line.starts_with("GET /v1/status ") {
            let body = status::encode_status(&store.status_document());
            write_binary(&mut stream, 200, &body)?;
            return Ok(());
        }
        let replicate_endpoint = if request_line.starts_with("POST /v1/share ") {
            false
        } else if request_line.starts_with("POST /v1/replicate ") {
            true
        } else {
            write_plain(&mut stream, 404, b"not found")?;
            return Ok(());
        };
        if !limiter.allow(peer_ip) {
            write_response(
                &mut stream,
                protocol::encode_error(Operation::Share, Status::RateLimited, "rate limited"),
                true,
            )?;
            return Ok(());
        }
        let content_len = content_length(&headers).unwrap_or(0);
        if content_len > store.max_payload_bytes() + MAX_WIRE_OVERHEAD {
            write_response(
                &mut stream,
                protocol::encode_error(Operation::Share, Status::PayloadTooLarge, "too large"),
                true,
            )?;
            return Ok(());
        }
        let body_start = header_end + 4;
        while buffer.len() < body_start + content_len {
            let read = stream.read(&mut chunk)?;
            if read == 0 {
                return Ok(());
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
        let body_end = body_start + content_len;
        let body = buffer[body_start..body_end].to_vec();
        let response =
            match protocol::decode_request(&body, store.max_payload_bytes() + MAX_WIRE_OVERHEAD) {
                Ok(request) => {
                    let _ = request.flags;
                    if replicate_endpoint && request.operation != Operation::Replicate {
                        protocol::encode_error(
                            request.operation,
                            Status::UnknownOperation,
                            "replication endpoint accepts only replication operations",
                        )
                    } else if !replicate_endpoint && request.operation == Operation::Replicate {
                        protocol::encode_error(
                            request.operation,
                            Status::UnknownOperation,
                            "share endpoint does not accept replication operations",
                        )
                    } else {
                        store.handle(request.operation, &request.payload)
                    }
                }
                Err(err) => protocol::encode_error(
                    Operation::Share,
                    Status::MalformedRequest,
                    &err.to_string(),
                ),
            };
        write_response(&mut stream, response, close)?;
        buffer.drain(..body_end);
        if close {
            return Ok(());
        }
    }
}

pub fn bench_http(mut config: ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    config.bind_addr = "127.0.0.1:0".to_string();
    config.rate_limit_per_minute = 0;
    let requests = config.benchmark_requests;
    let concurrency = benchmark_concurrency(&config);
    let payload_bytes = config.benchmark_payload_bytes;
    let store = Arc::new(ShareStore::open(config)?);
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let server_store = Arc::clone(&store);
    thread::spawn(move || {
        let _ = run_listener(listener, server_store);
    });
    thread::sleep(Duration::from_millis(50));

    let payload = benchmark_payload(payload_bytes);
    let body = Arc::new(protocol::encode_share_request(900, 1, &payload));
    let next = Arc::new(AtomicUsize::new(0));
    let failures = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();
    let mut workers = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let body = Arc::clone(&body);
        let next = Arc::clone(&next);
        let failures = Arc::clone(&failures);
        workers.push(thread::spawn(move || loop {
            let index = next.fetch_add(1, Ordering::Relaxed);
            if index >= requests {
                break;
            }
            match post_binary(addr, &body, true) {
                Ok(response) if response.len() >= 14 && response[6] == 0 && response[7] == 0 => {}
                _ => {
                    failures.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for worker in workers {
        worker.join().map_err(|_| "benchmark worker panicked")?;
    }
    let failures = failures.load(Ordering::Relaxed);
    if failures != 0 {
        return Err(format!("{failures} benchmark requests failed").into());
    }
    let elapsed = start.elapsed();
    println!(
        "http_single_request_share_rps={} requests={} concurrency={} live={}",
        (requests as f64 / elapsed.as_secs_f64()) as u64,
        requests,
        concurrency,
        store.stats().live
    );
    Ok(())
}

pub fn bench_http_fetch(mut config: ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    config.bind_addr = "127.0.0.1:0".to_string();
    config.rate_limit_per_minute = 0;
    let requests = config.benchmark_requests;
    let concurrency = benchmark_concurrency(&config);
    let payload_bytes = config.benchmark_payload_bytes;
    let store = Arc::new(ShareStore::open(config)?);

    let payload = benchmark_payload(payload_bytes);
    let share_request = protocol::encode_share_request(900, 1, &payload);
    let decoded = protocol::decode_request(&share_request, payload_bytes + 64)?;
    let mut codes = Vec::with_capacity(requests);
    for _ in 0..requests {
        let response = store.handle(decoded.operation, &decoded.payload);
        if response.len() < 14 || response[6] != 0 || response[7] != 0 {
            return Err("unable to preload share for fetch benchmark".into());
        }
        let mut reader = protocol::Reader::new(&response[14..]);
        reader.message_version()?;
        codes.push(reader.string()?);
    }

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let server_store = Arc::clone(&store);
    thread::spawn(move || {
        let _ = run_listener(listener, server_store);
    });
    thread::sleep(Duration::from_millis(50));

    let codes = Arc::new(codes);
    let next = Arc::new(AtomicUsize::new(0));
    let failures = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();
    let mut workers = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let codes = Arc::clone(&codes);
        let next = Arc::clone(&next);
        let failures = Arc::clone(&failures);
        workers.push(thread::spawn(move || loop {
            let index = next.fetch_add(1, Ordering::Relaxed);
            if index >= codes.len() {
                break;
            }
            let body = protocol::encode_fetch_request(&codes[index]);
            match post_binary(addr, &body, true) {
                Ok(response) if response.len() >= 14 && response[6] == 0 && response[7] == 0 => {}
                _ => {
                    failures.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for worker in workers {
        worker.join().map_err(|_| "benchmark worker panicked")?;
    }
    let failures = failures.load(Ordering::Relaxed);
    if failures != 0 {
        return Err(format!("{failures} fetch benchmark requests failed").into());
    }
    let elapsed = start.elapsed();
    println!(
        "http_single_request_fetch_rps={} requests={} concurrency={} live={}",
        (requests as f64 / elapsed.as_secs_f64()) as u64,
        requests,
        concurrency,
        store.stats().live
    );
    Ok(())
}

pub fn bench_http_flow(mut config: ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    config.bind_addr = "127.0.0.1:0".to_string();
    config.rate_limit_per_minute = 0;
    let flows = config.benchmark_requests;
    let concurrency = benchmark_concurrency(&config);
    let payload_bytes = config.benchmark_payload_bytes;
    let preload_shares = config.benchmark_preload_shares;
    let store = Arc::new(ShareStore::open(config)?);

    let payload = benchmark_payload(payload_bytes);
    if preload_shares > 0 {
        preload_live_shares(&store, preload_shares, &payload)?;
    }

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let server_store = Arc::clone(&store);
    thread::spawn(move || {
        let _ = run_listener(listener, server_store);
    });
    thread::sleep(Duration::from_millis(50));

    let share_body = Arc::new(protocol::encode_share_request(900, 1, &payload));
    let next = Arc::new(AtomicUsize::new(0));
    let failures = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();
    let mut workers = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let share_body = Arc::clone(&share_body);
        let next = Arc::clone(&next);
        let failures = Arc::clone(&failures);
        workers.push(thread::spawn(move || loop {
            let index = next.fetch_add(1, Ordering::Relaxed);
            if index >= flows {
                break;
            }
            let share_response = match post_binary(addr, &share_body, true) {
                Ok(response) if response.len() >= 14 && response[6] == 0 && response[7] == 0 => {
                    response
                }
                _ => {
                    failures.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            let mut reader = protocol::Reader::new(&share_response[14..]);
            if reader.message_version().is_err() {
                failures.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let share_code = match reader.string() {
                Ok(code) => code,
                Err(_) => {
                    failures.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            let fetch_body = protocol::encode_fetch_request(&share_code);
            match post_binary(addr, &fetch_body, true) {
                Ok(response) if response.len() >= 14 && response[6] == 0 && response[7] == 0 => {}
                _ => {
                    failures.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for worker in workers {
        worker.join().map_err(|_| "benchmark worker panicked")?;
    }
    let failures = failures.load(Ordering::Relaxed);
    if failures != 0 {
        return Err(format!("{failures} flow benchmark requests failed").into());
    }
    let elapsed = start.elapsed();
    let flow_rps = flows as f64 / elapsed.as_secs_f64();
    let total_rps = flow_rps * 2.0;
    println!(
        "http_single_request_flow_rps={} \
         http_single_request_total_rps={} \
         flows={} concurrency={} preloaded={} live={}",
        flow_rps as u64,
        total_rps as u64,
        flows,
        concurrency,
        preload_shares,
        store.stats().live
    );
    Ok(())
}

fn preload_live_shares(
    store: &ShareStore,
    count: usize,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let request = protocol::encode_share_request(900, 1, payload);
    let decoded = protocol::decode_request(&request, payload.len() + 64)?;
    for _ in 0..count {
        let response = store.handle(decoded.operation, &decoded.payload);
        if response.len() < 14 || response[6] != 0 || response[7] != 0 {
            return Err("unable to preload share".into());
        }
    }
    Ok(())
}

fn benchmark_payload(target_bytes: usize) -> Vec<u8> {
    let key_len = target_bytes.saturating_sub(112).clamp(32, 4096);
    let public_key = vec![42_u8; key_len];
    payload::encode_contact_share(
        "bench@example.com",
        &public_key,
        &[7_u8; 32],
        &[9_u8; 24],
        1,
        2,
    )
}

fn benchmark_concurrency(config: &ServerConfig) -> usize {
    if config.benchmark_concurrency == 0 {
        std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(4)
            .saturating_mul(16)
            .clamp(16, 128)
    } else {
        config.benchmark_concurrency
    }
}

fn post_binary(addr: SocketAddr, body: &[u8], close: bool) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(addr)?;
    post_binary_on_stream(&mut stream, addr, body, close)
}

fn post_binary_on_stream(
    stream: &mut TcpStream,
    addr: SocketAddr,
    body: &[u8],
    close: bool,
) -> std::io::Result<Vec<u8>> {
    let connection = if close { "close" } else { "keep-alive" };
    let header = format!(
        "POST /v1/share HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n\
         Connection: {connection}\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    let mut response = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        if let Some(pos) = find_header_end(&response) {
            break pos;
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Ok(Vec::new());
        }
        response.extend_from_slice(&chunk[..read]);
    };
    let headers = String::from_utf8_lossy(&response[..header_end]);
    let content_len = content_length(&headers).unwrap_or(0);
    let body_start = header_end + 4;
    while response.len() < body_start + content_len {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..read]);
    }
    Ok(response[body_start..body_start + content_len].to_vec())
}

fn write_response(stream: &mut TcpStream, body: Vec<u8>, close: bool) -> std::io::Result<()> {
    let connection = if close { "close" } else { "keep-alive" };
    let header = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n\
         Connection: {connection}\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(&body)?;
    Ok(())
}

fn write_plain(stream: &mut TcpStream, status: u16, body: &[u8]) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status} Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

fn write_binary(stream: &mut TcpStream, status: u16, body: &[u8]) -> std::io::Result<()> {
    let reason = if status == 200 { "OK" } else { "Error" };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if key.eq_ignore_ascii_case("content-length") {
                return value.trim().parse().ok();
            }
        }
    }
    None
}

fn wants_close(headers: &str) -> bool {
    headers.lines().any(|line| {
        line.split_once(':')
            .map(|(key, value)| {
                key.eq_ignore_ascii_case("connection") && value.trim().eq_ignore_ascii_case("close")
            })
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::RateLimiter;

    #[test]
    fn rate_limiter_enforces_burst_capacity() {
        let limiter = RateLimiter::new(60, 2);
        let ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));

        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert!(!limiter.allow(ip));
    }

    #[test]
    fn zero_rate_limit_disables_limiter() {
        let limiter = RateLimiter::new(0, 1);
        let ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));

        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert!(limiter.allow(None));
    }
}
