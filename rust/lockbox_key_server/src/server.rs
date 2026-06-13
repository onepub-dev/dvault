use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
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
const REQUEST_IO_TIMEOUT: Duration = Duration::from_secs(10);

pub fn run_server(bind: &str, store: Arc<ShareStore>) -> std::io::Result<()> {
    let listener = TcpListener::bind(bind)?;
    run_listener(listener, store)
}

pub fn run_listener(listener: TcpListener, store: Arc<ShareStore>) -> std::io::Result<()> {
    let local_addr = listener.local_addr()?;
    log_server_event(format!("lockbox_key_server listening on {local_addr}"));
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
    let (tx, rx) = mpsc::sync_channel::<TcpStream>(accepted_stream_queue_bound(worker_count));
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
                    let Ok(guard) = rx.lock() else {
                        break;
                    };
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

    let mut last_accept_error_log = Instant::now() - Duration::from_secs(30);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if tx.send(stream).is_err() {
                    break;
                }
            }
            Err(err) => {
                if is_accept_resource_pressure(&err) {
                    if last_accept_error_log.elapsed() >= Duration::from_secs(10) {
                        log_server_event(format!("accept deferred under resource pressure: {err}"));
                        last_accept_error_log = Instant::now();
                    }
                    thread::sleep(Duration::from_millis(50));
                } else {
                    log_server_event(format!("accept failed: {err}"));
                }
            }
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

fn accepted_stream_queue_bound(worker_count: usize) -> usize {
    worker_count.saturating_mul(4).clamp(16, 256)
}

fn is_accept_resource_pressure(err: &std::io::Error) -> bool {
    matches!(err.kind(), ErrorKind::WouldBlock) || matches!(err.raw_os_error(), Some(11 | 23 | 24))
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
        let Ok(mut clients) = self.clients.lock() else {
            return false;
        };
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
    configure_stream_deadlines(&stream)?;
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
        if request_line.starts_with("GET /v1/verify") {
            let page = handle_verify_request(request_line, &store);
            write_html(
                &mut stream,
                if page.success { 200 } else { 400 },
                &render_verify_page(&page),
            )?;
            return Ok(());
        }
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
        let topology_registration_endpoint =
            request_line.starts_with("POST /v1/topology/register ");
        let replicate_endpoint = if request_line.starts_with("POST /v1/share ") {
            false
        } else if request_line.starts_with("POST /v1/replicate ") {
            true
        } else if topology_registration_endpoint {
            false
        } else {
            write_plain(&mut stream, 404, b"not found")?;
            return Ok(());
        };
        if !topology_registration_endpoint && !limiter.allow(peer_ip) {
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
        let response = if topology_registration_endpoint {
            match store.handle_topology_registration(&body) {
                Ok(response) => response,
                Err(err) => protocol::encode_error(
                    Operation::Share,
                    Status::StoreUnavailable,
                    &err.to_string(),
                ),
            }
        } else {
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
                        store.handle_with_peer(request.operation, &request.payload, peer_ip)
                    }
                }
                Err(err) => protocol::encode_error(
                    Operation::Share,
                    Status::MalformedRequest,
                    &err.to_string(),
                ),
            }
        };
        write_response(&mut stream, response, close)?;
        buffer.drain(..body_end);
        if close {
            return Ok(());
        }
    }
}

fn configure_stream_deadlines(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(REQUEST_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(REQUEST_IO_TIMEOUT))
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
        b"signing-public-key-material",
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

fn write_html(stream: &mut TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    let reason = if status == 200 { "OK" } else { "Error" };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body.as_bytes())?;
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

fn handle_verify_request(request_line: &str, store: &ShareStore) -> crate::store::VerificationPage {
    let Some(target) = request_line.split_whitespace().nth(1) else {
        return verify_error(
            "Verification failed",
            "The verification request is malformed.",
        );
    };
    let Some((_, query)) = target.split_once('?') else {
        return verify_error(
            "Verification failed",
            "The verification link is missing its token.",
        );
    };
    let code = query_param(query, "code");
    let token = query_param(query, "token");
    match (code, token) {
        (Some(code), Some(token)) => store.verify_email(&code, &token),
        _ => verify_error(
            "Verification failed",
            "The verification link is missing its token.",
        ),
    }
}

fn verify_error(title: &str, message: &str) -> crate::store::VerificationPage {
    crate::store::VerificationPage {
        success: false,
        title: title.to_string(),
        message: message.to_string(),
        email: None,
    }
}

fn query_param(query: &str, name: &str) -> Option<String> {
    for part in query.split('&') {
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        if key == name {
            return Some(percent_decode(value));
        }
    }
    None
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_digit(bytes[index + 1]), hex_digit(bytes[index + 2]))
            {
                out.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        out.push(if bytes[index] == b'+' {
            b' '
        } else {
            bytes[index]
        });
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn render_verify_page(page: &crate::store::VerificationPage) -> String {
    let color = if page.success { "#146C2E" } else { "#B3261E" };
    let icon = if page.success {
        "check_circle"
    } else {
        "error"
    };
    let email = page
        .email
        .as_ref()
        .map(|email| {
            format!(
                "<p style=\"margin:16px 0 0;color:#49454F;font:500 14px Arial,sans-serif;\">{}</p>",
                escape_html(email)
            )
        })
        .unwrap_or_default();
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>{}</title></head>\
<body style=\"margin:0;background:#FFFBFE;color:#1D1B20;font-family:Arial,sans-serif;\">\
<main style=\"min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;box-sizing:border-box;\">\
<section style=\"max-width:520px;width:100%;border:1px solid #CAC4D0;border-radius:8px;padding:32px;background:#FFFBFE;box-sizing:border-box;\">\
<div style=\"width:48px;height:48px;border-radius:24px;background:{color};color:white;display:flex;align-items:center;justify-content:center;font:700 24px Arial,sans-serif;margin-bottom:20px;\">{icon}</div>\
<h1 style=\"margin:0 0 12px;font:500 28px Arial,sans-serif;color:#1D1B20;\">{}</h1>\
<p style=\"margin:0;color:#49454F;font:400 16px/1.5 Arial,sans-serif;\">{}</p>{email}\
</section></main></body></html>",
        escape_html(&page.title),
        escape_html(&page.title),
        escape_html(&page.message)
    )
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
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
    use std::io::ErrorKind;
    use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
    use std::thread;

    use super::{configure_stream_deadlines, RateLimiter, REQUEST_IO_TIMEOUT};

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

    #[test]
    fn stream_deadlines_are_configured_for_requests() {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(err) if err.kind() == ErrorKind::PermissionDenied => return,
            Err(err) => panic!("unable to bind local test listener: {err}"),
        };
        let addr = listener.local_addr().unwrap();
        let client = thread::spawn(move || TcpStream::connect(addr).unwrap());
        let (server, _) = listener.accept().unwrap();
        let client = client.join().unwrap();

        configure_stream_deadlines(&server).unwrap();

        assert_eq!(server.read_timeout().unwrap(), Some(REQUEST_IO_TIMEOUT));
        assert_eq!(server.write_timeout().unwrap(), Some(REQUEST_IO_TIMEOUT));
        drop(client);
    }
}
